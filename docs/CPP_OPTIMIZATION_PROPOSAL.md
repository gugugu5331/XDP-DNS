# XDP DNS 流量过滤系统 C++ 优化方案

## 1. 性能优化策略

### 1.1 性能瓶颈分析

当前 Go 实现的主要性能瓶颈：

| 组件 | 瓶颈原因 | 影响程度 |
|------|---------|---------|
| DNS 解析 | 字符串分配、GC 压力 | 高 |
| 域名匹配 | map 哈希计算、锁竞争 | 高 |
| 包处理 | 切片拷贝、接口调用开销 | 中 |
| 响应构建 | 内存分配、字节切片操作 | 中 |
| 指标收集 | 原子操作、goroutine 调度 | 低 |

### 1.2 C++ 优化目标

```
性能目标：
- DNS 解析: < 100ns/packet (当前 Go ~500ns)
- 域名匹配: < 50ns/lookup (当前 Go ~200ns)
- 端到端延迟: < 10μs (当前 Go ~50μs)
- 吞吐量: > 5M PPS (当前 Go ~1M PPS)
```

### 1.3 内存管理优化

#### 1.3.1 零拷贝数据包处理

```cpp
// 直接操作 UMEM 内存，避免拷贝
class ZeroCopyPacketView {
public:
    // 直接引用 UMEM 中的数据
    explicit ZeroCopyPacketView(uint8_t* umem_ptr, size_t len)
        : data_(umem_ptr), len_(len) {}
    
    // 解析时不拷贝，返回视图
    std::string_view getDNSName() const;
    
    // 原地修改响应包
    void swapAddresses();
    
private:
    uint8_t* data_;
    size_t len_;
};
```

#### 1.3.2 对象池和内存池

```cpp
// 预分配固定大小的对象池
template<typename T, size_t PoolSize = 4096>
class ObjectPool {
public:
    T* acquire() {
        if (free_list_.empty()) return nullptr;
        T* obj = free_list_.back();
        free_list_.pop_back();
        return obj;
    }
    
    void release(T* obj) {
        obj->reset();
        free_list_.push_back(obj);
    }
    
private:
    std::vector<T*> free_list_;
    alignas(64) std::array<T, PoolSize> storage_;
};

// DNS 消息对象池
static thread_local ObjectPool<DNSMessage> dns_message_pool;
```

### 1.4 并发处理优化

#### 1.4.1 无锁数据结构

```cpp
// 使用 RCU (Read-Copy-Update) 模式
class LockFreeDomainTrie {
public:
    // 读操作完全无锁
    const Rule* match(std::string_view domain) const {
        auto* node = root_.load(std::memory_order_acquire);
        return matchImpl(node, domain);
    }
    
    // 写操作创建新版本
    void update(const std::vector<Rule>& rules) {
        auto* new_root = buildTrie(rules);
        auto* old_root = root_.exchange(new_root, std::memory_order_release);
        // 延迟释放旧版本
        rcu_defer_free(old_root);
    }
    
private:
    std::atomic<TrieNode*> root_;
};
```

#### 1.4.2 CPU 亲和性和 NUMA 感知

```cpp
class WorkerThread {
public:
    void start(int cpu_id, int numa_node) {
        // 绑定到指定 CPU
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_id, &cpuset);
        pthread_setaffinity_np(thread_.native_handle(), sizeof(cpuset), &cpuset);
        
        // 使用本地 NUMA 内存
        numa_set_preferred(numa_node);
    }
};
```

---

## 2. 代码重构建议

### 2.1 适合 C++ 重写的组件

| 组件 | 优先级 | 原因 | 预期收益 |
|------|-------|------|---------|
| DNS Parser | P0 | 热路径，字符串处理密集 | 5-10x |
| Domain Trie | P0 | 查询频繁，需要无锁 | 3-5x |
| Packet Processor | P1 | 需要零拷贝处理 | 2-3x |
| Response Builder | P1 | 减少内存分配 | 2-3x |
| Filter Engine | P2 | 规则匹配优化 | 2x |
| Metrics Collector | P3 | 可保留 Go 实现 | - |

### 2.2 保留 Go 实现的组件

- **配置管理 (pkg/config)**: YAML 解析，启动时一次性加载
- **Metrics Exporter**: Prometheus HTTP 服务，非关键路径
- **规则热加载**: 低频操作，Go 的并发模型更适合
- **日志系统**: 异步日志，性能影响小

### 2.3 混合架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    Go Control Plane                          │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Config Mgr  │  │ Rule Loader  │  │ Metrics Exporter    │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
│                           │                                  │
│                    ┌──────▼──────┐                          │
│                    │  CGO Bridge │                          │
│                    └──────┬──────┘                          │
└───────────────────────────┼─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    C++ Data Plane                            │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ DNS Parser  │  │ Domain Trie  │  │ Packet Processor    │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Response    │  │ Filter       │  │ XDP Socket Handler  │ │
│  │ Builder     │  │ Engine       │  │                     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. 接口设计

### 3.1 C++ 核心库 API

```cpp
// include/xdp_dns/dns_parser.hpp
namespace xdp_dns {

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} __attribute__((packed));

struct DNSQuestion {
    std::string_view name;  // 零拷贝视图
    uint16_t qtype;
    uint16_t qclass;
};

class DNSMessage {
public:
    // 零拷贝解析
    static std::expected<DNSMessage, ParseError> 
    parse(std::span<const uint8_t> data);
    
    bool isQuery() const noexcept;
    std::string_view getQueryDomain() const noexcept;
    uint16_t getQueryType() const noexcept;
    
private:
    const uint8_t* raw_data_;
    size_t raw_len_;
    DNSHeader header_;
    std::vector<DNSQuestion> questions_;
};

} // namespace xdp_dns
```

### 3.2 CGO 桥接接口

```cpp
// include/xdp_dns/cgo_bridge.h
#ifdef __cplusplus
extern "C" {
#endif

// 初始化/清理
int xdp_dns_init(const char* config_path);
void xdp_dns_cleanup(void);

// 数据包处理 - 返回动作
typedef enum {
    ACTION_ALLOW = 0,
    ACTION_BLOCK = 1,
    ACTION_REDIRECT = 2,
    ACTION_LOG = 3
} FilterAction;

typedef struct {
    FilterAction action;
    uint32_t redirect_ip;  // 网络字节序
    uint32_t ttl;
    const char* rule_id;
} FilterResult;

// 核心处理函数
FilterResult xdp_dns_process_packet(
    const uint8_t* packet_data,
    size_t packet_len,
    uint8_t* response_buf,
    size_t* response_len
);

// 规则管理
int xdp_dns_load_rules(const char* rules_yaml);
int xdp_dns_add_rule(const char* rule_json);
int xdp_dns_remove_rule(const char* rule_id);

// 统计信息
typedef struct {
    uint64_t packets_received;
    uint64_t packets_allowed;
    uint64_t packets_blocked;
    uint64_t packets_redirected;
    uint64_t parse_errors;
    uint64_t avg_latency_ns;
} XDPDNSStats;

void xdp_dns_get_stats(XDPDNSStats* stats);

#ifdef __cplusplus
}
#endif
```

---

*文档继续在 CPP_OPTIMIZATION_PROPOSAL_PART2.md*

