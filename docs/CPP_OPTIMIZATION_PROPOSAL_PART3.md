# XDP DNS 流量过滤系统 C++ 优化方案 (续)

## 5. 具体实施步骤

### 5.1 阶段规划

```
Phase 1: 基础设施 (1-2周)
├── 创建 C++ 项目结构
├── 配置 CMake 构建系统
├── 建立 CGO 桥接框架
└── 设置 CI/CD 流水线

Phase 2: DNS 解析器 (2周)
├── 实现零拷贝 DNS 解析
├── 单元测试和基准测试
├── CGO 集成测试
└── 性能对比验证

Phase 3: 域名匹配引擎 (2周)
├── 实现无锁 Trie 结构
├── 通配符匹配优化
├── 并发安全测试
└── 集成到过滤引擎

Phase 4: 数据包处理器 (2周)
├── 零拷贝包处理
├── 响应构建器
├── XDP Socket 集成
└── 端到端测试

Phase 5: 集成和优化 (2周)
├── 完整系统集成
├── 性能调优
├── 生产环境测试
└── 文档和发布
```

### 5.2 Phase 1: 基础设施

#### 5.2.1 创建 C++ 项目结构

```bash
# 创建目录
mkdir -p cpp/{include/xdp_dns,src,tests}

# 创建基础头文件
cat > cpp/include/xdp_dns/common.hpp << 'EOF'
#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <string_view>
#include <expected>
#include <array>

namespace xdp_dns {

// 错误类型
enum class Error {
    Success = 0,
    PacketTooShort,
    InvalidHeader,
    TruncatedMessage,
    PointerLoop,
    InvalidLabel,
    BufferTooSmall,
};

// 网络字节序转换
inline uint16_t ntohs(uint16_t n) {
    return __builtin_bswap16(n);
}

inline uint32_t ntohl(uint32_t n) {
    return __builtin_bswap32(n);
}

inline uint16_t htons(uint16_t h) {
    return __builtin_bswap16(h);
}

inline uint32_t htonl(uint32_t h) {
    return __builtin_bswap32(h);
}

} // namespace xdp_dns
EOF
```

### 5.3 Phase 2: DNS 解析器实现

#### 5.3.1 高性能 DNS 解析器

```cpp
// cpp/include/xdp_dns/dns_parser.hpp
#pragma once

#include "common.hpp"
#include <vector>

namespace xdp_dns {

// DNS 头部 (网络字节序)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
    
    // 解析后的值
    uint16_t getId() const { return ntohs(id); }
    uint16_t getFlags() const { return ntohs(flags); }
    bool isQuery() const { return (getFlags() & 0x8000) == 0; }
    uint16_t getQDCount() const { return ntohs(qd_count); }
} __attribute__((packed));

static_assert(sizeof(DNSHeader) == 12, "DNSHeader size mismatch");

// DNS 问题 (零拷贝)
struct DNSQuestion {
    const uint8_t* name_ptr;     // 指向原始数据
    uint16_t name_len;           // 域名长度
    uint16_t qtype;
    uint16_t qclass;
    
    // 获取域名 (需要解码时调用)
    std::string decodeName(const uint8_t* packet_start) const;
};

// DNS 消息解析器
class DNSParser {
public:
    struct Result {
        const DNSHeader* header;
        DNSQuestion question;
        size_t consumed_bytes;
    };
    
    // 快速解析 - 只解析第一个问题
    static std::expected<Result, Error> 
    parseQuery(std::span<const uint8_t> data);
    
    // 域名比较 (不解码，直接比较)
    static bool domainEquals(
        const uint8_t* packet,
        const DNSQuestion& q,
        std::string_view domain
    );
    
    // 域名后缀匹配
    static bool domainEndsWith(
        const uint8_t* packet,
        const DNSQuestion& q,
        std::string_view suffix
    );

private:
    // 解析域名，返回结束位置
    static std::expected<size_t, Error>
    parseName(std::span<const uint8_t> data, size_t offset);
};

} // namespace xdp_dns
```

### 5.4 Phase 3: 域名匹配引擎

#### 5.4.1 无锁 Trie 实现

```cpp
// cpp/include/xdp_dns/domain_trie.hpp
#pragma once

#include "common.hpp"
#include <atomic>
#include <memory>
#include <unordered_map>
#include <shared_mutex>

namespace xdp_dns {

// 过滤规则
struct Rule {
    uint32_t id;
    uint8_t action;      // 0=allow, 1=block, 2=redirect
    uint32_t redirect_ip;
    uint32_t ttl;
    char rule_id[32];
};

// Trie 节点
struct TrieNode {
    std::unordered_map<std::string, std::unique_ptr<TrieNode>> children;
    const Rule* exact_rule = nullptr;
    const Rule* wildcard_rule = nullptr;
};

// 读写分离的 Trie
class DomainTrie {
public:
    DomainTrie() : root_(std::make_unique<TrieNode>()) {}
    
    // 读操作 - 使用共享锁
    const Rule* match(std::string_view domain) const {
        std::shared_lock lock(mutex_);
        return matchImpl(root_.get(), domain);
    }
    
    // 写操作 - 批量更新，最小化锁时间
    void updateRules(std::vector<Rule> rules);
    
private:
    const Rule* matchImpl(const TrieNode* node, std::string_view domain) const;
    void insertRule(TrieNode* node, std::string_view domain, const Rule* rule);
    
    mutable std::shared_mutex mutex_;
    std::unique_ptr<TrieNode> root_;
    std::vector<Rule> rules_;  // 规则存储
};

} // namespace xdp_dns
```

### 5.5 验证和测试策略

#### 5.5.1 单元测试

```cpp
// cpp/tests/dns_parser_test.cpp
#include <gtest/gtest.h>
#include "xdp_dns/dns_parser.hpp"

using namespace xdp_dns;

TEST(DNSParserTest, ParseSimpleQuery) {
    // example.com A 查询
    uint8_t packet[] = {
        0x12, 0x34,  // ID
        0x01, 0x00,  // Flags (standard query)
        0x00, 0x01,  // QDCount = 1
        0x00, 0x00,  // ANCount = 0
        0x00, 0x00,  // NSCount = 0
        0x00, 0x00,  // ARCount = 0
        // Question
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,  // Type A
        0x00, 0x01,  // Class IN
    };
    
    auto result = DNSParser::parseQuery(packet);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->header->getId(), 0x1234);
    EXPECT_TRUE(result->header->isQuery());
    EXPECT_EQ(result->question.qtype, 1);  // A
}

TEST(DNSParserTest, DomainMatching) {
    // 测试域名匹配
    uint8_t packet[] = { /* ... */ };
    auto result = DNSParser::parseQuery(packet);
    
    EXPECT_TRUE(DNSParser::domainEquals(packet, result->question, "example.com"));
    EXPECT_TRUE(DNSParser::domainEndsWith(packet, result->question, ".com"));
}
```

#### 5.5.2 基准测试

```cpp
// cpp/tests/benchmark_test.cpp
#include <benchmark/benchmark.h>
#include "xdp_dns/dns_parser.hpp"
#include "xdp_dns/domain_trie.hpp"

static void BM_DNSParse(benchmark::State& state) {
    uint8_t packet[] = { /* DNS query packet */ };
    
    for (auto _ : state) {
        auto result = xdp_dns::DNSParser::parseQuery(packet);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_DNSParse);

static void BM_TrieMatch(benchmark::State& state) {
    xdp_dns::DomainTrie trie;
    // 添加 10000 条规则
    
    for (auto _ : state) {
        auto rule = trie.match("sub.example.com");
        benchmark::DoNotOptimize(rule);
    }
}
BENCHMARK(BM_TrieMatch);

BENCHMARK_MAIN();
```

---

*文档继续在 CPP_OPTIMIZATION_PROPOSAL_PART4.md*

