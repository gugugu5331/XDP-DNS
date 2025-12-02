# XDP DNS 流量过滤系统设计文档

## 1. 系统概述

### 1.1 目标
构建高性能的 DNS 流量过滤系统，利用 XDP (eXpress Data Path) 技术在网卡驱动层拦截和处理 DNS 数据包，实现：
- **超低延迟**: 绕过内核网络栈，直接在驱动层处理
- **零拷贝**: 使用 AF_XDP Socket 实现用户态零拷贝读取
- **高吞吐**: 支持百万级 PPS 的 DNS 查询处理能力
- **灵活过滤**: 支持基于域名、IP、查询类型的动态过滤规则

### 1.2 系统架构
```
┌─────────────────────────────────────────────────────────────────────────┐
│                           User Space (Go + C++)                               │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐   │
│  │ Config Mgr  │  │ DNS Parser   │  │ Filter Eng  │  │ Stats/Metrics│   │
│  └─────────────┘  └──────────────┘  └─────────────┘  └──────────────┘   │
│         │                │                 │                │           │
│         └────────────────┴─────────────────┴────────────────┘           │
│                              │                                          │
│  ┌───────────────────────────▼───────────────────────────────────────┐  │
│  │                    AF_XDP Socket (Zero-Copy)                      │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │  │
│  │  │Fill Ring │  │Comp Ring │  │ RX Ring  │  │ TX Ring  │          │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘          │  │
│  │                         UMEM (Shared Memory)                      │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                            ┌───────▼───────┐
                            │   eBPF Maps   │
                            │ ┌───────────┐ │
                            │ │ xsks_map  │ │
                            │ │qidconf_map│ │
                            │ │filter_map │ │
                            │ │metrics_map│ │
                            │ └───────────┘ │
                            └───────────────┘
                                    │
┌───────────────────────────────────▼─────────────────────────────────────┐
│                         Kernel Space (XDP/eBPF)                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      XDP Program (C/eBPF)                         │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐ │  │
│  │  │Parse Eth│─▶│Parse IP │─▶│Parse UDP│─▶│Check DNS│─▶│Redirect │ │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                            ┌───────▼───────┐
                            │   NIC Driver  │
                            │    (XDP支持)   │
                            └───────────────┘
```

### 1.3 数据流
```
Packet In → NIC → XDP Program → DNS检测 → AF_XDP → Go程序 → DNS解析 → 过滤决策 → 响应/丢弃
                      │                        │                              │
                      │                        │                              │
                      ├─ 非DNS → XDP_PASS ────▶│ Kernel Network Stack        │
                      │                        │                              │
                      └─ DNS → bpf_redirect ──▶│ Zero-Copy处理 ─────────────▶│
```

## 2. 项目结构

```
xdp-dns/
├── cmd/
│   └── dns-filter/
│       └── main.go              # 主程序入口
├── pkg/
│   ├── xdp/
│   │   ├── socket.go            # AF_XDP Socket 封装
│   │   ├── program.go           # XDP 程序管理
│   │   ├── ring.go              # 环形缓冲区操作
│   │   └── umem.go              # UMEM 内存管理
│   ├── dns/
│   │   ├── parser.go            # DNS 协议解析
│   │   ├── query.go             # DNS 查询处理
│   │   ├── response.go          # DNS 响应生成
│   │   └── types.go             # DNS 类型定义
│   ├── filter/
│   │   ├── engine.go            # 过滤引擎
│   │   ├── rules.go             # 过滤规则管理
│   │   ├── domain.go            # 域名匹配
│   │   └── ip.go                # IP 匹配
│   ├── packet/
│   │   ├── ethernet.go          # 以太网头解析
│   │   ├── ipv4.go              # IPv4 头解析
│   │   ├── ipv6.go              # IPv6 头解析
│   │   └── udp.go               # UDP 头解析
│   ├── config/
│   │   ├── config.go            # 配置管理
│   │   └── loader.go            # 配置加载
│   └── metrics/
│       ├── collector.go         # 指标收集
│       └── exporter.go          # Prometheus 导出
├── bpf/
│   ├── xdp_dns_filter.c         # XDP eBPF 程序 (核心)
│   ├── xdp_dns_filter.h         # 头文件定义
│   ├── vmlinux.h                # 内核类型定义
│   └── Makefile                 # 编译脚本
├── internal/
│   ├── worker/
│   │   ├── pool.go              # Worker 池
│   │   └── processor.go         # 数据包处理器
│   └── cache/
│       └── lru.go               # LRU 缓存
├── configs/
│   ├── config.yaml              # 主配置文件
│   └── rules.yaml               # 过滤规则配置
├── scripts/
│   ├── setup.sh                 # 环境设置脚本
│   ├── build.sh                 # 构建脚本
│   └── deploy.sh                # 部署脚本
├── tests/
│   ├── integration/             # 集成测试
│   └── benchmark/               # 性能基准测试
├── docs/
│   └── XDP_DNS_FILTER_DESIGN.md # 本设计文档
├── go.mod
├── go.sum
└── Makefile
```

## 3. eBPF/XDP 程序设计 (C)

详细代码见 `bpf/xdp_dns_filter.c`，核心功能包括：

### 3.1 数据结构定义
```c
// DNS 头部结构
struct dns_hdr {
    __u16 id;           // 事务ID
    __u16 flags;        // 标志位
    __u16 qdcount;      // 问题数
    __u16 ancount;      // 回答数
    __u16 nscount;      // 授权数
    __u16 arcount;      // 附加数
};

// 数据包元信息 (传递给用户态)
struct pkt_meta {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 pkt_len;
    __u8  is_query;     // 1=查询, 0=响应
    __u8  qtype;        // 查询类型
};
```

### 3.2 eBPF Maps 定义
```c
// AF_XDP Socket 映射
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_SOCKS);
} xsks_map SEC(".maps");

// 队列配置映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_SOCKS);
} qidconf_map SEC(".maps");

// DNS 端口过滤映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 64);
} dns_ports_map SEC(".maps");

// 指标统计映射
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct metrics);
    __uint(max_entries, 4);
} metrics_map SEC(".maps");

// IP 黑名单 (LPM Trie)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, sizeof(struct lpm_key));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_blacklist SEC(".maps");
```

### 3.3 核心处理逻辑

```c
SEC("xdp")
int xdp_dns_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 只处理 IPv4/IPv6
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6)
        return XDP_PASS;

    // 2. 解析 IP 头
    struct iphdr *iph = NULL;
    struct ipv6hdr *ip6h = NULL;
    void *l4_hdr;
    __u8 protocol;

    if (h_proto == ETH_P_IP) {
        iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        protocol = iph->protocol;
        l4_hdr = (void *)iph + (iph->ihl * 4);
    } else {
        ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        protocol = ip6h->nexthdr;
        l4_hdr = (void *)(ip6h + 1);
    }

    // 3. 只处理 UDP
    if (protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udph = l4_hdr;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    // 4. 检查是否为 DNS 端口 (53, 853, etc.)
    __u16 dst_port = bpf_ntohs(udph->dest);
    __u16 src_port = bpf_ntohs(udph->source);

    __u8 *is_dns_port = bpf_map_lookup_elem(&dns_ports_map, &dst_port);
    if (!is_dns_port) {
        is_dns_port = bpf_map_lookup_elem(&dns_ports_map, &src_port);
        if (!is_dns_port)
            return XDP_PASS;
    }

    // 5. 验证 DNS 包结构
    struct dns_hdr *dnsh = (void *)(udph + 1);
    if ((void *)(dnsh + 1) > data_end)
        return XDP_PASS;

    // 6. 更新统计指标
    __u32 key = 0;
    struct metrics *m = bpf_map_lookup_elem(&metrics_map, &key);
    if (m) {
        __sync_fetch_and_add(&m->dns_packets, 1);
    }

    // 7. IP 黑名单检查 (可选快速过滤)
    if (iph) {
        struct lpm_key lpm = { .prefixlen = 32, .addr = iph->saddr };
        if (bpf_map_lookup_elem(&ip_blacklist, &lpm)) {
            if (m) __sync_fetch_and_add(&m->blocked, 1);
            return XDP_DROP;
        }
    }

    // 8. 重定向到 AF_XDP Socket
    int index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&qidconf_map, &index)) {
        return bpf_redirect_map(&xsks_map, index, XDP_PASS);
    }

    return XDP_PASS;
}
```

## 4. Go 用户态程序设计

### 4.1 主程序入口 (cmd/dns-filter/main.go)

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "xdp-dns/pkg/config"
    "xdp-dns/pkg/xdp"
    "xdp-dns/pkg/dns"
    "xdp-dns/pkg/filter"
    "xdp-dns/pkg/metrics"
    "xdp-dns/internal/worker"
)

func main() {
    // 加载配置
    cfg, err := config.Load("configs/config.yaml")
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // 初始化指标收集器
    metricsCollector := metrics.NewCollector()

    // 加载 XDP 程序
    program, err := xdp.LoadProgram(xdp.ProgramOptions{
        BPFPath:     cfg.BPFPath,
        Interface:   cfg.Interface,
        QueueCount:  cfg.QueueCount,
    })
    if err != nil {
        log.Fatalf("Failed to load XDP program: %v", err)
    }
    defer program.Close()

    // 创建 AF_XDP Socket
    socket, err := xdp.NewSocket(xdp.SocketOptions{
        Interface:    cfg.Interface,
        QueueID:      cfg.QueueID,
        NumFrames:    cfg.NumFrames,
        FrameSize:    cfg.FrameSize,
    })
    if err != nil {
        log.Fatalf("Failed to create XDP socket: %v", err)
    }
    defer socket.Close()

    // 初始化过滤引擎
    filterEngine, err := filter.NewEngine(cfg.RulesPath)
    if err != nil {
        log.Fatalf("Failed to init filter engine: %v", err)
    }

    // 创建 Worker 池
    workerPool := worker.NewPool(worker.PoolOptions{
        NumWorkers:     cfg.NumWorkers,
        Socket:         socket,
        FilterEngine:   filterEngine,
        DNSParser:      dns.NewParser(),
        Metrics:        metricsCollector,
    })

    // 启动处理
    ctx, cancel := context.WithCancel(context.Background())
    go workerPool.Start(ctx)

    // 优雅关闭
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh

    log.Println("Shutting down...")
    cancel()
    workerPool.Wait()
}
```

### 4.2 DNS 协议解析 (pkg/dns/parser.go)

```go
package dns

import (
    "encoding/binary"
    "errors"
    "strings"
)

// DNS 消息类型
const (
    TypeA     uint16 = 1
    TypeAAAA  uint16 = 28
    TypeCNAME uint16 = 5
    TypeMX    uint16 = 15
    TypeTXT   uint16 = 16
    TypeNS    uint16 = 2
    TypeSOA   uint16 = 6
    TypePTR   uint16 = 12
    TypeANY   uint16 = 255
)

// DNS 响应码
const (
    RCodeNoError  = 0
    RCodeNXDomain = 3
    RCodeRefused  = 5
)

type Header struct {
    ID      uint16
    Flags   uint16
    QDCount uint16
    ANCount uint16
    NSCount uint16
    ARCount uint16
}

type Question struct {
    Name   string
    QType  uint16
    QClass uint16
}

type Message struct {
    Header    Header
    Questions []Question
    RawData   []byte
}

type Parser struct {
    // 可添加解析选项
}

func NewParser() *Parser {
    return &Parser{}
}

func (p *Parser) Parse(data []byte) (*Message, error) {
    if len(data) < 12 {
        return nil, errors.New("DNS message too short")
    }

    msg := &Message{RawData: data}

    // 解析头部
    msg.Header = Header{
        ID:      binary.BigEndian.Uint16(data[0:2]),
        Flags:   binary.BigEndian.Uint16(data[2:4]),
        QDCount: binary.BigEndian.Uint16(data[4:6]),
        ANCount: binary.BigEndian.Uint16(data[6:8]),
        NSCount: binary.BigEndian.Uint16(data[8:10]),
        ARCount: binary.BigEndian.Uint16(data[10:12]),
    }

    // 解析问题部分
    offset := 12
    for i := uint16(0); i < msg.Header.QDCount; i++ {
        q, newOffset, err := p.parseQuestion(data, offset)
        if err != nil {
            return nil, err
        }
        msg.Questions = append(msg.Questions, q)
        offset = newOffset
    }

    return msg, nil
}

func (p *Parser) parseQuestion(data []byte, offset int) (Question, int, error) {
    name, newOffset, err := p.parseName(data, offset)
    if err != nil {
        return Question{}, 0, err
    }

    if newOffset+4 > len(data) {
        return Question{}, 0, errors.New("question truncated")
    }

    return Question{
        Name:   name,
        QType:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
        QClass: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
    }, newOffset + 4, nil
}

func (p *Parser) parseName(data []byte, offset int) (string, int, error) {
    var labels []string
    visited := make(map[int]bool)

    for {
        if offset >= len(data) {
            return "", 0, errors.New("name truncated")
        }

        // 防止指针循环
        if visited[offset] {
            return "", 0, errors.New("pointer loop detected")
        }
        visited[offset] = true

        length := int(data[offset])

        if length == 0 {
            return strings.Join(labels, "."), offset + 1, nil
        }

        // 压缩指针
        if length&0xC0 == 0xC0 {
            if offset+1 >= len(data) {
                return "", 0, errors.New("pointer truncated")
            }
            ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
            name, _, err := p.parseName(data, ptr)
            if err != nil {
                return "", 0, err
            }
            labels = append(labels, name)
            return strings.Join(labels, "."), offset + 2, nil
        }

        offset++
        if offset+length > len(data) {
            return "", 0, errors.New("label truncated")
        }

        labels = append(labels, string(data[offset:offset+length]))
        offset += length
    }
}

// IsQuery 检查是否为查询
func (m *Message) IsQuery() bool {
    return m.Header.Flags&0x8000 == 0
}

// GetQueryDomain 获取查询域名
func (m *Message) GetQueryDomain() string {
    if len(m.Questions) > 0 {
        return strings.ToLower(m.Questions[0].Name)
    }
    return ""
}

// GetQueryType 获取查询类型
func (m *Message) GetQueryType() uint16 {
    if len(m.Questions) > 0 {
        return m.Questions[0].QType
    }
    return 0
}
```

### 4.3 过滤引擎 (pkg/filter/engine.go)

```go
package filter

import (
    "strings"
    "sync"
    "sync/atomic"

    "xdp-dns/pkg/dns"
)

type Action int

const (
    ActionAllow Action = iota
    ActionBlock
    ActionRedirect
    ActionLog
)

type Rule struct {
    ID          string
    Priority    int
    DomainMatch string    // 域名匹配 (支持通配符)
    QueryTypes  []uint16  // 查询类型
    Action      Action
    Enabled     bool
}

type Engine struct {
    rules      []Rule
    domainTrie *DomainTrie     // 域名前缀树
    mu         sync.RWMutex
    stats      EngineStats
}

type EngineStats struct {
    TotalChecks   uint64
    Allowed       uint64
    Blocked       uint64
    Redirected    uint64
}

func NewEngine(rulesPath string) (*Engine, error) {
    e := &Engine{
        domainTrie: NewDomainTrie(),
    }

    if err := e.LoadRules(rulesPath); err != nil {
        return nil, err
    }

    return e, nil
}

// Check 检查 DNS 消息是否应该被过滤
func (e *Engine) Check(msg *dns.Message, srcIP string) (Action, *Rule) {
    atomic.AddUint64(&e.stats.TotalChecks, 1)

    domain := msg.GetQueryDomain()
    qtype := msg.GetQueryType()

    e.mu.RLock()
    defer e.mu.RUnlock()

    // 1. 精确域名匹配 (Trie 查找)
    if rule := e.domainTrie.Match(domain); rule != nil {
        return e.applyRule(rule, qtype)
    }

    // 2. 通配符匹配
    for _, rule := range e.rules {
        if !rule.Enabled {
            continue
        }
        if e.matchDomain(domain, rule.DomainMatch) {
            return e.applyRule(&rule, qtype)
        }
    }

    atomic.AddUint64(&e.stats.Allowed, 1)
    return ActionAllow, nil
}

func (e *Engine) applyRule(rule *Rule, qtype uint16) (Action, *Rule) {
    // 检查查询类型
    if len(rule.QueryTypes) > 0 {
        found := false
        for _, t := range rule.QueryTypes {
            if t == qtype || t == dns.TypeANY {
                found = true
                break
            }
        }
        if !found {
            return ActionAllow, nil
        }
    }

    switch rule.Action {
    case ActionBlock:
        atomic.AddUint64(&e.stats.Blocked, 1)
    case ActionRedirect:
        atomic.AddUint64(&e.stats.Redirected, 1)
    default:
        atomic.AddUint64(&e.stats.Allowed, 1)
    }

    return rule.Action, rule
}

func (e *Engine) matchDomain(domain, pattern string) bool {
    // 支持通配符匹配
    // *.example.com 匹配所有子域名
    // example.com 精确匹配

    if strings.HasPrefix(pattern, "*.") {
        suffix := pattern[1:] // .example.com
        return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
    }

    return domain == pattern
}

// AddRule 动态添加规则
func (e *Engine) AddRule(rule Rule) {
    e.mu.Lock()
    defer e.mu.Unlock()

    e.rules = append(e.rules, rule)
    if !strings.HasPrefix(rule.DomainMatch, "*") {
        e.domainTrie.Insert(rule.DomainMatch, &rule)
    }
}

// RemoveRule 移除规则
func (e *Engine) RemoveRule(id string) bool {
    e.mu.Lock()
    defer e.mu.Unlock()

    for i, rule := range e.rules {
        if rule.ID == id {
            e.rules = append(e.rules[:i], e.rules[i+1:]...)
            return true
        }
    }
    return false
}

// GetStats 获取统计信息
func (e *Engine) GetStats() EngineStats {
    return EngineStats{
        TotalChecks: atomic.LoadUint64(&e.stats.TotalChecks),
        Allowed:     atomic.LoadUint64(&e.stats.Allowed),
        Blocked:     atomic.LoadUint64(&e.stats.Blocked),
        Redirected:  atomic.LoadUint64(&e.stats.Redirected),
    }
}
```

### 4.4 Worker 处理池 (internal/worker/pool.go)

```go
package worker

import (
    "context"
    "log"
    "runtime"
    "sync"

    "xdp-dns/pkg/xdp"
    "xdp-dns/pkg/dns"
    "xdp-dns/pkg/filter"
    "xdp-dns/pkg/metrics"
)

type PoolOptions struct {
    NumWorkers   int
    Socket       *xdp.Socket
    FilterEngine *filter.Engine
    DNSParser    *dns.Parser
    Metrics      *metrics.Collector
}

type Pool struct {
    options   PoolOptions
    packets   chan xdp.Packet
    wg        sync.WaitGroup
}

func NewPool(opts PoolOptions) *Pool {
    if opts.NumWorkers <= 0 {
        opts.NumWorkers = runtime.NumCPU()
    }

    return &Pool{
        options: opts,
        packets: make(chan xdp.Packet, opts.NumWorkers*1024),
    }
}

func (p *Pool) Start(ctx context.Context) {
    // 启动 workers
    for i := 0; i < p.options.NumWorkers; i++ {
        p.wg.Add(1)
        go p.worker(ctx, i)
    }

    // 启动 receiver
    p.wg.Add(1)
    go p.receiver(ctx)
}

func (p *Pool) receiver(ctx context.Context) {
    defer p.wg.Done()

    socket := p.options.Socket

    for {
        select {
        case <-ctx.Done():
            return
        default:
        }

        // 填充 Fill Ring
        descs := socket.GetDescs(socket.NumFreeFillSlots(), true)
        socket.Fill(descs)

        // 轮询接收
        numRx, _, err := socket.Poll(100) // 100ms 超时
        if err != nil {
            log.Printf("Poll error: %v", err)
            continue
        }

        if numRx == 0 {
            continue
        }

        // 分发到 workers
        rxDescs := socket.Receive(numRx)
        for _, desc := range rxDescs {
            pkt := xdp.Packet{
                Desc: desc,
                Data: socket.GetFrame(desc),
            }

            select {
            case p.packets <- pkt:
            default:
                // 队列满，丢弃包
                p.options.Metrics.IncDropped()
            }
        }
    }
}

func (p *Pool) worker(ctx context.Context, id int) {
    defer p.wg.Done()

    parser := p.options.DNSParser
    engine := p.options.FilterEngine
    metrics := p.options.Metrics

    for {
        select {
        case <-ctx.Done():
            return
        case pkt := <-p.packets:
            p.processPacket(pkt, parser, engine, metrics)
        }
    }
}

func (p *Pool) processPacket(pkt xdp.Packet, parser *dns.Parser,
    engine *filter.Engine, metrics *metrics.Collector) {

    // 解析 UDP 负载中的 DNS 消息
    // 假设已经跳过了 Ethernet + IP + UDP 头
    dnsData := extractDNSPayload(pkt.Data)
    if dnsData == nil {
        return
    }

    msg, err := parser.Parse(dnsData)
    if err != nil {
        metrics.IncParseError()
        return
    }

    metrics.IncReceived()

    // 只处理查询
    if !msg.IsQuery() {
        return
    }

    // 过滤检查
    srcIP := extractSourceIP(pkt.Data)
    action, rule := engine.Check(msg, srcIP)

    switch action {
    case filter.ActionAllow:
        // 允许通过 - 可以转发到真实 DNS 服务器
        metrics.IncAllowed()

    case filter.ActionBlock:
        // 生成 NXDOMAIN 响应
        response := dns.BuildNXDomainResponse(msg)
        if response != nil {
            p.sendResponse(pkt, response)
        }
        metrics.IncBlocked()
        log.Printf("Blocked: %s (rule: %s)", msg.GetQueryDomain(), rule.ID)

    case filter.ActionRedirect:
        // 生成重定向响应
        response := dns.BuildRedirectResponse(msg, rule)
        if response != nil {
            p.sendResponse(pkt, response)
        }
        metrics.IncRedirected()
    }
}

func (p *Pool) sendResponse(pkt xdp.Packet, response []byte) {
    // 构建完整响应包 (Ethernet + IP + UDP + DNS)
    // 交换源/目的地址
    responsePkt := buildResponsePacket(pkt.Data, response)

    // 发送响应
    p.options.Socket.Transmit([]xdp.Packet{{
        Data: responsePkt,
    }})
}

func (p *Pool) Wait() {
    p.wg.Wait()
}
```

## 5. 配置管理

### 5.1 主配置文件 (configs/config.yaml)

```yaml
# XDP DNS Filter 配置

# 网络接口配置
interface: eth0
queue_id: 0
queue_count: 4

# BPF 程序路径
bpf_path: /opt/xdp-dns/bpf/xdp_dns_filter.o

# AF_XDP Socket 配置
xdp:
  num_frames: 4096
  frame_size: 2048
  fill_ring_size: 2048
  comp_ring_size: 2048
  rx_ring_size: 2048
  tx_ring_size: 2048

# Worker 配置
workers:
  num_workers: 8      # 0 表示使用 CPU 核心数
  batch_size: 64

# DNS 配置
dns:
  listen_ports:
    - 53
    - 5353
  upstream_servers:
    - 8.8.8.8:53
    - 8.8.4.4:53
  cache_size: 10000
  cache_ttl: 300

# 过滤规则配置
rules_path: /opt/xdp-dns/configs/rules.yaml

# 监控配置
metrics:
  enabled: true
  listen: ":9090"
  path: /metrics

# 日志配置
logging:
  level: info
  format: json
  output: /var/log/xdp-dns/filter.log
```

### 5.2 过滤规则配置 (configs/rules.yaml)

```yaml
# DNS 过滤规则

rules:
  # 黑名单规则
  - id: block-ads
    priority: 100
    enabled: true
    action: block
    domains:
      - "*.doubleclick.net"
      - "*.googlesyndication.com"
      - "*.googleadservices.com"
      - "ads.*.com"

  - id: block-malware
    priority: 90
    enabled: true
    action: block
    domains:
      - "malware.example.com"
      - "*.malicious.org"

  # 重定向规则
  - id: redirect-internal
    priority: 80
    enabled: true
    action: redirect
    redirect_ip: "192.168.1.100"
    domains:
      - "internal.company.com"

  # 日志规则 (仅记录不阻止)
  - id: log-suspicious
    priority: 50
    enabled: true
    action: log
    query_types:
      - TXT
      - ANY
    domains:
      - "*"

# IP 黑名单
ip_blacklist:
  - "10.0.0.0/8"
  - "192.168.100.0/24"

# 速率限制
rate_limits:
  - source: "0.0.0.0/0"
    queries_per_second: 100
    burst: 200
```

## 6. 编译和部署

### 6.1 编译脚本 (scripts/build.sh)

```bash
#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/build"

echo "=== Building XDP DNS Filter ==="

# 创建输出目录
mkdir -p ${OUTPUT_DIR}

# 1. 编译 eBPF 程序
echo "[1/3] Compiling eBPF program..."
cd ${PROJECT_ROOT}/bpf

# 生成 vmlinux.h (如果不存在)
if [ ! -f vmlinux.h ]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
fi

# 编译 eBPF 程序
clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include \
    -I${PROJECT_ROOT}/bpf \
    -c xdp_dns_filter.c \
    -o ${OUTPUT_DIR}/xdp_dns_filter.o

# 2. 使用 bpf2go 生成 Go 绑定
echo "[2/3] Generating Go bindings..."
cd ${PROJECT_ROOT}/pkg/xdp
go generate ./...

# 3. 编译 Go 程序
echo "[3/3] Building Go binary..."
cd ${PROJECT_ROOT}
CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o ${OUTPUT_DIR}/dns-filter \
    ./cmd/dns-filter

echo "=== Build complete ==="
echo "Output: ${OUTPUT_DIR}/"
ls -la ${OUTPUT_DIR}/
```

### 6.2 部署脚本 (scripts/deploy.sh)

```bash
#!/bin/bash
set -e

INSTALL_DIR="/opt/xdp-dns"
SERVICE_NAME="xdp-dns-filter"
INTERFACE="${1:-eth0}"

echo "=== Deploying XDP DNS Filter ==="

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# 创建安装目录
mkdir -p ${INSTALL_DIR}/{bin,bpf,configs,logs}

# 复制文件
cp build/dns-filter ${INSTALL_DIR}/bin/
cp build/xdp_dns_filter.o ${INSTALL_DIR}/bpf/
cp configs/*.yaml ${INSTALL_DIR}/configs/

# 设置权限
chmod +x ${INSTALL_DIR}/bin/dns-filter

# 创建 systemd 服务
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=XDP DNS Filter Service
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/bin/dns-filter -config ${INSTALL_DIR}/configs/config.yaml
ExecStop=/bin/kill -SIGTERM \$MAINPID
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
LimitNOFILE=65535

# 安全设置
NoNewPrivileges=no
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF

# 重新加载 systemd
systemctl daemon-reload

# 设置网卡队列 (可选)
echo "Configuring network interface ${INTERFACE}..."
ethtool -L ${INTERFACE} combined 4 2>/dev/null || true

# 增加 locked memory 限制
echo "* - memlock unlimited" >> /etc/security/limits.d/99-xdp.conf

echo "=== Deployment complete ==="
echo "Start service: systemctl start ${SERVICE_NAME}"
echo "Enable service: systemctl enable ${SERVICE_NAME}"
```




## 7. 性能优化

### 7.1 内核层优化 (XDP/eBPF)

```c
// 1. 使用 per-CPU maps 避免锁竞争
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct metrics);
    __uint(max_entries, 1);
} percpu_metrics SEC(".maps");

// 2. 使用 LPM Trie 进行高效 IP 匹配
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, sizeof(struct lpm_key));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_lpm SEC(".maps");

// 3. 批量处理 - 使用 BPF_MAP_TYPE_QUEUE
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct pkt_info);
    __uint(max_entries, 1024);
} pkt_queue SEC(".maps");

// 4. 使用 BTF 和 CO-RE 提高兼容性
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// 5. 尾调用优化复杂逻辑
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

SEC("xdp")
int xdp_entry(struct xdp_md *ctx) {
    // 基础解析后，使用尾调用处理 DNS
    bpf_tail_call(ctx, &jmp_table, DNS_HANDLER);
    return XDP_PASS;
}
```

### 7.2 用户态优化 (Go)

```go
// 1. 对象池减少 GC 压力
var messagePool = sync.Pool{
    New: func() interface{} {
        return &dns.Message{
            Questions: make([]dns.Question, 0, 4),
        }
    },
}

func (p *Parser) Parse(data []byte) (*dns.Message, error) {
    msg := messagePool.Get().(*dns.Message)
    msg.Questions = msg.Questions[:0]
    // ... 解析逻辑
    return msg, nil
}

func (p *Parser) Release(msg *dns.Message) {
    messagePool.Put(msg)
}

// 2. 批量处理
func (p *Pool) processBatch(packets []xdp.Packet) {
    const batchSize = 64

    for i := 0; i < len(packets); i += batchSize {
        end := i + batchSize
        if end > len(packets) {
            end = len(packets)
        }

        batch := packets[i:end]
        for _, pkt := range batch {
            p.processPacket(pkt)
        }
    }
}

// 3. 使用 SIMD 加速 DNS 解析 (via assembly)
//go:noescape
func parseDNSNameSIMD(data []byte, offset int) (string, int)

// 4. 无锁数据结构
type LockFreeCounter struct {
    value uint64
}

func (c *LockFreeCounter) Inc() {
    atomic.AddUint64(&c.value, 1)
}

// 5. CPU 亲和性
func setAffinity(workerID int) {
    var cpuset unix.CPUSet
    cpuset.Set(workerID % runtime.NumCPU())
    unix.SchedSetaffinity(0, &cpuset)
}
```

### 7.3 系统级优化

```bash
#!/bin/bash
# scripts/optimize.sh - 系统优化脚本

INTERFACE=$1

# 1. 增加 Ring Buffer 大小
ethtool -G ${INTERFACE} rx 4096 tx 4096

# 2. 启用 XDP Native 模式
# 需要驱动支持，如 i40e, mlx5

# 3. 关闭中断合并 (低延迟场景)
ethtool -C ${INTERFACE} rx-usecs 0 tx-usecs 0

# 4. 启用 busy polling
sysctl -w net.core.busy_poll=50
sysctl -w net.core.busy_read=50

# 5. 增加 socket buffer
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728

# 6. 禁用 IRQ 平衡
service irqbalance stop

# 7. 手动设置 IRQ 亲和性
for irq in $(cat /proc/interrupts | grep ${INTERFACE} | awk '{print $1}' | tr -d ':'); do
    echo 2 > /proc/irq/$irq/smp_affinity
done

# 8. 设置 CPU 性能模式
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > $cpu
done

# 9. 禁用透明大页 (THP)
echo never > /sys/kernel/mm/transparent_hugepage/enabled

# 10. 内存锁定限制
ulimit -l unlimited
```

## 8. 错误处理机制

### 8.1 eBPF 程序错误处理

```c
// 所有指针访问前必须进行边界检查
SEC("xdp")
int xdp_dns_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 边界检查宏
    #define BOUNDS_CHECK(ptr, size) \
        if ((void *)(ptr) + (size) > data_end) \
            return XDP_PASS;

    struct ethhdr *eth = data;
    BOUNDS_CHECK(eth, sizeof(*eth));

    // 使用 helper 函数返回值检查
    int *value = bpf_map_lookup_elem(&config_map, &key);
    if (!value) {
        // Map 查找失败，使用默认行为
        return XDP_PASS;
    }

    // 重定向失败处理
    int ret = bpf_redirect_map(&xsks_map, index, XDP_PASS);
    // XDP_PASS 作为 fallback

    return ret;
}
```

### 8.2 Go 错误处理

```go
package errors

import (
    "fmt"
    "runtime"
)

// 自定义错误类型
type XDPError struct {
    Op      string
    Err     error
    Context map[string]interface{}
}

func (e *XDPError) Error() string {
    return fmt.Sprintf("xdp: %s: %v", e.Op, e.Err)
}

func (e *XDPError) Unwrap() error {
    return e.Err
}

// 错误恢复
func (p *Pool) safeProcessPacket(pkt xdp.Packet) {
    defer func() {
        if r := recover(); r != nil {
            buf := make([]byte, 4096)
            n := runtime.Stack(buf, false)
            log.Printf("Panic recovered: %v\n%s", r, buf[:n])
            p.options.Metrics.IncPanics()
        }
    }()

    p.processPacket(pkt)
}

// 重试机制
func (s *Socket) ReceiveWithRetry(maxRetries int) ([]Packet, error) {
    var lastErr error

    for i := 0; i < maxRetries; i++ {
        packets, err := s.Receive()
        if err == nil {
            return packets, nil
        }

        lastErr = err

        // 判断是否可重试
        if !isRetryable(err) {
            return nil, err
        }

        time.Sleep(time.Duration(i*10) * time.Millisecond)
    }

    return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// 健康检查
type HealthChecker struct {
    socket  *xdp.Socket
    program *xdp.Program
}

func (h *HealthChecker) Check() error {
    // 检查 socket 状态
    stats, err := h.socket.Stats()
    if err != nil {
        return fmt.Errorf("socket stats failed: %w", err)
    }

    // 检查丢包率
    dropRate := float64(stats.KernelStats.RxDropped) / float64(stats.Received)
    if dropRate > 0.01 { // 1% 丢包阈值
        return fmt.Errorf("high drop rate: %.2f%%", dropRate*100)
    }

    // 检查 eBPF 程序
    info, err := h.program.Info()
    if err != nil {
        return fmt.Errorf("program info failed: %w", err)
    }

    if !info.IsAttached() {
        return fmt.Errorf("XDP program not attached")
    }

    return nil
}
```

## 9. 测试和验证方案

### 9.1 单元测试

```go
// pkg/dns/parser_test.go
package dns

import (
    "testing"
)

func TestParser_Parse(t *testing.T) {
    tests := []struct {
        name    string
        data    []byte
        want    *Message
        wantErr bool
    }{
        {
            name: "valid A query",
            data: []byte{
                0x12, 0x34, // ID
                0x01, 0x00, // Flags (standard query)
                0x00, 0x01, // QDCount
                0x00, 0x00, // ANCount
                0x00, 0x00, // NSCount
                0x00, 0x00, // ARCount
                // Question: example.com
                0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                0x03, 'c', 'o', 'm',
                0x00,       // null terminator
                0x00, 0x01, // Type A
                0x00, 0x01, // Class IN
            },
            want: &Message{
                Header: Header{ID: 0x1234, QDCount: 1},
                Questions: []Question{{
                    Name:   "example.com",
                    QType:  TypeA,
                    QClass: 1,
                }},
            },
            wantErr: false,
        },
        {
            name:    "too short",
            data:    []byte{0x12, 0x34},
            want:    nil,
            wantErr: true,
        },
    }

    p := NewParser()
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := p.Parse(tt.data)
            if (err != nil) != tt.wantErr {
                t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !tt.wantErr && got.Header.ID != tt.want.Header.ID {
                t.Errorf("Parse() ID = %v, want %v", got.Header.ID, tt.want.Header.ID)
            }
        })
    }
}

// 基准测试
func BenchmarkParser_Parse(b *testing.B) {
    data := []byte{/* DNS query packet */}
    p := NewParser()

    b.ResetTimer()
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        _, _ = p.Parse(data)
    }
}
```

### 9.2 集成测试

```go
// tests/integration/xdp_test.go
package integration

import (
    "context"
    "net"
    "testing"
    "time"

    "github.com/stretchr/testify/require"
)

func TestXDPDNSFilter_E2E(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }

    // 需要 root 权限
    requireRoot(t)

    // 启动测试服务
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // 初始化 XDP 程序和 socket
    // ...

    // 发送测试 DNS 查询
    conn, err := net.Dial("udp", "127.0.0.1:53")
    require.NoError(t, err)
    defer conn.Close()

    // 构建 DNS 查询
    query := buildDNSQuery("blocked.example.com", TypeA)
    _, err = conn.Write(query)
    require.NoError(t, err)

    // 读取响应
    buf := make([]byte, 512)
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    n, err := conn.Read(buf)
    require.NoError(t, err)

    // 验证响应是 NXDOMAIN
    response := parseDNSResponse(buf[:n])
    require.Equal(t, RCodeNXDomain, response.RCode)
}
```

### 9.3 性能基准测试

```go
// tests/benchmark/throughput_test.go
package benchmark

import (
    "testing"
    "time"
)

func BenchmarkThroughput(b *testing.B) {
    // 初始化 XDP 系统
    // ...

    b.ResetTimer()

    start := time.Now()
    var totalPackets uint64

    for i := 0; i < b.N; i++ {
        // 发送批量 DNS 查询
        packets := generateDNSPackets(1000)
        sendPackets(packets)
        totalPackets += 1000
    }

    elapsed := time.Since(start)
    pps := float64(totalPackets) / elapsed.Seconds()

    b.ReportMetric(pps, "packets/sec")
}
```

### 9.4 测试脚本

```bash
#!/bin/bash
# scripts/test.sh

set -e

echo "=== Running XDP DNS Filter Tests ==="

# 1. 单元测试
echo "[1/4] Running unit tests..."
go test -v -race ./pkg/...

# 2. 集成测试 (需要 root)
echo "[2/4] Running integration tests..."
sudo go test -v ./tests/integration/... -tags=integration

# 3. 性能测试
echo "[3/4] Running benchmarks..."
go test -bench=. -benchmem ./tests/benchmark/...

# 4. 功能验证
echo "[4/4] Running functional tests..."

# 启动服务
sudo ./build/dns-filter &
PID=$!
sleep 2

# 测试查询
echo "Testing allowed domain..."
dig @127.0.0.1 google.com +short

echo "Testing blocked domain..."
dig @127.0.0.1 blocked.example.com +short || echo "Blocked as expected"

# 停止服务
sudo kill $PID

echo "=== All tests passed ==="
```

## 10. 监控和运维

### 10.1 Prometheus 指标

```go
// pkg/metrics/exporter.go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    PacketsReceived = promauto.NewCounter(prometheus.CounterOpts{
        Name: "xdp_dns_packets_received_total",
        Help: "Total DNS packets received",
    })

    PacketsBlocked = promauto.NewCounter(prometheus.CounterOpts{
        Name: "xdp_dns_packets_blocked_total",
        Help: "Total DNS packets blocked",
    })

    PacketLatency = promauto.NewHistogram(prometheus.HistogramOpts{
        Name:    "xdp_dns_packet_latency_seconds",
        Help:    "Packet processing latency",
        Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
    })

    XDPDrops = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "xdp_kernel_drops",
        Help: "Kernel XDP drops",
    })
)
```

### 10.2 Grafana Dashboard

```json
{
  "title": "XDP DNS Filter Dashboard",
  "panels": [
    {
      "title": "Packets/sec",
      "targets": [
        {"expr": "rate(xdp_dns_packets_received_total[1m])"}
      ]
    },
    {
      "title": "Block Rate",
      "targets": [
        {"expr": "rate(xdp_dns_packets_blocked_total[1m]) / rate(xdp_dns_packets_received_total[1m]) * 100"}
      ]
    },
    {
      "title": "Latency P99",
      "targets": [
        {"expr": "histogram_quantile(0.99, rate(xdp_dns_packet_latency_seconds_bucket[5m]))"}
      ]
    }
  ]
}
```

## 11. 总结

### 11.1 关键技术点

1. **XDP (eXpress Data Path)**: 在网卡驱动层处理数据包，绕过内核网络栈
2. **AF_XDP Socket**: 提供用户态零拷贝数据包访问
3. **eBPF Maps**: 内核态与用户态高效数据共享
4. **UMEM**: 共享内存区域，实现真正的零拷贝

### 11.2 性能预期

| 指标 | 目标值 |
|------|--------|
| 吞吐量 | > 1M PPS |
| 延迟 (P99) | < 100μs |
| CPU 使用率 | < 20% (单核) |
| 内存使用 | < 100MB |

### 11.3 后续优化方向

1. **多队列支持**: 利用 RSS 分散负载到多个 CPU
2. **零拷贝响应**: 在 UMEM 中直接构建响应包
3. **域名 Trie 优化**: 使用 SIMD 加速匹配
4. **热更新**: 支持规则热加载不中断服务
5. **集群部署**: 多节点负载均衡和故障转移
