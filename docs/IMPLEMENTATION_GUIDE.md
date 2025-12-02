# XDP DNS Filter 混合架构完整实施方案

## 目录

1. [项目概述](#1-项目概述)
2. [架构设计](#2-架构设计)
3. [环境搭建](#3-环境搭建)
4. [开发指南](#4-开发指南)
5. [部署手册](#5-部署手册)
6. [性能优化](#6-性能优化)
7. [运维指南](#7-运维指南)
8. [最佳实践](#8-最佳实践)

---

## 1. 项目概述

### 1.1 项目目标

构建一个高性能 DNS 流量过滤系统，实现：

- **超高吞吐量**: 单机 10M+ PPS
- **超低延迟**: P99 < 1ms
- **灵活过滤**: 支持域名黑白名单、正则匹配、通配符
- **实时监控**: Prometheus 指标导出
- **热更新**: 规则实时生效，无需重启

### 1.2 技术选型

| 组件 | 技术 | 理由 |
|------|------|------|
| 数据面 | C++ 17 | 64x 更快的 DNS 解析 |
| 匹配引擎 | Go | 2x 更快的 Trie 匹配 |
| 包处理 | XDP/eBPF | 内核级零拷贝 |
| 配置管理 | YAML | 人类可读 |
| 监控 | Prometheus | 行业标准 |

### 1.3 性能指标

```
┌─────────────────────────────────────────────────────────────┐
│                    性能对比总览                              │
├─────────────────┬──────────────┬──────────────┬─────────────┤
│ 指标             │ 纯 Go        │ 混合架构      │ 提升        │
├─────────────────┼──────────────┼──────────────┼─────────────┤
│ DNS 解析        │ 770 ns       │ 12 ns        │ 64x         │
│ 响应构建        │ 2200 ns      │ 4 ns         │ 550x        │
│ 端到端 (Block)  │ 2125 ns      │ 724 ns       │ 2.9x        │
│ 吞吐量 (单核)   │ 500K PPS     │ 1.4M PPS     │ 2.8x        │
│ 内存分配        │ 35 allocs    │ 8 allocs     │ -77%        │
└─────────────────┴──────────────┴──────────────┴─────────────┘
```

---

## 2. 架构设计

### 2.1 整体架构

```
                           ┌─────────────────────────────────────┐
                           │           控制面 (Go)                │
                           │  ┌─────────┐ ┌─────────┐ ┌────────┐ │
                           │  │ Config  │ │ Rules   │ │ HTTP   │ │
                           │  │ Manager │ │ Engine  │ │ API    │ │
                           │  └────┬────┘ └────┬────┘ └────────┘ │
                           └───────┼───────────┼──────────────────┘
                                   │           │
                    ┌──────────────┼───────────┼──────────────────┐
                    │              ▼           ▼                  │
                    │  ┌───────────────────────────────────────┐  │
                    │  │         混合处理器 (Hybrid)            │  │
                    │  │                                       │  │
                    │  │  ┌─────────┐  ┌─────────┐  ┌────────┐ │  │
 Network ──────────▶│  │  │ C++ DNS │─▶│ Go Trie │─▶│ C++    │ │  │
                    │  │  │ Parser  │  │ Match   │  │ Builder│ │  │
                    │  │  │ (12ns)  │  │ (160ns) │  │ (4ns)  │ │  │
                    │  │  └─────────┘  └─────────┘  └────────┘ │  │
                    │  └───────────────────────────────────────┘  │
                    │                    数据面                    │
                    └─────────────────────────────────────────────┘
                                         │
                    ┌────────────────────┼────────────────────────┐
                    │                    ▼                        │
                    │  ┌───────────────────────────────────────┐  │
                    │  │           XDP/eBPF 层                  │  │
                    │  │   ETH → IP → UDP → DNS Port Check     │  │
                    │  └───────────────────────────────────────┘  │
                    │                  内核空间                    │
                    └─────────────────────────────────────────────┘
```

### 2.2 数据流

```
1. 网络包到达网卡
       │
       ▼
2. XDP 程序快速过滤 (非 DNS 直接放行)
       │
       ▼
3. AF_XDP Socket 零拷贝传递到用户态
       │
       ▼
4. C++ DNS 解析器解析查询 (12ns)
       │
       ▼
5. Go Trie 引擎匹配规则 (160ns)
       │
       ▼
6. 根据动作决定：
   ├─ Allow: 转发到上游 DNS
   ├─ Block: C++ 构建 NXDOMAIN (24ns)
   └─ Redirect: C++ 构建 A 记录 (4ns)
       │
       ▼
7. 响应返回客户端
```

### 2.3 模块划分

| 模块 | 语言 | 职责 | 性能要求 |
|------|------|------|---------|
| `cpp/src/dns_parser.cpp` | C++ | DNS 解析 | < 20ns |
| `cpp/src/cgo_bridge.cpp` | C++ | CGO 桥接 | < 50ns |
| `pkg/filter/engine.go` | Go | 规则匹配 | < 200ns |
| `pkg/dns/hybrid/processor.go` | Go | 流程编排 | < 800ns |
| `bpf/xdp_dns_filter.c` | C/BPF | 包过滤 | < 100ns |

---

## 3. 环境搭建

### 3.1 系统要求

```bash
# 操作系统
- Ubuntu 22.04 LTS (推荐)
- Kernel 5.15+ (XDP 支持)
- 64-bit x86_64

# 硬件要求
- CPU: 4+ 核心 (推荐 8+)
- 内存: 4GB+ (推荐 8GB+)
- 网卡: 支持 XDP 的网卡 (Intel, Mellanox 等)
```

### 3.2 依赖安装

```bash
#!/bin/bash
# install_dependencies.sh

set -e

echo "=== 安装基础依赖 ==="
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libelf-dev \
    clang \
    llvm \
    libbpf-dev

echo "=== 安装 C++ 开发依赖 ==="
sudo apt-get install -y \
    g++ \
    libgtest-dev \
    libbenchmark-dev

echo "=== 安装 Go ==="
GO_VERSION="1.21.5"
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

echo "=== 验证安装 ==="
go version
g++ --version
cmake --version
clang --version

echo "=== 安装完成 ==="
```

### 3.3 项目克隆与编译

```bash
# 1. 克隆项目
git clone https://github.com/gugugu5331/XDP-DNS.git
cd XDP-DNS

# 2. 编译 C++ 库
mkdir -p cpp/build && cd cpp/build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
make -j$(nproc)

# 3. 验证 C++ 编译
./xdp_dns_tests      # 应该显示 16 tests passed
./xdp_dns_benchmark  # 性能基准测试

# 4. 设置库路径
export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH
cd ../..

# 5. 编译 Go 应用
go build -o dns-filter ./cmd/dns-filter

# 6. 验证完整构建
./dns-filter --version
```

### 3.4 开发环境配置

```bash
# .envrc (推荐使用 direnv)
export PROJECT_ROOT=$(pwd)
export LD_LIBRARY_PATH=$PROJECT_ROOT/cpp/build:$LD_LIBRARY_PATH
export CGO_CFLAGS="-I$PROJECT_ROOT/cpp/include"
export CGO_LDFLAGS="-L$PROJECT_ROOT/cpp/build -lxdp_dns"

# IDE 配置 (VSCode settings.json)
{
    "go.buildFlags": ["-tags=cgo"],
    "go.testEnvVars": {
        "LD_LIBRARY_PATH": "${workspaceFolder}/cpp/build"
    },
    "C_Cpp.default.includePath": [
        "${workspaceFolder}/cpp/include"
    ]
}
```

---

## 4. 开发指南

### 4.1 C++ 数据面开发

#### 4.1.1 DNS 解析器

```cpp
// cpp/include/xdp_dns/dns_parser.hpp 关键接口

namespace xdp_dns {

// DNS 解析结果
struct DNSParseResult {
    const DNSHeader* header;    // 零拷贝指向原始数据
    DNSQuestion question;       // 问题部分
    size_t question_end;        // 问题结束位置
    uint16_t id;                // DNS ID
    uint16_t flags;             // 标志位
    bool is_query;              // 是否查询
};

class DNSParser {
public:
    // 解析 DNS 查询 (性能: ~12ns)
    static Error parse(
        const uint8_t* data,
        size_t len,
        DNSParseResult* result
    );

    // 解码域名 (性能: ~50ns)
    static Error decodeName(
        const uint8_t* packet,
        size_t packet_len,
        size_t name_offset,
        char* out_buf,
        size_t buf_size,
        size_t* out_len
    );
};

} // namespace xdp_dns
```

#### 4.1.2 响应构建器

```cpp
// cpp/include/xdp_dns/dns_parser.hpp

class DNSResponseBuilder {
public:
    // 构建 NXDOMAIN 响应 (性能: ~24ns)
    static size_t buildNXDomain(
        const uint8_t* query,
        size_t query_len,
        const DNSParseResult& parsed,
        uint8_t* response,
        size_t response_buf_size
    );

    // 构建 A 记录响应 (性能: ~4ns)
    static size_t buildAResponse(
        const uint8_t* query,
        size_t query_len,
        const DNSParseResult& parsed,
        uint32_t ip,           // 网络字节序
        uint32_t ttl,
        uint8_t* response,
        size_t response_buf_size
    );
};
```

#### 4.1.3 CGO 桥接

```c
// cpp/include/xdp_dns/cgo_bridge.h

// 供 Go 调用的 C 接口
int xdp_dns_parse(
    const uint8_t* packet_data,
    size_t packet_len,
    XDPDNSParseResult* result
);

int xdp_dns_build_nxdomain(
    const uint8_t* original_packet,
    size_t original_len,
    uint8_t* response_buf,
    size_t response_buf_size,
    size_t* response_len
);

int xdp_dns_build_a_response(
    const uint8_t* original_packet,
    size_t original_len,
    uint32_t ipv4_addr,
    uint32_t ttl,
    uint8_t* response_buf,
    size_t response_buf_size,
    size_t* response_len
);
```

### 4.2 Go 管理面开发

#### 4.2.1 CGO 绑定

```go
// pkg/dns/cppbridge/bridge.go

package cppbridge

/*
#cgo CFLAGS: -I${SRCDIR}/../../../cpp/include
#cgo LDFLAGS: -L${SRCDIR}/../../../cpp/build -lxdp_dns -lstdc++
#include "xdp_dns/cgo_bridge.h"
*/
import "C"
import "unsafe"

// Parse 使用 C++ 高性能解析器解析 DNS 查询
func Parse(packet []byte) (*ParseResult, error) {
    var result C.XDPDNSParseResult

    ret := C.xdp_dns_parse(
        (*C.uint8_t)(unsafe.Pointer(&packet[0])),
        C.size_t(len(packet)),
        &result,
    )

    if ret != 0 {
        return nil, codeToError(int(ret))
    }

    return &ParseResult{
        ID:     uint16(result.id),
        Domain: C.GoStringN(&result.domain[0], C.int(result.domain_len)),
        QType:  uint16(result.qtype),
    }, nil
}
```

#### 4.2.2 混合处理器

```go
// pkg/dns/hybrid/processor.go

package hybrid

type Processor struct {
    engine *filter.Engine
}

func NewProcessor(engine *filter.Engine) (*Processor, error) {
    if err := cppbridge.Init(); err != nil {
        return nil, err
    }
    return &Processor{engine: engine}, nil
}

// Process 处理 DNS 数据包 (总延迟 ~720ns)
func (p *Processor) Process(packet []byte) (*ProcessResult, error) {
    // Step 1: C++ 解析 (12ns)
    parsed, err := cppbridge.Parse(packet)
    if err != nil {
        return nil, err
    }

    // Step 2: Go Trie 匹配 (160ns)
    result, err := p.engine.CheckDomain(parsed.Domain, parsed.QType)
    if err != nil {
        return &ProcessResult{Action: filter.ActionAllow}, nil
    }

    pr := &ProcessResult{
        Action: result.Action,
        Domain: parsed.Domain,
    }

    // Step 3: C++ 响应构建 (4-24ns)
    switch result.Action {
    case filter.ActionBlock:
        pr.Response, err = cppbridge.BuildNXDomain(packet)
    case filter.ActionRedirect:
        ip := binary.BigEndian.Uint32(result.RedirectIP)
        pr.Response, err = cppbridge.BuildAResponse(packet, ip, result.TTL)
    }

    return pr, err
}
```

#### 4.2.3 过滤引擎

```go
// pkg/filter/engine.go

type Engine struct {
    rules      []Rule
    domainTrie *DomainTrie
    mu         sync.RWMutex
}

// CheckDomain 检查域名匹配 (性能: ~160ns)
func (e *Engine) CheckDomain(domain string, qtype uint16) (*CheckResult, error) {
    e.mu.RLock()
    defer e.mu.RUnlock()

    // 1. Trie 精确匹配
    if rule := e.domainTrie.Match(domain); rule != nil {
        return e.buildResult(rule), nil
    }

    // 2. 通配符匹配
    for _, rule := range e.rules {
        if matchWildcard(domain, rule.Domains) {
            return e.buildResult(&rule), nil
        }
    }

    return &CheckResult{Action: ActionAllow}, nil
}

// AddRule 动态添加规则 (支持热更新)
func (e *Engine) AddRule(rule Rule) {
    e.mu.Lock()
    defer e.mu.Unlock()

    e.rules = append(e.rules, rule)
    for _, domain := range rule.Domains {
        if !strings.HasPrefix(domain, "*") {
            e.domainTrie.Insert(domain, &rule)
        }
    }
}
```

### 4.3 规则配置

#### 4.3.1 规则文件格式

```yaml
# configs/rules.yaml

version: "1.0"
rules:
  # 阻止广告域名
  - id: block_ads
    priority: 100
    enabled: true
    action: block
    domains:
      - "*.doubleclick.net"
      - "*.googlesyndication.com"
      - "ads.*.com"
    query_types:
      - A
      - AAAA

  # 重定向恶意域名
  - id: redirect_malware
    priority: 90
    enabled: true
    action: redirect
    redirect_ip: "127.0.0.1"
    redirect_ttl: 3600
    domains:
      - "*.malware.com"
      - "phishing.example.com"

  # 仅记录可疑域名
  - id: log_suspicious
    priority: 50
    enabled: true
    action: log
    domains:
      - "*.suspicious.net"
```

#### 4.3.2 规则优先级

```
┌─────────────────────────────────────────────────────────────┐
│                    规则匹配流程                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DNS Query: "ads.doubleclick.net"                          │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────┐               │
│  │ 1. Trie 精确匹配                         │               │
│  │    - 查找 "ads.doubleclick.net"         │               │
│  │    - 未找到                              │               │
│  └─────────────────────────────────────────┘               │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────┐               │
│  │ 2. 按优先级遍历规则                      │               │
│  │    - Priority 100: block_ads            │               │
│  │    - 匹配 "*.doubleclick.net" ✓         │               │
│  └─────────────────────────────────────────┘               │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────┐               │
│  │ 3. 执行动作                              │               │
│  │    - Action: BLOCK                       │               │
│  │    - 构建 NXDOMAIN 响应                  │               │
│  └─────────────────────────────────────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. 部署手册

### 5.1 部署架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        生产部署架构                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│    ┌─────────────┐      ┌─────────────┐      ┌─────────────┐   │
│    │   Client    │      │   Client    │      │   Client    │   │
│    └──────┬──────┘      └──────┬──────┘      └──────┬──────┘   │
│           │                    │                    │           │
│           └────────────────────┼────────────────────┘           │
│                                │                                │
│                         ┌──────▼──────┐                         │
│                         │ Load Balancer│                        │
│                         └──────┬───────┘                        │
│                                │                                │
│           ┌────────────────────┼────────────────────┐           │
│           │                    │                    │           │
│    ┌──────▼──────┐      ┌──────▼──────┐      ┌──────▼──────┐   │
│    │  DNS Filter │      │  DNS Filter │      │  DNS Filter │   │
│    │   Node 1    │      │   Node 2    │      │   Node 3    │   │
│    │ (Active)    │      │ (Active)    │      │ (Standby)   │   │
│    └──────┬──────┘      └──────┬──────┘      └─────────────┘   │
│           │                    │                                │
│           └────────────────────┼────────────────────────────────┤
│                                │                                │
│                         ┌──────▼──────┐                         │
│                         │   Upstream  │                         │
│                         │ DNS Server  │                         │
│                         │ (8.8.8.8)   │                         │
│                         └─────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 系统配置

```bash
#!/bin/bash
# scripts/prepare_system.sh

set -e

echo "=== 系统优化配置 ==="

# 1. 内核参数优化
cat >> /etc/sysctl.conf << 'EOF'
# XDP DNS Filter 优化配置

# 网络栈优化
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535

# UDP 优化
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# XDP 相关
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 0
EOF

sysctl -p

# 2. 大页内存
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
echo "vm.nr_hugepages = 1024" >> /etc/sysctl.conf

# 3. CPU 亲和性
echo "performance" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 4. 网卡优化
IFACE="eth0"  # 根据实际情况修改
ethtool -G $IFACE rx 4096 tx 4096
ethtool -K $IFACE rx-gro on
ethtool -K $IFACE tx-gro on

echo "=== 系统配置完成 ==="
```

### 5.3 服务配置

```yaml
# configs/config.yaml

server:
  listen: ":53"
  workers: 8

xdp:
  interface: "eth0"
  queue_id: 0
  num_frames: 4096
  frame_size: 2048

upstream:
  servers:
    - "8.8.8.8:53"
    - "8.8.4.4:53"
  timeout: 2s
  retry: 3

filter:
  rules_path: "/etc/xdp-dns/rules.yaml"
  reload_interval: 30s

metrics:
  enabled: true
  listen: ":9090"
  path: "/metrics"

logging:
  level: "info"
  format: "json"
  output: "/var/log/xdp-dns/dns-filter.log"
```

### 5.4 Systemd 服务

```ini
# /etc/systemd/system/xdp-dns-filter.service

[Unit]
Description=XDP DNS Filter Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/xdp-dns/dns-filter \
    --config=/etc/xdp-dns/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitMEMLOCK=infinity

# 环境变量
Environment="LD_LIBRARY_PATH=/opt/xdp-dns/lib"
Environment="GOMAXPROCS=8"

# 资源限制
MemoryLimit=2G
CPUQuota=800%

[Install]
WantedBy=multi-user.target
```

### 5.5 部署脚本

```bash
#!/bin/bash
# scripts/deploy.sh

set -e

VERSION=${1:-"latest"}
INSTALL_DIR="/opt/xdp-dns"
CONFIG_DIR="/etc/xdp-dns"
LOG_DIR="/var/log/xdp-dns"

echo "=== XDP DNS Filter 部署 ==="
echo "版本: $VERSION"

# 1. 创建目录
mkdir -p $INSTALL_DIR/{bin,lib}
mkdir -p $CONFIG_DIR
mkdir -p $LOG_DIR

# 2. 停止现有服务
systemctl stop xdp-dns-filter || true

# 3. 复制文件
cp build/dns-filter $INSTALL_DIR/bin/
cp cpp/build/libxdp_dns.so* $INSTALL_DIR/lib/
cp configs/*.yaml $CONFIG_DIR/

# 4. 设置权限
chmod +x $INSTALL_DIR/bin/dns-filter
chown -R root:root $INSTALL_DIR

# 5. 安装服务
cp scripts/xdp-dns-filter.service /etc/systemd/system/
systemctl daemon-reload

# 6. 启动服务
systemctl enable xdp-dns-filter
systemctl start xdp-dns-filter

# 7. 验证
sleep 2
systemctl status xdp-dns-filter
echo "=== 部署完成 ==="
```

---

## 6. 性能优化

### 6.1 性能调优参数

```yaml
# configs/performance.yaml

# CPU 优化
cpu:
  # Go runtime
  gomaxprocs: 8           # 等于物理核心数
  gogc: 100               # GC 触发百分比 (100=默认)

  # 亲和性绑定
  affinity:
    enabled: true
    cores: [0, 1, 2, 3]   # 绑定到特定核心

# 内存优化
memory:
  # 对象池
  pool:
    packet_buffer_size: 2048
    max_pool_size: 10000

  # 预分配
  preallocate:
    response_buffers: 1000
    parse_results: 1000

# 网络优化
network:
  # XDP 配置
  xdp:
    mode: "native"        # native | generic | offload
    batch_size: 64        # 批处理大小

  # Socket 配置
  socket:
    rx_ring_size: 4096
    tx_ring_size: 4096
    fill_ring_size: 4096
    comp_ring_size: 4096
```

### 6.2 批处理优化

```go
// 批量处理减少 CGO 调用开销
type BatchProcessor struct {
    batchSize int
    packets   [][]byte
    results   []*ProcessResult
}

func (bp *BatchProcessor) ProcessBatch(packets [][]byte) ([]*ProcessResult, error) {
    // 1. 批量 C++ 解析
    parseResults := make([]*cppbridge.ParseResult, len(packets))
    for i, pkt := range packets {
        parseResults[i], _ = cppbridge.Parse(pkt)
    }

    // 2. 批量 Go 匹配
    checkResults := make([]*filter.CheckResult, len(packets))
    for i, pr := range parseResults {
        checkResults[i], _ = bp.engine.CheckDomain(pr.Domain, pr.QType)
    }

    // 3. 批量 C++ 响应构建
    responses := make([][]byte, len(packets))
    for i, cr := range checkResults {
        switch cr.Action {
        case filter.ActionBlock:
            responses[i], _ = cppbridge.BuildNXDomain(packets[i])
        case filter.ActionRedirect:
            responses[i], _ = cppbridge.BuildAResponse(packets[i], cr.IP, cr.TTL)
        }
    }

    return bp.buildResults(checkResults, responses), nil
}
```

### 6.3 内存池优化

```go
// pkg/dns/pool/buffer_pool.go

var packetPool = sync.Pool{
    New: func() interface{} {
        buf := make([]byte, 2048)
        return &buf
    },
}

func GetPacketBuffer() *[]byte {
    return packetPool.Get().(*[]byte)
}

func PutPacketBuffer(buf *[]byte) {
    *buf = (*buf)[:0]  // 重置长度
    packetPool.Put(buf)
}

// 使用示例
func processPacket(rawData []byte) {
    buf := GetPacketBuffer()
    defer PutPacketBuffer(buf)

    // 使用 buf 处理数据
    copy(*buf, rawData)
    // ...
}
```

### 6.4 性能监控

```go
// pkg/metrics/performance.go

var (
    parseLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "xdp_dns_parse_latency_nanoseconds",
            Help:    "DNS 解析延迟分布",
            Buckets: []float64{10, 20, 50, 100, 200, 500, 1000},
        },
        []string{"result"},
    )

    processLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "xdp_dns_process_latency_nanoseconds",
            Help:    "端到端处理延迟分布",
            Buckets: []float64{100, 200, 500, 1000, 2000, 5000},
        },
        []string{"action"},
    )

    throughput = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "xdp_dns_packets_total",
            Help: "处理的数据包总数",
        },
        []string{"action"},
    )
)

// 延迟采样
func recordLatency(start time.Time, action string) {
    elapsed := time.Since(start).Nanoseconds()
    processLatency.WithLabelValues(action).Observe(float64(elapsed))
}
```

### 6.5 基准测试

```bash
#!/bin/bash
# scripts/benchmark.sh

echo "=== 完整性能基准测试 ==="

# 1. C++ 单元测试
echo ""
echo ">>> C++ 单元测试"
cd cpp/build
./xdp_dns_tests

# 2. C++ 基准测试
echo ""
echo ">>> C++ 基准测试"
./xdp_dns_benchmark --benchmark_repetitions=3

# 3. Go 基准测试
echo ""
echo ">>> Go 基准测试"
cd ../..
export LD_LIBRARY_PATH=$PWD/cpp/build
go test -bench=. -benchmem -count=3 ./pkg/dns/hybrid/
go test -bench=. -benchmem -count=3 ./tests/benchmark/

# 4. 端到端压测
echo ""
echo ">>> 端到端压测 (dnsperf)"
if command -v dnsperf &> /dev/null; then
    dnsperf -s 127.0.0.1 -d queries.txt -l 10 -c 10 -Q 100000
else
    echo "dnsperf 未安装，跳过"
fi

echo ""
echo "=== 测试完成 ==="
```

---

## 7. 运维指南

### 7.1 监控告警

```yaml
# prometheus/alerts.yaml

groups:
  - name: xdp-dns-filter
    rules:
      # 高延迟告警
      - alert: DNSHighLatency
        expr: histogram_quantile(0.99, xdp_dns_process_latency_nanoseconds) > 5000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "DNS 处理延迟过高"
          description: "P99 延迟超过 5μs"

      # 高错误率告警
      - alert: DNSHighErrorRate
        expr: rate(xdp_dns_errors_total[5m]) > 100
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "DNS 错误率过高"
          description: "每秒错误超过 100"

      # 服务不可用
      - alert: DNSServiceDown
        expr: up{job="xdp-dns-filter"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "DNS Filter 服务不可用"
```

### 7.2 日志管理

```yaml
# configs/logging.yaml

logging:
  level: info
  format: json

  outputs:
    - type: file
      path: /var/log/xdp-dns/dns-filter.log
      max_size: 100MB
      max_backups: 10
      max_age: 30
      compress: true

    - type: stdout
      format: text

  # 访问日志 (采样)
  access_log:
    enabled: true
    sample_rate: 0.01  # 1% 采样
    fields:
      - client_ip
      - domain
      - action
      - latency_ns
```

### 7.3 规则热更新

```bash
# 方式 1: SIGHUP 信号
sudo kill -HUP $(pidof dns-filter)

# 方式 2: HTTP API
curl -X POST http://localhost:9090/api/v1/rules/reload

# 方式 3: 监听文件变化 (自动)
# 配置 reload_interval: 30s 后自动生效
```

```go
// internal/reload/watcher.go

func WatchRulesFile(path string, engine *filter.Engine) {
    watcher, _ := fsnotify.NewWatcher()
    watcher.Add(path)

    for event := range watcher.Events {
        if event.Op&fsnotify.Write == fsnotify.Write {
            log.Info("检测到规则文件变化，重新加载")
            if err := engine.LoadRules(path); err != nil {
                log.Errorf("规则加载失败: %v", err)
            } else {
                log.Info("规则重新加载成功")
            }
        }
    }
}
```

### 7.4 故障排查

```bash
#!/bin/bash
# scripts/troubleshoot.sh

echo "=== XDP DNS Filter 故障排查 ==="

# 1. 服务状态
echo ""
echo ">>> 服务状态"
systemctl status xdp-dns-filter

# 2. 最近日志
echo ""
echo ">>> 最近日志 (最后 50 行)"
journalctl -u xdp-dns-filter -n 50 --no-pager

# 3. 资源使用
echo ""
echo ">>> 资源使用"
ps aux | grep dns-filter
cat /proc/$(pidof dns-filter)/status | grep -E "VmRSS|VmSize|Threads"

# 4. 网络连接
echo ""
echo ">>> 监听端口"
ss -ulnp | grep dns-filter

# 5. XDP 状态
echo ""
echo ">>> XDP 程序状态"
ip link show | grep xdp

# 6. 指标检查
echo ""
echo ">>> Prometheus 指标"
curl -s http://localhost:9090/metrics | head -30

echo ""
echo "=== 排查完成 ==="
```

### 7.5 备份恢复

```bash
#!/bin/bash
# scripts/backup.sh

BACKUP_DIR="/backup/xdp-dns/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

# 备份配置
cp -r /etc/xdp-dns/* $BACKUP_DIR/
cp /etc/systemd/system/xdp-dns-filter.service $BACKUP_DIR/

# 备份日志
tar -czf $BACKUP_DIR/logs.tar.gz /var/log/xdp-dns/

echo "备份完成: $BACKUP_DIR"

# 恢复脚本
# scripts/restore.sh $BACKUP_DIR
```

---

## 8. 最佳实践

### 8.1 规则设计

```yaml
# ✅ 好的规则设计
rules:
  # 1. 高优先级放前面
  - id: whitelist_internal
    priority: 1000
    action: allow
    domains:
      - "*.internal.company.com"

  # 2. 精确域名优先于通配符
  - id: block_specific
    priority: 100
    action: block
    domains:
      - "malware.example.com"   # 精确匹配

  # 3. 通配符规则放后面
  - id: block_wildcard
    priority: 50
    action: block
    domains:
      - "*.malware.com"         # 通配符

# ❌ 避免的规则设计
rules:
  # 避免过于宽泛的通配符
  - id: bad_rule
    action: block
    domains:
      - "*"                     # 太宽泛!
      - "*.com"                 # 太宽泛!
```

### 8.2 资源规划

```
┌─────────────────────────────────────────────────────────────┐
│                    资源规划指南                              │
├─────────────────┬───────────────────────────────────────────┤
│ 流量规模         │ 推荐配置                                  │
├─────────────────┼───────────────────────────────────────────┤
│ < 100K PPS      │ 2 核 / 2GB 内存 / 纯 Go 实现              │
│ 100K - 500K PPS │ 4 核 / 4GB 内存 / 混合架构                 │
│ 500K - 1M PPS   │ 8 核 / 8GB 内存 / 混合架构 + XDP           │
│ > 1M PPS        │ 16 核 / 16GB 内存 / 多实例 + 负载均衡      │
└─────────────────┴───────────────────────────────────────────┘
```

### 8.3 安全建议

```yaml
# 1. 网络隔离
security:
  # 仅监听内网
  listen: "10.0.0.1:53"

  # 限制管理接口访问
  management:
    listen: "127.0.0.1:9090"
    allowed_ips:
      - "127.0.0.1"
      - "10.0.0.0/8"

# 2. 最小权限
# 使用 capabilities 而非 root
# setcap cap_net_admin,cap_net_raw+ep /opt/xdp-dns/bin/dns-filter

# 3. 日志脱敏
logging:
  # 不记录完整客户端 IP
  anonymize_ip: true
  # 不记录完整域名
  hash_domains: true
```

### 8.4 升级策略

```bash
#!/bin/bash
# scripts/rolling_upgrade.sh

# 蓝绿部署升级
OLD_VERSION=$(readlink /opt/xdp-dns/current)
NEW_VERSION=$1

# 1. 部署新版本
mkdir -p /opt/xdp-dns/$NEW_VERSION
cp -r ./build/* /opt/xdp-dns/$NEW_VERSION/

# 2. 测试新版本
/opt/xdp-dns/$NEW_VERSION/bin/dns-filter --test-config
if [ $? -ne 0 ]; then
    echo "配置测试失败，中止升级"
    exit 1
fi

# 3. 切换流量
ln -sfn /opt/xdp-dns/$NEW_VERSION /opt/xdp-dns/current
systemctl restart xdp-dns-filter

# 4. 验证
sleep 5
if systemctl is-active --quiet xdp-dns-filter; then
    echo "升级成功: $NEW_VERSION"
else
    echo "升级失败，回滚到 $OLD_VERSION"
    ln -sfn /opt/xdp-dns/$OLD_VERSION /opt/xdp-dns/current
    systemctl restart xdp-dns-filter
    exit 1
fi
```

### 8.5 测试策略

```go
// tests/integration/integration_test.go

func TestEndToEnd(t *testing.T) {
    // 1. 启动服务
    srv := StartTestServer(t)
    defer srv.Stop()

    // 2. 测试允许的域名
    t.Run("AllowedDomain", func(t *testing.T) {
        resp := QueryDNS(t, "allowed.example.com")
        assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
    })

    // 3. 测试阻止的域名
    t.Run("BlockedDomain", func(t *testing.T) {
        resp := QueryDNS(t, "blocked.ads.com")
        assert.Equal(t, dns.RcodeNameError, resp.Rcode)
    })

    // 4. 测试重定向
    t.Run("RedirectedDomain", func(t *testing.T) {
        resp := QueryDNS(t, "redirect.example.com")
        assert.Equal(t, "127.0.0.1", resp.Answer[0].(*dns.A).A.String())
    })

    // 5. 性能测试
    t.Run("Performance", func(t *testing.T) {
        start := time.Now()
        for i := 0; i < 10000; i++ {
            QueryDNS(t, fmt.Sprintf("test%d.example.com", i))
        }
        elapsed := time.Since(start)
        qps := float64(10000) / elapsed.Seconds()
        assert.Greater(t, qps, 10000.0, "QPS 应该超过 10000")
    })
}
```

---

## 附录

### A. 常见问题

**Q: CGO 调用开销如何优化?**

A:
1. 批量处理减少调用次数
2. 使用共享内存传递数据
3. 对于极致性能，考虑纯 C++ 数据面

**Q: 为什么 Go 的 Trie 比 C++ 快?**

A: Go 的内置 map 经过高度优化，使用了更好的哈希算法和内存布局。

**Q: 如何处理超大规则集?**

A:
1. 使用布隆过滤器预过滤
2. 分片规则到多个 Trie
3. 考虑使用数据库后端

### B. 参考资料

- [XDP 官方文档](https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/)
- [eBPF 指南](https://ebpf.io/)
- [Go CGO 最佳实践](https://golang.org/cmd/cgo/)
- [C++ 高性能编程](https://www.agner.org/optimize/)

### C. 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0.0 | 2025-12 | 初始版本，混合架构实现 |
| 0.9.0 | 2025-11 | 纯 Go 版本 |

---

**文档版本**: 1.0
**最后更新**: 2025-12-02
**作者**: XDP DNS Filter Team
```

