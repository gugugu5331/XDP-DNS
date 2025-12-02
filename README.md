# XDP DNS Filter

高性能 DNS 流量过滤系统，基于 XDP (eXpress Data Path) 和 AF_XDP Socket 技术实现。

## 特性

- **超低延迟**: 在网卡驱动层处理数据包，绕过内核网络栈
- **零拷贝**: 使用 AF_XDP Socket 实现用户态零拷贝数据包处理
- **高吞吐**: 支持百万级 PPS 的 DNS 查询处理能力
- **灵活过滤**: 支持基于域名、IP、查询类型的动态过滤规则
- **Prometheus 监控**: 内置指标导出，支持 Grafana 可视化

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Space (Go)                              │
│  ┌───────────┐  ┌────────────┐  ┌───────────┐  ┌────────────┐   │
│  │ Config    │  │ DNS Parser │  │ Filter    │  │ Metrics    │   │
│  │ Manager   │  │            │  │ Engine    │  │ Collector  │   │
│  └───────────┘  └────────────┘  └───────────┘  └────────────┘   │
│                              │                                   │
│  ┌───────────────────────────▼─────────────────────────────────┐│
│  │                  AF_XDP Socket (Zero-Copy)                  ││
│  │    Fill Ring │ Completion Ring │ RX Ring │ TX Ring          ││
│  └─────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
                               │
                       ┌───────▼───────┐
                       │   eBPF Maps   │
                       └───────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                   Kernel Space (XDP/eBPF)                        │
│     Parse ETH → Parse IP → Parse UDP → Check DNS → Redirect     │
└──────────────────────────────────────────────────────────────────┘
```

## 快速开始

### 环境要求

- Linux 内核 5.4+ (推荐 5.10+)
- Go 1.21+
- Clang/LLVM (可选，用于编译 BPF 程序)
- 支持 XDP 的网卡驱动

### 构建

```bash
# 克隆项目
git clone <repository-url>
cd xdp-dns

# 构建
make build

# 或仅构建 Go 程序
make build-go
```

### 配置

编辑 `configs/config.yaml`:

```yaml
interface: eth0      # 网络接口
queue_id: 0         # 队列 ID

xdp:
  num_frames: 4096   # UMEM 帧数量
  frame_size: 2048   # 帧大小

workers:
  num_workers: 8     # Worker 数量

dns:
  listen_ports:
    - 53

metrics:
  enabled: true
  listen: ":9090"
```

编辑过滤规则 `configs/rules.yaml`:

```yaml
rules:
  - id: block-ads
    priority: 100
    enabled: true
    action: block
    domains:
      - "*.ads.com"
      - "*.doubleclick.net"
```

### 运行

```bash
# 开发模式运行
sudo make run

# 或直接运行
sudo ./build/dns-filter -config configs/config.yaml
```

### 安装为系统服务

```bash
sudo make install

# 启动服务
sudo systemctl start xdp-dns-filter

# 查看日志
sudo journalctl -u xdp-dns-filter -f
```

## 项目结构

```
xdp-dns/
├── cmd/dns-filter/      # 主程序入口
├── pkg/
│   ├── dns/             # DNS 协议解析
│   ├── filter/          # 过滤引擎
│   ├── config/          # 配置管理
│   └── metrics/         # 指标收集
├── internal/worker/     # Worker 处理池
├── bpf/                 # eBPF/XDP 程序
├── xdp/                 # XDP Socket 封装
├── configs/             # 配置文件
└── scripts/             # 构建脚本
```

## 监控

访问 `http://localhost:9090/metrics` 获取 Prometheus 指标。

主要指标:
- `xdp_dns_packets_received_total` - 接收的 DNS 包总数
- `xdp_dns_packets_blocked_total` - 阻止的 DNS 包总数
- `xdp_dns_packets_allowed_total` - 允许的 DNS 包总数

## 开发

```bash
# 运行测试
make test

# 运行基准测试
make bench

# 代码格式化
make fmt
```

## License

MIT License

