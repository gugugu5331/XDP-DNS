# XDP DNS 威胁分析系统 - 使用 XDP 测试指南

## 测试架构

```
┌────────────────────────────────────────────────────────────────┐
│                        测试流程                                 │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  dnsperf 生成 DNS 流量                                          │
│       │                                                        │
│       ├──▶ 向 8.8.8.8:53 发送查询                              │
│       │                                                        │
│       ▼                                                        │
│  网卡 (eth0) ◀── XDP 程序拦截                                  │
│       │                                                        │
│       ├──▶ 检测 UDP 53 端口                                    │
│       │                                                        │
│       ▼                                                        │
│  bpf_redirect_map()                                            │
│       │                                                        │
│       ▼                                                        │
│  AF_XDP Socket (零拷贝)                                         │
│       │                                                        │
│       ▼                                                        │
│  用户态程序 (dns-filter)                                        │
│       │                                                        │
│       ├──▶ 解析 DNS 数据包                                     │
│       ├──▶ 匹配威胁规则                                        │
│       └──▶ 统计 (allowed/blocked/logged)                      │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## 前置条件

### 1. 系统要求
- Linux 内核 5.4+（推荐 5.10+）
- root 权限
- 支持 XDP 的网卡驱动

### 2. 检查内核支持
```bash
# 检查内核版本
uname -r

# 检查 XDP 支持
sudo dmesg | grep -i xdp

# 检查网卡驱动是否支持 XDP
ethtool -i eth0 | grep driver
```

### 3. 安装依赖
```bash
# 安装 dnsperf
sudo apt-get install dnsperf

# 安装 BPF 工具
sudo apt-get install clang llvm libbpf-dev

# 检查 ulimit（XDP 需要锁定内存）
ulimit -l
# 如果太小，临时增加
sudo ulimit -l unlimited
```

## 编译系统

### 1. 编译 BPF 程序
```bash
cd xdp-dns
make build-bpf
# 或
cd bpf && make
```

### 2. 编译 Go 程序
```bash
cd xdp-dns
go build -o dns-filter ./cmd/dns-filter
```

## 测试步骤

### 方式 1: 使用自动化脚本（推荐）

```bash
# 完整流程测试（需要 root）
sudo ./tests/benchmark/test_full_flow.sh eth0 8.8.8.8 30

# 说明:
# - eth0: 要监听的网卡
# - 8.8.8.8: DNS 服务器
# - 30: 测试时长（秒）
```

### 方式 2: 手动测试

#### 步骤 1: 启动 XDP DNS 分析系统

终端 1:
```bash
# 编辑配置文件，设置正确的网卡
vim configs/config.yaml

# 启动系统（需要 root）
sudo ./dns-filter -config configs/config.yaml
```

预期输出:
```
Starting XDP DNS Filter...
Using interface: eth0 (index: 2)
XDP program attached to eth0
XDP socket created and registered
Filter engine initialized with 6 rules
Worker pool started with 4 workers
Metrics server started on :9090/metrics
XDP DNS Filter is running. Press Ctrl+C to stop.
```

#### 步骤 2: 生成 DNS 流量

终端 2:
```bash
cd tests/benchmark

# 运行 dnsperf 生成流量
./run_dnsperf.sh 8.8.8.8 10 1000 5

# 参数说明:
# - 8.8.8.8: 目标 DNS 服务器
# - 10: 持续时间（秒）
# - 1000: 目标 QPS
# - 5: 并发客户端数
```

#### 步骤 3: 查看检测结果

终端 3:
```bash
# 查看统计数据
curl http://localhost:9090/stats

# 查看 Prometheus 指标
curl http://localhost:9090/metrics | grep xdp_dns
```

预期输出:
```json
{
  "received": 5000,
  "allowed": 3400,
  "blocked": 1200,
  "logged": 400,
  "dropped": 0
}
```

## 验证 XDP 工作

### 1. 检查 XDP 程序是否加载
```bash
# 查看 XDP 程序
sudo ip link show eth0

# 应该看到类似：
# xdp/id:123 ...
```

### 2. 使用 bpftool 检查
```bash
# 列出加载的 BPF 程序
sudo bpftool prog list | grep xdp

# 查看 BPF map
sudo bpftool map list
```

### 3. 查看 XDP 统计
```bash
# 查看网卡统计
sudo ethtool -S eth0 | grep xdp
```

## 性能测试

### 基准测试
```bash
# 低负载测试
./run_dnsperf.sh 8.8.8.8 10 500 2

# 中等负载
./run_dnsperf.sh 8.8.8.8 30 5000 5

# 高负载（压力测试）
./run_dnsperf.sh 8.8.8.8 60 50000 10
```

### 预期性能指标
- **吞吐量**: ~1-5M PPS（单核）
- **延迟**: 解析 + 检测 < 1us
- **CPU 使用**: 取决于流量

## 故障排查

### XDP 程序无法加载
```bash
# 检查内核消息
sudo dmesg | tail -50

# 常见问题:
# 1. 内核版本不支持
# 2. 网卡驱动不支持 XDP
# 3. 内存锁定限制
```

### 无流量捕获
```bash
# 检查 XDP 程序是否附加
sudo ip link show eth0

# 检查防火墙
sudo iptables -L

# 使用 tcpdump 验证流量
sudo tcpdump -i eth0 udp port 53 -c 10
```

### 性能不佳
```bash
# 检查 CPU 亲和性
# 增加 worker 数量
# 调整 UMEM 大小

# 检查丢包
curl http://localhost:9090/stats
```

