# XDP DNS 威胁分析系统 - 快速测试指南

## 🚀 5 分钟快速测试

### 步骤 1: 检查系统支持

```bash
sudo make test-xdp-setup
```

**预期输出:**
```
╔══════════════════════════════════════════════════════════════╗
║              XDP 支持情况检查                                 ║
╚══════════════════════════════════════════════════════════════╝

系统检查:
[1] 内核版本 >= 5.4 ... ✓
[2] Root 权限 ... ✓
[3] BPF 文件系统 ... ✓

工具检查:
[4] clang 编译器 ... ✓
[5] LLVM 工具链 ... ✓
[6] bpftool ... ✓
[7] dnsperf ... ✓

✓ 所有检查通过 (7/7)
```

如果检查失败，根据提示安装缺失的依赖。

---

### 步骤 2: 编译系统

```bash
# 编译 BPF 程序和 Go 应用
make build

# 或分别编译
make build-bpf   # 编译 XDP 程序
make build-go    # 编译用户态程序
```

**验证编译结果:**
```bash
ls -lh build/dns-filter     # Go 程序
ls -lh bpf/xdp_dns_filter.o # XDP BPF 对象
```

---

### 步骤 3: 配置网卡

**检查可用网卡:**
```bash
ip link show
```

**编辑配置文件:**
```bash
vim configs/config.yaml
```

修改 `interface` 为你的网卡名称（如 eth0, ens33, wlp2s0）:
```yaml
interface: eth0  # 改为你的网卡
queue_id: 0
```

---

### 步骤 4: 运行快速测试（10秒）

```bash
sudo make test-xdp-quick
```

这个命令会：
1. 启动 XDP DNS 分析系统
2. 使用 dnsperf 生成 10 秒的 DNS 流量
3. 显示检测结果

**预期输出:**
```
╔══════════════════════════════════════════════════════════════════╗
║          DNS 威胁流量分析系统 - 完整流程测试                      ║
╚══════════════════════════════════════════════════════════════════╝

[1/3] 启动 XDP DNS 威胁分析系统...
XDP program attached to eth0
Filter engine initialized with 6 rules
Worker pool started with 4 workers

[2/3] 开始生成 DNS 流量 (10s)...
DNS Performance Testing Tool
Queries sent:         5000
Queries completed:    5000 (100.00%)
QPS:                  500.0

[3/3] 获取分析结果...
{
  "received": 5000,
  "allowed": 3400,    // 正常域名
  "blocked": 1200,    // 威胁域名
  "logged": 400,      // 可疑查询
  "dropped": 0
}

✓ 测试完成!
```

---

## 🔍 详细测试

### 运行完整测试（30秒）

```bash
sudo make test-xdp-full INTERFACE=eth0
```

### 手动测试（两个终端）

**终端 1 - 启动系统:**
```bash
sudo ./build/dns-filter -config configs/config.yaml
```

**终端 2 - 生成流量:**
```bash
cd tests/benchmark
./run_dnsperf.sh 8.8.8.8 30 1000 5
```

**终端 3 - 查看统计:**
```bash
# 实时查看
watch -n 1 curl -s http://localhost:9090/stats

# 查看 Prometheus 指标
curl http://localhost:9090/metrics | grep xdp_dns
```

---

## 📊 验证 XDP 工作

### 1. 检查 XDP 程序是否加载

```bash
# 查看 XDP 程序
sudo ip link show eth0 | grep xdp

# 应该看到类似：
# xdp/id:123 xdpgeneric/id:124
```

### 2. 使用 bpftool 验证

```bash
# 列出 BPF 程序
sudo bpftool prog list | grep xdp

# 查看 BPF maps
sudo bpftool map list

# 查看具体 map 内容
sudo bpftool map dump name xsks_map
```

### 3. 查看网卡统计

```bash
# XDP 统计
sudo ethtool -S eth0 | grep xdp

# 接收数据包
sudo ethtool -S eth0 | grep rx_packets
```

---

## 🎯 测试不同流量类型

### 测试 1: 正常域名（应该放行）
```bash
dig @8.8.8.8 www.google.com
dig @8.8.8.8 www.github.com
```

### 测试 2: 威胁域名（应该阻止）
```bash
dig @8.8.8.8 c2.malware.com
dig @8.8.8.8 bot.botnet.net
```

### 测试 3: 可疑查询（应该记录）
```bash
dig @8.8.8.8 tunnel.example.com TXT
dig @8.8.8.8 host.dyndns.org
```

---

## 🛠️ 故障排查

### XDP 无法加载

```bash
# 检查内核日志
sudo dmesg | grep -i xdp

# 检查网卡是否支持 XDP
ethtool -i eth0

# 尝试 generic 模式
# 在 xdp/program.go 中修改 xdp.DefaultXdpFlags
```

### 看不到流量

```bash
# 验证流量确实经过网卡
sudo tcpdump -i eth0 udp port 53 -c 10

# 检查防火墙
sudo iptables -L -n -v

# 检查 XDP 统计
curl http://localhost:9090/stats
```

### 性能问题

```bash
# 增加 worker 数量（configs/config.yaml）
workers:
  num_workers: 8

# 增加 UMEM 大小
xdp:
  num_frames: 8192
```

---

## 📈 性能基准测试

### 低负载测试
```bash
./tests/benchmark/run_dnsperf.sh 8.8.8.8 10 500 2
```

### 中等负载
```bash
./tests/benchmark/run_dnsperf.sh 8.8.8.8 30 5000 5
```

### 高负载压测
```bash
./tests/benchmark/run_dnsperf.sh 8.8.8.8 60 50000 10
```

---

## 🔗 更多资源

- [完整测试指南](docs/XDP_TESTING_GUIDE.md)
- [架构文档](docs/ARCHITECTURE_DIAGRAMS.md)
- [实现指南](docs/IMPLEMENTATION_GUIDE.md)

