# 快速开始 - 多队列 XDP DNS Filter

本文档提供快速开始指南。完整文档见 `docs/MULTI_QUEUE.md`。

## 1️⃣ 检查网卡队列支持

```bash
# 查看网卡队列配置
ethtool -l eth0

# 典型输出:
# Channel parameters for eth0:
# Pre-set maximums:
#   RX:           4
#   TX:           4
#   Combined:     4
# Current hardware settings:
#   RX:           1
#   TX:           1
#   Combined:     1
```

## 2️⃣ 启用多队列

```bash
# 方法 A: 直接使用 ethtool
sudo ethtool -L eth0 combined 4

# 方法 B: 使用 Makefile
sudo make enable-multi-queue INTERFACE=eth0 NUM_QUEUES=4

# 验证
ethtool -l eth0  # 应该显示 4 个队列
```

## 3️⃣ 配置应用

编辑 `configs/config.yaml`，修改以下部分：

```yaml
interface: eth0
queue_start: 0
queue_count: 4          # ← 改为 4 (与网卡配置一致)

workers:
  num_workers: 0           # 自动使用所有 CPU 核
  workers_per_queue: 2     # 每个队列 2 个 worker
  batch_size: 64

response:
  enabled: true            # ← 启用 DNS 响应发送
  block_response: true     # 对威胁查询发送响应
  nxdomain: true           # 返回 NXDOMAIN
```

## 4️⃣ 构建和运行

```bash
# 构建
make build-go

# 运行（需要 root 权限）
sudo ./build/dns-filter -config configs/config.yaml

# 预期输出:
# 2025-12-03 14:30:15 XDP program attached to eth0
# 2025-12-03 14:30:15 Multi-queue XDP sockets created: queues 0-3 (4 total)
# 2025-12-03 14:30:15   Queue 0: socket created and registered (fd=12)
# 2025-12-03 14:30:15   Queue 1: socket created and registered (fd=13)
# 2025-12-03 14:30:15   Queue 2: socket created and registered (fd=14)
# 2025-12-03 14:30:15   Queue 3: socket created and registered (fd=15)
# 2025-12-03 14:30:15 Worker pool started: 8 workers for 4 queues
# 2025-12-03 14:30:15 XDP DNS Filter is running. Press Ctrl+C to stop.
```

## 5️⃣ 验证运行

### 终端 1: 运行过滤器
```bash
sudo ./build/dns-filter -config configs/config.yaml
```

### 终端 2: 发送测试查询
```bash
# 测试 DNS 查询
nslookup example.com <filter_ip>

# 使用 dig 测试
dig @<filter_ip> example.com

# 使用 dnsperf 进行负载测试
dnsperf -s <filter_ip> -c 10 -d queries.txt -l 10 -Q 10000
```

## 6️⃣ 监控和调试

### 查看实时性能指标
```bash
curl http://localhost:9090/metrics | grep dns_filter
```

### 查看队列处理情况
```bash
# 列出所有 Socket FD
lsof -p $(pgrep dns-filter) | grep AF_XDP

# 监控 BPF maps
sudo bpftool map dump name qidconf_map
sudo bpftool map dump name dns_ports_map
```

### 查看日志
```bash
# 实时日志
tail -f logs/dns-filter.log | grep Queue

# 统计每个队列的处理量
grep "Queue [0-3]" logs/dns-filter.log | \
    sed 's/.*Queue \([0-3]\).*/\1/' | sort | uniq -c
```

## 测试模式 (使用虚拟网卡)

如果没有物理网卡支持，可以使用虚拟网卡进行测试：

```bash
# 自动测试 (包含虚拟网卡设置)
sudo make test-multi-queue

# 或手动
sudo ./tests/benchmark/test_multi_queue.sh
```

## 常见问题

### Q: 启用队列失败
```
Error: Operation not supported
```
A: 网卡不支持多队列或驱动不支持，尝试更新驱动或用虚拟网卡测试。

### Q: Socket 注册失败
```
Failed to register socket for queue X
```
A: 检查：
- 队列 ID 是否在有效范围
- 该队列是否已被其他程序使用
- BPF 程序是否正确加载

### Q: 性能不理想
A: 尝试调整：
```yaml
workers:
  workers_per_queue: 4      # 增加 worker 数
  batch_size: 128           # 增加批处理大小

xdp:
  num_frames: 8192          # 增加帧缓冲
  rx_ring_size: 4096        # 增加 RX ring
```

## 性能基准

典型配置下的预期性能：

| 配置 | PPS | 延迟 | CPU 使用 |
|------|-----|------|--------|
| 1 队列 | ~50k | 100μs | 25% |
| 2 队列 | ~100k | 100μs | 50% |
| 4 队列 | ~200k | 100μs | 100% |

## 下一步

- 阅读完整文档: `docs/MULTI_QUEUE.md`
- 调整性能参数 `configs/config.yaml`
- 配置 Prometheus 监控
- 部署到生产环境

---

**需要帮助?**
- 查看 `docs/MULTI_QUEUE.md` 完整文档
- 运行 `make help` 查看所有命令
- 检查 `tests/benchmark/test_multi_queue.sh` 测试脚本

