# 多 RX 队列使用指南

本文档说明如何启用和使用 XDP DNS Filter 的多队列功能。

## 概述

多 RX 队列支持允许 XDP DNS Filter 在多个网卡 RX 队列上并行处理 DNS 流量，显著提升吞吐量和性能。

```
Network Interface
    ├─ Queue 0 → AF_XDP Socket → Worker Pool 1
    ├─ Queue 1 → AF_XDP Socket → Worker Pool 2
    ├─ Queue 2 → AF_XDP Socket → Worker Pool 3
    └─ Queue 3 → AF_XDP Socket → Worker Pool 4
         ↓
    统一 DNS Filter Engine
         ↓
    可选响应发送（TX Ring）
```

## 前提条件

### 硬件要求

- 网卡支持多 RX 队列（大多数现代网卡都支持）
- 足够的 CPU 核心来处理多个 worker 线程

### 软件要求

```bash
# Ubuntu/Debian
sudo apt install ethtool linux-tools-common

# RedHat/CentOS
sudo yum install ethtool linux-tools
```

## 配置步骤

### 1. 检查网卡队列支持

```bash
# 查看网卡队列配置
ethtool -l eth0

# 输出示例:
# Channel parameters for eth0:
# Pre-set maximums:
#   RX:           8
#   TX:           8
#   Other:        0
# Current hardware settings:
#   RX:           1
#   TX:           1
#   Other:        0
```

### 2. 启用多队列

```bash
# 启用 4 个 RX/TX 队列
sudo ethtool -L eth0 combined 4

# 或分别配置
sudo ethtool -L eth0 rx 4
sudo ethtool -L eth0 tx 4

# 验证
ethtool -l eth0
```

使用 Makefile：

```bash
# 启用 4 个队列
sudo make enable-multi-queue INTERFACE=eth0 NUM_QUEUES=4

# 查看配置
make show-queue-config INTERFACE=eth0
```

### 3. 配置 XDP DNS Filter

编辑 `configs/config.yaml`：

```yaml
# 网络接口配置
interface: eth0

# 多队列配置
queue_start: 0      # 起始队列 ID (0 = Queue 0)
queue_count: 4      # 使用的队列数量

# Worker 配置
workers:
  num_workers: 0              # 0 = 使用 CPU 核心数
  workers_per_queue: 2        # 每个队列 2 个 worker
  batch_size: 64

# 响应配置（可选）
response:
  enabled: true
  block_response: true
  nxdomain: true              # 对威胁返回 NXDOMAIN
```

参数说明：

- `queue_start`: 起始队列 ID（通常为 0）
- `queue_count`: 要使用的队列数量
- `workers_per_queue`: 每个队列的 worker 线程数
  - 建议值：2-4（取决于 CPU 核心数）
  - 总 workers = queue_count × workers_per_queue

### 4. 启动服务

```bash
# 构建
make build-go

# 启动
sudo ./build/dns-filter -config configs/config.yaml
```

输出示例：

```
2025-12-03 14:30:15 Starting XDP DNS Filter...
2025-12-03 14:30:15 Using interface: eth0 (index: 2)
2025-12-03 14:30:15 Loading XDP DNS filter program from: bpf/xdp_dns_filter_bpfel.o
2025-12-03 14:30:15 XDP program attached to eth0
2025-12-03 14:30:15 Multi-queue XDP sockets created: queues 0-3 (4 total)
2025-12-03 14:30:15   Queue 0: socket created and registered (fd=12)
2025-12-03 14:30:15   Queue 1: socket created and registered (fd=13)
2025-12-03 14:30:15   Queue 2: socket created and registered (fd=14)
2025-12-03 14:30:15   Queue 3: socket created and registered (fd=15)
2025-12-03 14:30:15 Worker pool started: 8 workers for 4 queues
```

## 性能测试

### 快速测试（使用虚拟网卡）

```bash
# 运行多队列测试（包含环境搭建）
sudo make test-multi-queue

# 或手动运行
sudo ./tests/benchmark/test_multi_queue.sh
```

### 完整性能测试

```bash
# 生成 DNS 流量进行性能测试
dnsperf -s <DNS_SERVER> -c <NUM_CLIENTS> -d <QUERY_FILE> -l <DURATION>

# 示例：向本地 Filter 发送 DNS 查询
dnsperf -s 127.0.0.1 -c 10 -d queries.txt -l 60 -Q 10000
```

### 监控性能指标

```bash
# 查看实时指标（需要启用 Metrics）
curl http://localhost:9090/metrics

# 使用 Prometheus 采集
# 配置 prometheus.yml:
# global:
#   scrape_interval: 15s
# scrape_configs:
#   - job_name: 'xdp-dns-filter'
#     static_configs:
#       - targets: ['localhost:9090']
```

## 响应发送功能

### 启用 DNS 响应

配置中启用响应发送：

```yaml
response:
  enabled: true           # 启用响应发送
  block_response: true    # 对阻止的查询发送响应
  nxdomain: true          # 返回 NXDOMAIN (true) 或 REFUSED (false)
```

### 工作原理

1. **接收阶段**：从 RX Ring 接收 DNS 查询
2. **处理阶段**：
   - 解析 DNS 消息
   - 执行过滤规则检查
3. **响应阶段**（可选）：
   - 对威胁查询：构建 NXDOMAIN/REFUSED 响应
   - 通过 TX Ring 发送回客户端

### 自定义响应处理

在代码中使用自定义响应处理器：

```go
workerPool := worker.NewPool(worker.PoolOptions{
    // ... 其他选项
    ResponseHandler: func(query *dns.Message, action filter.Action, 
        rule *filter.Rule, pktInfo *worker.PacketInfo) ([]byte, bool) {
        
        if action == filter.ActionBlock {
            // 自定义阻止响应逻辑
            if rule.ID == "malware" {
                return buildSinkholeResponse(query), true
            }
        }
        
        return nil, false // 不发送响应
    },
})
```

## 故障排除

### 问题：网卡不支持多队列

```
Error: Operation not supported
```

解决方案：
- 更新网卡驱动
- 检查网卡是否支持多队列：`ethtool -l <interface>`

### 问题：权限不足

```
Error: Operation not permitted
```

解决方案：
```bash
# 使用 sudo 运行
sudo ./build/dns-filter -config configs/config.yaml

# 或配置 CAP_SYS_ADMIN 权限
sudo setcap cap_sys_admin,cap_sys_resource,cap_ipc_lock,cap_net_admin+ep \
    ./build/dns-filter
```

### 问题：Socket 注册失败

```
Failed to register socket for queue X
```

原因可能：
- 队列 ID 超出范围
- BPF 程序中的 map 大小不足
- 队列已被其他程序使用

解决方案：
- 检查队列配置：`ethtool -l <interface>`
- 查看 BPF map 大小：`sudo bpftool map`
- 关闭其他使用 AF_XDP 的程序

### 问题：性能不理想

尝试：
1. 增加 worker 数量：`workers_per_queue: 4`
2. 增加 batch 大小：`batch_size: 128`
3. 启用 CPU 亲和性（可选）
4. 检查网卡 RSS 配置

## 性能调优建议

### 内存配置

```yaml
xdp:
  num_frames: 8192        # 增加帧数
  frame_size: 2048        # 大帧尺寸
  fill_ring_size: 4096
  rx_ring_size: 4096
  tx_ring_size: 4096
```

### Worker 配置

```yaml
workers:
  num_workers: 0              # 使用所有 CPU 核心
  workers_per_queue: 2        # 根据 CPU 数量调整
  batch_size: 128             # 更大的批处理
```

### RSS 配置（可选）

```bash
# 启用接收端缩放
ethtool -X eth0 rxfh-indir equal 4

# 设置 RPS（软件包转向）
echo f > /sys/class/net/eth0/queues/rx-0/rps_cpus
```

## 监控和日志

### 查看队列状态

```bash
# 检查 BPF maps
sudo bpftool map dump name qidconf_map

# 输出示例:
# [{
#   "key": 0,
#   "value": 1      # Queue 0 已启用
# },{
#   "key": 1,
#   "value": 1      # Queue 1 已启用
# }]

# 检查 Socket 文件描述符
lsof -p $(pgrep dns-filter) | grep AF_XDP
```

### 实时日志

```bash
# 跟踪所有队列活动
tail -f logs/dns-filter.log | grep Queue

# 统计每队列处理量
grep "Queue [0-3]" logs/dns-filter.log | \
    sed 's/.*Queue \([0-3]\).*/\1/' | sort | uniq -c
```

## 相关资源

- [AF_XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [ethtool Documentation](https://man7.org/linux/man-pages/man8/ethtool.8.html)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)

