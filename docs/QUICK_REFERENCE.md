# XDP DNS Filter 快速参考卡

## 🚀 快速开始

```bash
# 1. 编译 C++ 库
cd cpp/build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)

# 2. 编译 Go 应用
cd ../.. && go build -o dns-filter ./cmd/dns-filter

# 3. 运行
export LD_LIBRARY_PATH=$PWD/cpp/build
./dns-filter --config=configs/config.yaml
```

## 📊 性能指标

| 操作 | C++ | Go | 提升 |
|------|-----|-----|------|
| DNS 解析 | 12ns | 770ns | **64x** |
| NXDOMAIN | 24ns | 1226ns | **51x** |
| A 响应 | 4ns | 2205ns | **550x** |
| Trie 匹配 | 359ns | **160ns** | Go 快 2x |

## 🔧 常用命令

### 测试
```bash
# C++ 测试
./cpp/build/xdp_dns_tests
./cpp/build/xdp_dns_benchmark

# Go 测试
go test ./pkg/...
go test -bench=. ./pkg/dns/hybrid/
```

### 部署
```bash
# 安装服务
sudo ./scripts/deploy.sh

# 管理服务
sudo systemctl start xdp-dns-filter
sudo systemctl status xdp-dns-filter
sudo systemctl stop xdp-dns-filter
```

### 规则热更新
```bash
# 方式1: 信号
sudo kill -HUP $(pidof dns-filter)

# 方式2: API
curl -X POST http://localhost:9090/api/v1/rules/reload
```

## 📝 规则语法

```yaml
rules:
  - id: rule_name         # 规则ID
    priority: 100         # 优先级 (越大越优先)
    enabled: true         # 是否启用
    action: block         # allow | block | redirect | log
    domains:              # 域名列表
      - "*.ads.com"       # 通配符
      - "specific.com"    # 精确匹配
    query_types:          # 查询类型 (可选)
      - A
      - AAAA
    redirect_ip: "1.1.1.1"  # 重定向IP (action=redirect时)
    redirect_ttl: 300       # TTL
```

## 🔍 故障排查

```bash
# 服务状态
systemctl status xdp-dns-filter

# 查看日志
journalctl -u xdp-dns-filter -f

# 检查指标
curl http://localhost:9090/metrics

# 测试DNS
dig @127.0.0.1 test.example.com
```

## 📈 监控指标

| 指标 | 说明 |
|------|------|
| `xdp_dns_packets_total` | 处理的包总数 |
| `xdp_dns_process_latency_nanoseconds` | 处理延迟 |
| `xdp_dns_errors_total` | 错误总数 |
| `xdp_dns_rules_count` | 规则数量 |

## 🏗️ 项目结构

```
xdp-dns/
├── cpp/                    # C++ 高性能数据面
│   ├── include/xdp_dns/   # 头文件
│   ├── src/               # 实现
│   └── tests/             # 测试
├── pkg/
│   ├── dns/cppbridge/     # CGO 绑定
│   ├── dns/hybrid/        # 混合处理器
│   └── filter/            # Go 过滤引擎
├── configs/               # 配置文件
└── docs/                  # 文档
```

## ⚙️ 配置参考

```yaml
# config.yaml
server:
  listen: ":53"
  workers: 8

xdp:
  interface: "eth0"
  queue_id: 0

upstream:
  servers: ["8.8.8.8:53"]
  timeout: 2s

filter:
  rules_path: "/etc/xdp-dns/rules.yaml"

metrics:
  enabled: true
  listen: ":9090"
```

## 🔗 相关链接

- [完整实施方案](IMPLEMENTATION_GUIDE.md)
- [混合架构设计](../HYBRID_ARCHITECTURE.md)
- [性能测试报告](../tests/benchmark/results/BENCHMARK_REPORT.md)
- [GitHub 仓库](https://github.com/gugugu5331/XDP-DNS)

---
*版本: 1.0 | 更新: 2025-12-02*

