#!/bin/bash
#
# XDP DNS 威胁分析系统 - 演示测试
#
# 此脚本演示系统的完整功能，无需 root 权限
# 使用模拟数据测试威胁检测逻辑
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

clear

echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        XDP DNS 威胁流量分析系统 - 功能演示                        ║
║                                                                  ║
║        基于 XDP + AF_XDP 的高性能 DNS 威胁检测                    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""

echo -e "${CYAN}系统架构:${NC}"
echo ""
echo "  ┌─────────────┐      XDP 程序       ┌─────────────┐"
echo "  │   网卡 NIC  │ ────────────────▶  │ DNS 端口检测 │"
echo "  └─────────────┘      UDP 53        └──────┬──────┘"
echo "                                             │"
echo "                                 bpf_redirect_map()"
echo "                                             │"
echo "                                             ▼"
echo "  ┌─────────────┐    零拷贝读取      ┌─────────────┐"
echo "  │  AF_XDP     │ ◀────────────────  │ 共享内存    │"
echo "  │  Socket     │                    │   UMEM      │"
echo "  └──────┬──────┘                    └─────────────┘"
echo "         │"
echo "         ▼"
echo "  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐"
echo "  │ DNS 解析器  │───▶│ 威胁检测器   │───▶│ 统计输出    │"
echo "  └─────────────┘    └─────────────┘    └─────────────┘"
echo ""
sleep 2

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}步骤 1: 加载威胁检测规则${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "规则文件: configs/rules.yaml"
echo ""
grep -E "^  - id:|^    action:|^    description:" "$PROJECT_ROOT/configs/rules.yaml" | \
    sed 's/  - id:/\n  规则ID:/; s/action:/动作:/; s/description:/说明:/' | head -20
echo ""
sleep 2

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}步骤 2: 准备测试查询数据${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

QUERY_FILE="$SCRIPT_DIR/dnsperf_queries.txt"
TOTAL_QUERIES=$(grep -v '^#' "$QUERY_FILE" | grep -v '^$' | wc -l)

echo "查询文件: $QUERY_FILE"
echo "总查询数: $TOTAL_QUERIES"
echo ""
echo "查询示例:"
head -10 "$QUERY_FILE" | awk '{printf "  %s\n", $0}'
echo "  ..."
echo ""
sleep 2

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}步骤 3: 执行威胁检测测试${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

cd "$SCRIPT_DIR"
go test -v -run TestThreatDetection 2>&1 | grep -A 100 "DNS 威胁检测测试"

echo ""
sleep 1

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}步骤 4: 性能基准测试${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "运行基准测试..."
echo ""

go test -bench=BenchmarkThreatDetectionDnsperf -benchtime=3s 2>&1 | tail -5

echo ""
sleep 1

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}演示完成!${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${CYAN}实际 XDP 测试:${NC}"
echo ""
echo "在真实环境中运行 XDP 测试（需要 root 权限）:"
echo ""
echo -e "  ${GREEN}1. 检查 XDP 支持:${NC}"
echo "     sudo make test-xdp-setup"
echo ""
echo -e "  ${GREEN}2. 快速测试 (10秒):${NC}"
echo "     sudo make test-xdp-quick INTERFACE=eth0"
echo ""
echo -e "  ${GREEN}3. 完整测试 (30秒):${NC}"
echo "     sudo make test-xdp-full INTERFACE=eth0"
echo ""
echo -e "  ${GREEN}4. 手动测试:${NC}"
echo "     # 终端 1: 启动系统"
echo "     sudo ./build/dns-filter -config configs/config.yaml"
echo ""
echo "     # 终端 2: 生成流量"
echo "     ./tests/benchmark/run_dnsperf.sh 8.8.8.8 30 1000 5"
echo ""
echo "     # 终端 3: 查看结果"
echo "     curl http://localhost:9090/stats"
echo ""

echo -e "${CYAN}相关文档:${NC}"
echo "  - QUICKSTART_XDP_TEST.md   - 快速开始指南"
echo "  - docs/XDP_TESTING_GUIDE.md - 详细测试指南"
echo ""

