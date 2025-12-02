#!/bin/bash
#
# DNS 威胁流量分析系统 - 完整流程测试
#
# 此脚本需要 root 权限运行 XDP 程序
#
# 使用方法:
#   sudo ./test_full_flow.sh [网卡名] [DNS服务器] [测试时长]
#
# 示例:
#   sudo ./test_full_flow.sh eth0 8.8.8.8 10
#

set -e

# 参数
INTERFACE="${1:-eth0}"
DNS_SERVER="${2:-8.8.8.8}"
DURATION="${3:-10}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
QUERY_FILE="${SCRIPT_DIR}/dnsperf_queries.txt"
CONFIG_FILE="${PROJECT_ROOT}/configs/config.yaml"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}清理中...${NC}"
    if [ -n "$XDP_PID" ]; then
        kill $XDP_PID 2>/dev/null || true
        wait $XDP_PID 2>/dev/null || true
    fi
    echo -e "${GREEN}清理完成${NC}"
}

trap cleanup EXIT

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║          DNS 威胁流量分析系统 - 完整流程测试                      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}错误: 需要 root 权限运行 XDP 程序${NC}"
    echo "请使用: sudo $0 $*"
    exit 1
fi

# 检查网卡
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo -e "${RED}错误: 网卡 $INTERFACE 不存在${NC}"
    echo "可用网卡:"
    ip -o link show | awk -F': ' '{print "  " $2}'
    exit 1
fi

# 检查 dnsperf
if ! command -v dnsperf &>/dev/null; then
    echo -e "${RED}错误: dnsperf 未安装${NC}"
    exit 1
fi

# 检查程序是否已编译
if [ ! -f "$PROJECT_ROOT/dns-filter" ]; then
    echo -e "${YELLOW}编译 dns-filter...${NC}"
    cd "$PROJECT_ROOT"
    go build -o dns-filter ./cmd/dns-filter
fi

echo -e "${CYAN}测试配置:${NC}"
echo "  网卡:        $INTERFACE"
echo "  DNS 服务器:  $DNS_SERVER"
echo "  测试时长:    ${DURATION}s"
echo ""

# 创建临时配置
TMP_CONFIG=$(mktemp)
cat > "$TMP_CONFIG" << EOF
interface: $INTERFACE
queue_id: 0
queue_count: 1
rules_path: ${PROJECT_ROOT}/configs/rules.yaml

xdp:
  num_frames: 4096
  frame_size: 2048
  fill_ring_num_descs: 2048
  completion_ring_num_descs: 2048
  rx_ring_num_descs: 2048
  tx_ring_num_descs: 2048

workers:
  num_workers: 4
  batch_size: 32

metrics:
  enabled: true
  listen: ":9090"
  path: "/metrics"
EOF

echo -e "${GREEN}[1/3] 启动 XDP DNS 威胁分析系统...${NC}"
cd "$PROJECT_ROOT"
./dns-filter -config "$TMP_CONFIG" &
XDP_PID=$!

# 等待启动
sleep 3

if ! kill -0 $XDP_PID 2>/dev/null; then
    echo -e "${RED}错误: XDP 程序启动失败${NC}"
    exit 1
fi

echo -e "${GREEN}[2/3] 开始生成 DNS 流量 (${DURATION}s)...${NC}"
echo ""

# 运行 dnsperf
dnsperf \
    -s "$DNS_SERVER" \
    -p 53 \
    -d "$QUERY_FILE" \
    -l "$DURATION" \
    -c 5 \
    -Q 500 \
    -S 1

echo ""
echo -e "${GREEN}[3/3] 获取分析结果...${NC}"
echo ""

# 获取统计
if curl -s http://localhost:9090/stats 2>/dev/null; then
    echo ""
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}测试完成!${NC}"

# 清理临时文件
rm -f "$TMP_CONFIG"

