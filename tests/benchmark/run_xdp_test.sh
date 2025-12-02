#!/bin/bash
#
# XDP DNS 测试 - 使用已编译程序
#

set -e

INTERFACE="${1:-eth0}"
DNS_SERVER="${2:-8.8.8.8}"
DURATION="${3:-10}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}清理中...${NC}"
    if [ -n "$XDP_PID" ]; then
        sudo kill $XDP_PID 2>/dev/null || true
        wait $XDP_PID 2>/dev/null || true
    fi
    echo -e "${GREEN}清理完成${NC}"
}

trap cleanup EXIT INT TERM

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║          XDP DNS 威胁流量分析 - 实际测试                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}错误: 需要 root 权限${NC}"
    echo "请使用: sudo $0 $*"
    exit 1
fi

# 检查程序
if [ ! -f "$PROJECT_ROOT/build/dns-filter" ]; then
    echo -e "${RED}错误: dns-filter 程序不存在${NC}"
    echo "请先编译: make build-go"
    exit 1
fi

# 检查网卡
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo -e "${RED}错误: 网卡 $INTERFACE 不存在${NC}"
    exit 1
fi

# 检查 dnsperf
if ! command -v dnsperf &>/dev/null; then
    echo -e "${RED}错误: dnsperf 未安装${NC}"
    exit 1
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
  fill_ring_size: 2048
  comp_ring_size: 2048
  rx_ring_size: 2048
  tx_ring_size: 2048

workers:
  num_workers: 4
  batch_size: 32

metrics:
  enabled: true
  listen: ":9090"
  path: "/metrics"
EOF

echo -e "${GREEN}[1/3] 启动 XDP DNS 分析系统...${NC}"
echo ""

cd "$PROJECT_ROOT"
sudo ./build/dns-filter -config "$TMP_CONFIG" > /tmp/xdp-dns.log 2>&1 &
XDP_PID=$!

echo "PID: $XDP_PID"
echo "日志: /tmp/xdp-dns.log"
echo ""

# 等待启动
echo "等待系统启动..."
sleep 5

# 检查进程
if ! kill -0 $XDP_PID 2>/dev/null; then
    echo -e "${RED}错误: XDP 程序启动失败${NC}"
    echo ""
    echo "日志内容:"
    cat /tmp/xdp-dns.log
    exit 1
fi

echo -e "${GREEN}✓ 系统已启动${NC}"
echo ""

echo -e "${GREEN}[2/3] 生成 DNS 流量 (${DURATION}s)...${NC}"
echo ""

# 运行 dnsperf
cd "$SCRIPT_DIR"
./run_dnsperf.sh "$DNS_SERVER" "$DURATION" 500 3

echo ""
echo -e "${GREEN}[3/3] 获取统计结果...${NC}"
echo ""

# 等待一下让统计更新
sleep 2

# 获取统计
if curl -s http://localhost:9090/stats 2>/dev/null; then
    echo ""
else
    echo -e "${YELLOW}无法获取统计数据${NC}"
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}测试完成!${NC}"
echo ""
echo "查看详细日志: cat /tmp/xdp-dns.log"

# 清理
rm -f "$TMP_CONFIG"

