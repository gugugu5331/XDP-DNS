#!/bin/bash
# 测试 XDP DNS Filter 的响应功能

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="/tmp/xdp-response-test"
LOG_DIR="$TEST_DIR"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

cleanup() {
    echo "清理..."
    pkill -f "dns-filter.*config" 2>/dev/null || true
    sleep 1
    ip link del veth_xdp 2>/dev/null || true
    ip netns del ns_test 2>/dev/null || true
}

trap cleanup EXIT

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         XDP DNS 响应测试                                       ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 创建测试环境
echo -e "${BLUE}[1/5] 创建测试网络环境...${NC}"
mkdir -p "$LOG_DIR"
cleanup 2>/dev/null || true

ip netns add ns_test
ip link add veth_xdp type veth peer name veth_send
ip link set veth_send netns ns_test
ip link set veth_xdp up
ip addr add 10.99.0.1/24 dev veth_xdp

ip netns exec ns_test ip link set lo up
ip netns exec ns_test ip link set veth_send up
ip netns exec ns_test ip addr add 10.99.0.2/24 dev veth_send

# 配置 ARP
echo 1 > /proc/sys/net/ipv4/conf/veth_xdp/proxy_arp
MAC=$(ip link show veth_xdp | grep ether | awk '{print $2}')
ip netns exec ns_test ip neigh replace 10.99.0.1 lladdr $MAC dev veth_send nud permanent
echo -e "  ${GREEN}✓${NC} 网络环境就绪"

# 创建配置文件（启用响应）
echo -e "${BLUE}[2/5] 创建配置文件（启用响应）...${NC}"
cat > "$LOG_DIR/config.yaml" << EOF
interface: veth_xdp
queue_start: 0
queue_count: 1
bpf_path: ${PROJECT_ROOT}/bpf/xdp_dns_filter_bpfel.o
rules_path: ${PROJECT_ROOT}/configs/rules.yaml
xdp:
  num_frames: 4096
  frame_size: 2048
  fill_ring_size: 2048
  comp_ring_size: 2048
  rx_ring_size: 2048
  tx_ring_size: 2048
workers:
  num_workers: 2
  workers_per_queue: 2
  batch_size: 32
dns:
  listen_ports:
    - 53
response:
  enabled: true
  block_response: true
  nxdomain: true
  echo_mode: true
metrics:
  enabled: true
  listen: ":9096"
  path: "/metrics"
EOF
echo -e "  ${GREEN}✓${NC} 配置文件已创建（响应已启用）"

# 启动 DNS Filter
echo -e "${BLUE}[3/5] 启动 XDP DNS Filter...${NC}"
"$PROJECT_ROOT/build/dns-filter" -config "$LOG_DIR/config.yaml" > "$LOG_DIR/dns-filter.log" 2>&1 &
FILTER_PID=$!
sleep 3

if ! ps -p $FILTER_PID > /dev/null 2>&1; then
    echo -e "  ${RED}✗${NC} 进程启动失败"
    cat "$LOG_DIR/dns-filter.log"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} 进程启动 (PID: $FILTER_PID)"

# 测试 DNS 查询响应
echo -e "${BLUE}[4/5] 测试 DNS 查询响应...${NC}"
echo ""

# 测试 1: 使用 dig（如果可用）
if command -v dig &> /dev/null; then
    echo "  测试 1: 使用 dig 发送查询..."
    result=$(timeout 5 ip netns exec ns_test dig @10.99.0.1 example.com +short +tries=1 +time=2 2>&1 || echo "TIMEOUT")
    if [ "$result" = "TIMEOUT" ] || [ -z "$result" ]; then
        echo -e "    ${RED}✗${NC} dig 未收到响应 (超时)"
    else
        echo -e "    ${GREEN}✓${NC} dig 收到响应: $result"
    fi
else
    echo "  dig 未安装，跳过测试 1"
fi

# 测试 2: 使用 nslookup
echo ""
echo "  测试 2: 使用 nslookup 发送查询..."
result=$(timeout 5 ip netns exec ns_test nslookup -timeout=2 example.com 10.99.0.1 2>&1 || echo "TIMEOUT")
if echo "$result" | grep -q "TIMEOUT\|timed out\|connection timed out"; then
    echo -e "    ${RED}✗${NC} nslookup 未收到响应 (超时)"
    echo "    调试信息: $result"
else
    echo -e "    ${GREEN}✓${NC} nslookup 收到响应"
    echo "$result" | head -5 | sed 's/^/    /'
fi

# 测试 3: 使用 nc 发送原始 DNS 查询
echo ""
echo "  测试 3: 使用 nc 发送原始 DNS 查询..."
# DNS 查询 example.com A (简化版)
DNS_QUERY=$(echo -e '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01')
result=$(echo -n "$DNS_QUERY" | timeout 3 ip netns exec ns_test nc -u -w 2 10.99.0.1 53 | xxd 2>&1 || echo "TIMEOUT")
if [ "$result" = "TIMEOUT" ] || [ -z "$result" ]; then
    echo -e "    ${RED}✗${NC} nc 未收到响应"
else
    echo -e "    ${GREEN}✓${NC} nc 收到响应:"
    echo "$result" | head -3 | sed 's/^/    /'
fi

# 检查日志
echo ""
echo -e "${BLUE}[5/5] 检查处理日志...${NC}"
sleep 1

echo "  最近日志:"
tail -20 "$LOG_DIR/dns-filter.log" | grep -E "received|SUSPICIOUS|THREAT|Response|Queue" | tail -10 | sed 's/^/    /'

# 统计
echo ""
if curl -s "http://localhost:9096/metrics" > /dev/null 2>&1; then
    stats=$(curl -s "http://localhost:9096/metrics" | grep -E "dns_filter_(received|blocked|allowed)" | head -5)
    echo "  Metrics:"
    echo "$stats" | sed 's/^/    /'
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo "  完整日志: $LOG_DIR/dns-filter.log"
echo ""
echo "  手动测试命令:"
echo "    ip netns exec ns_test dig @10.99.0.1 example.com"
echo "    ip netns exec ns_test nslookup example.com 10.99.0.1"
echo ""

