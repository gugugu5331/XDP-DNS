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
YELLOW='\033[1;33m'
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
echo -e "${BLUE}║         XDP DNS 响应功能测试                                   ║${NC}"
echo -e "${BLUE}║         mode: all - 所有请求都会收到响应                        ║${NC}"
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

# 创建配置文件 - 使用 mode: "all" 模式
echo -e "${BLUE}[2/5] 创建配置文件 (mode: all)...${NC}"
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
  mode: "all"
  block_response: true
  nxdomain: true
metrics:
  enabled: true
  listen: ":9096"
  path: "/metrics"
EOF
echo -e "  ${GREEN}✓${NC} 配置文件已创建 (mode: all - 所有请求都响应)"

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

# 测试 1: 使用 dig 查询正常域名
echo "  测试 1: dig 查询正常域名 (example.com)..."
result=$(timeout 5 ip netns exec ns_test dig @10.99.0.1 example.com +tries=1 +time=2 2>&1 || echo "TIMEOUT")
if echo "$result" | grep -q "NOERROR"; then
    echo -e "    ${GREEN}✓${NC} dig: 收到 NOERROR 响应!"
    echo "$result" | grep -E "status:|SERVER:" | head -2 | sed 's/^/      /'
elif echo "$result" | grep -q "TIMEOUT\|timed out"; then
    echo -e "    ${RED}✗${NC} dig: 超时无响应"
else
    echo -e "    ${YELLOW}⚠${NC} dig: 响应异常"
    echo "$result" | grep "status:" | sed 's/^/      /'
fi

# 测试 2: 使用 nslookup 查询正常域名
echo ""
echo "  测试 2: nslookup 查询正常域名 (google.com)..."
result=$(timeout 5 ip netns exec ns_test nslookup -timeout=2 google.com 10.99.0.1 2>&1 || echo "TIMEOUT")
if echo "$result" | grep -q "timed out\|TIMEOUT"; then
    echo -e "    ${RED}✗${NC} nslookup: 超时无响应"
else
    echo -e "    ${GREEN}✓${NC} nslookup: 收到响应!"
    echo "$result" | head -4 | sed 's/^/      /'
fi

# 测试 3: 查询恶意域名 (应该返回 NXDOMAIN)
echo ""
echo "  测试 3: 查询恶意域名 (test.malware.com)..."
result=$(timeout 5 ip netns exec ns_test dig @10.99.0.1 test.malware.com +tries=1 +time=2 2>&1 || echo "TIMEOUT")
if echo "$result" | grep -qi "NXDOMAIN"; then
    echo -e "    ${GREEN}✓${NC} 恶意域名: 收到 NXDOMAIN 响应!"
elif echo "$result" | grep -q "TIMEOUT\|timed out"; then
    echo -e "    ${RED}✗${NC} 恶意域名: 超时无响应"
else
    echo -e "    ${YELLOW}⚠${NC} 恶意域名: 响应状态未知"
    echo "$result" | grep "status:" | sed 's/^/      /'
fi

# 测试 4: 批量查询测试
echo ""
echo "  测试 4: 批量查询测试 (10个请求)..."
success=0
for i in $(seq 1 10); do
    result=$(timeout 2 ip netns exec ns_test dig @10.99.0.1 test$i.example.com +tries=1 +time=1 +short 2>&1)
    if [ $? -eq 0 ]; then
        ((success++))
    fi
done
echo -e "    成功响应: ${success}/10"
if [ $success -ge 8 ]; then
    echo -e "    ${GREEN}✓${NC} 批量测试通过!"
else
    echo -e "    ${RED}✗${NC} 批量测试失败"
fi

# 检查日志
echo ""
echo -e "${BLUE}[5/5] 检查处理日志...${NC}"
sleep 1

echo "  已处理的请求数:"
grep -c "SUSPICIOUS\|THREAT\|Allowed" "$LOG_DIR/dns-filter.log" 2>/dev/null | sed 's/^/    /' || echo "    0"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  📁 完整日志: $LOG_DIR/dns-filter.log"
echo ""
echo "  💡 响应模式说明:"
echo "     - mode: block_only  仅对被阻止的域名返回 NXDOMAIN"
echo "     - mode: all         对所有请求返回响应 (用于 dnsperf 测试)"
echo ""
echo "  🧪 dnsperf 测试示例:"
echo "     # 创建查询文件"
echo "     echo 'example.com A' > /tmp/queries.txt"
echo "     # 运行性能测试"
echo "     ip netns exec ns_test dnsperf -s 10.99.0.1 -d /tmp/queries.txt -l 10"
echo ""

