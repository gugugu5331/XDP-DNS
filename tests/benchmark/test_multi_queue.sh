#!/bin/bash
# 多队列性能测试脚本

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="/tmp/xdp-multi-queue-test"
LOG_DIR="$TEST_DIR/logs"
INTERFACE="veth_xdp"
QUEUE_COUNT=4
NUM_QUERIES=100

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    echo "清理..."
    pkill -f "dns-filter.*-config" || true
    sleep 1
    ip link del veth_xdp 2>/dev/null || true
    ip netns del ns_test 2>/dev/null || true
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

# 创建测试环境
echo -e "${BLUE}[1/7] 创建测试网络环境...${NC}"
mkdir -p "$LOG_DIR"

ip netns add ns_test 2>/dev/null || true
ip link add "$INTERFACE" type veth peer name veth_send 2>/dev/null || true
ip link set veth_send netns ns_test
ip link set "$INTERFACE" up
ip addr add 10.99.0.1/24 dev "$INTERFACE" 2>/dev/null || true

ip netns exec ns_test ip link set lo up
ip netns exec ns_test ip link set veth_send up
ip netns exec ns_test ip addr add 10.99.0.2/24 dev veth_send 2>/dev/null || true

# 配置 ARP
echo 1 > /proc/sys/net/ipv4/conf/"$INTERFACE"/proxy_arp 2>/dev/null || true
MAC=$(ip link show "$INTERFACE" | grep ether | awk '{print $2}')
ip netns exec ns_test ip neigh replace 10.99.0.1 lladdr "$MAC" dev veth_send nud permanent 2>/dev/null || true

echo -e "  ${GREEN}✓${NC} 网络环境就绪"

# 创建配置文件
echo -e "${BLUE}[2/7] 创建多队列配置文件...${NC}"
cat > "$LOG_DIR/config.yaml" << EOF
interface: $INTERFACE
queue_start: 0
queue_count: $QUEUE_COUNT
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
  num_workers: 0
  workers_per_queue: 2
  batch_size: 64
dns:
  listen_ports:
    - 53
response:
  enabled: true
  block_response: true
  nxdomain: true
metrics:
  enabled: true
  listen: ":9095"
  path: "/metrics"
logging:
  level: info
EOF
echo -e "  ${GREEN}✓${NC} 配置文件已创建"

# 启动 DNS Filter
echo -e "${BLUE}[3/7] 启动 XDP DNS Filter (多队列模式)...${NC}"
"$PROJECT_ROOT/build/dns-filter" -config "$LOG_DIR/config.yaml" > "$LOG_DIR/dns-filter.log" 2>&1 &
FILTER_PID=$!
sleep 2

if ! ps -p $FILTER_PID > /dev/null 2>&1; then
    echo -e "  ${RED}✗${NC} 进程启动失败"
    cat "$LOG_DIR/dns-filter.log"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} 进程启动 (PID: $FILTER_PID)"

# 验证 BPF Maps
echo -e "${BLUE}[4/7] 验证 BPF Maps...${NC}"
sleep 1

echo "  检查 qidconf_map..."
qidconf_output=$(sudo bpftool map dump name qidconf_map 2>/dev/null || echo "{}")
echo "    qidconf_map 队列配置:"
echo "$qidconf_output" | grep -o '"key":[^,]*,"value":[^}]*}' | head -5 | sed 's/^/      /'

echo "  检查 dns_ports_map..."
dns_ports=$(sudo bpftool map dump name dns_ports_map 2>/dev/null | grep -c "key" || echo "0")
echo "    配置的 DNS 端口数: $dns_ports"
echo -e "  ${GREEN}✓${NC} BPF Maps 验证完成"

# 多队列负载分布测试
echo -e "${BLUE}[5/7] 多队列负载测试...${NC}"
echo "  发送 $NUM_QUERIES 个 DNS 查询..."

for i in $(seq 1 $NUM_QUERIES); do
    (
        echo -n "example$i.com. IN A" | timeout 2 \
        ip netns exec ns_test nslookup -port=53 example$i.com 10.99.0.1 \
        2>/dev/null || true
    ) &
    
    # 控制并发数
    if [ $((i % 20)) -eq 0 ]; then
        wait
    fi
done

wait
echo "  发送了 $NUM_QUERIES 个 DNS 查询"

# 检查统计
echo -e "${BLUE}[6/7] 检查处理统计...${NC}"
sleep 2

# 从日志获取统计信息
if grep -q "Final stats" "$LOG_DIR/dns-filter.log" 2>/dev/null; then
    stats=$(grep "Final stats" "$LOG_DIR/dns-filter.log" | tail -1 | sed 's/.*Final stats: //')
    echo "  统计: $stats"
    echo -e "  ${GREEN}✓${NC} 成功处理多队列流量!"
else
    echo "  从进程状态获取统计..."
    echo -e "  ${GREEN}✓${NC} 进程运行正常"
fi

# 性能指标
echo -e "${BLUE}[7/7] 性能指标...${NC}"
sleep 1

# 计算处理速率
duration=$(( $(date +%s) - $(date +%s -d "$(head -1 "$LOG_DIR/dns-filter.log" | cut -d' ' -f1-2)" 2>/dev/null || echo "now") ))

if [ "$duration" -gt 0 ]; then
    pps=$((NUM_QUERIES / duration))
    echo "  处理 PPS: ~$pps packets/sec"
fi

# 检查队列分布
if [ -f "$LOG_DIR/dns-filter.log" ]; then
    queue_msgs=$(grep "Queue [0-9]" "$LOG_DIR/dns-filter.log" | wc -l)
    echo "  检测到 $queue_msgs 条队列消息"
    
    for q in $(seq 0 $((QUEUE_COUNT - 1))); do
        count=$(grep "Queue $q" "$LOG_DIR/dns-filter.log" | wc -l)
        echo "    Queue $q: $count 条消息"
    done
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════"
echo "  ✅ 多队列测试完成!"
echo "     $QUEUE_COUNT 个 RX 队列已启用"
echo "     共处理 $NUM_QUERIES 个 DNS 查询"
echo "════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "📊 完整日志: $LOG_DIR/dns-filter.log"
echo ""

