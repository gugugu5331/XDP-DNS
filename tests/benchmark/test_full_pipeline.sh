#!/bin/bash
#
# XDP DNS 完整流水线测试
# 验证: 网卡 -> XDP -> AF_XDP -> 用户态 的完整流程
#

set -e

PROJECT_ROOT="/home/lxx/work/xdp-dns"
LOG_DIR="/tmp/xdp-pipeline-test"
mkdir -p "$LOG_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}清理...${NC}"
    pkill -9 -f dns-filter 2>/dev/null || true
    ip netns del ns_test 2>/dev/null || true
    ip link del veth_xdp 2>/dev/null || true
}
trap cleanup EXIT

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║           XDP DNS 完整流水线测试                                       ║"
echo "║   验证: 网卡驱动 -> XDP BPF -> AF_XDP Socket -> 用户态处理             ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 检查 root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}需要 root 权限${NC}"
    exit 1
fi

# 清理旧环境
cleanup 2>/dev/null || true
sleep 1

echo -e "${BLUE}[1/6] 创建测试网络环境...${NC}"
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

echo -e "${BLUE}[2/6] 创建配置文件...${NC}"
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
metrics:
  enabled: true
  listen: ":9095"
  path: "/metrics"
EOF
echo -e "  ${GREEN}✓${NC} 配置文件已创建"

echo -e "${BLUE}[3/6] 启动 XDP DNS Filter (使用真正的 DNS 过滤程序)...${NC}"
cd "$PROJECT_ROOT"
"$PROJECT_ROOT/build/dns-filter" -config "$LOG_DIR/config.yaml" > "$LOG_DIR/dns-filter.log" 2>&1 &
DNS_PID=$!
sleep 3

if ! kill -0 $DNS_PID 2>/dev/null; then
    echo -e "  ${RED}✗${NC} 启动失败!"
    echo "日志:"
    cat "$LOG_DIR/dns-filter.log"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} 进程启动 (PID: $DNS_PID)"

echo -e "${BLUE}[4/6] 验证 BPF Maps 配置...${NC}"
sleep 1

# 检查 dns_ports_map
echo "  检查 dns_ports_map..."
dns_map=$(bpftool map list 2>/dev/null | grep dns_ports_map)
if [ -n "$dns_map" ]; then
    map_id=$(echo "$dns_map" | awk '{print $1}' | tr -d ':')
    content=$(bpftool map dump id $map_id 2>/dev/null)
    # 检查 JSON 格式 ("key": 53) 或十六进制格式 (35 00)
    if echo "$content" | grep -qE '"key":\s*53|key:\s*35\s*00'; then
        echo -e "  ${GREEN}✓${NC} dns_ports_map 已配置端口 53"
    else
        echo -e "  ${RED}✗${NC} dns_ports_map 未配置端口 53!"
        echo "  内容: $content"
    fi
else
    echo -e "  ${RED}✗${NC} dns_ports_map 不存在!"
fi

# 检查 qidconf_map
echo "  检查 qidconf_map..."
qid_map=$(bpftool map list 2>/dev/null | grep qidconf_map)
if [ -n "$qid_map" ]; then
    map_id=$(echo "$qid_map" | awk '{print $1}' | tr -d ':')
    content=$(bpftool map dump id $map_id 2>/dev/null)
    echo "  qidconf_map 内容: "
    echo "$content" | head -20
    # 检查 JSON 格式 ("value": 1) 或十六进制格式 (value: 01)
    if echo "$content" | grep -qE '"value":\s*1|value:\s*01\s*00\s*00\s*00'; then
        echo -e "  ${GREEN}✓${NC} qidconf_map 队列已启用"
    else
        echo -e "  ${YELLOW}⚠${NC} qidconf_map 队列可能未启用，请检查上面的内容"
    fi
fi

echo -e "${BLUE}[5/6] 发送测试 DNS 查询...${NC}"
# 发送 10 个 DNS 查询
ip netns exec ns_test python3 << 'PY'
import socket
import struct

def build_dns_query(domain, tid):
    header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    question = b''
    for part in domain.split('.'):
        question += bytes([len(part)]) + part.encode()
    question += b'\x00\x00\x01\x00\x01'
    return header + question

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(10):
    q = build_dns_query(f"test{i}.example.com", i)
    sock.sendto(q, ("10.99.0.1", 53))
print("发送了 10 个 DNS 查询")
sock.close()
PY

sleep 2

echo -e "${BLUE}[6/6] 检查接收统计...${NC}"
stats=$(curl -s http://localhost:9095/stats 2>/dev/null)
echo "  统计: $stats"

received=$(echo "$stats" | grep -o '"received":[0-9]*' | cut -d: -f2)
if [ -n "$received" ] && [ "$received" -gt 0 ]; then
    echo -e "  ${GREEN}✓ 成功接收 $received 个 DNS 包!${NC}"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✅ 完整流水线测试通过!${NC}"
    echo -e "${GREEN}     网卡驱动 -> XDP BPF -> AF_XDP -> 用户态 流程正常工作${NC}"
else
    echo -e "  ${RED}✗ 未接收到 DNS 包${NC}"
    echo ""
    echo "诊断信息:"
    echo "  - 程序日志:"
    tail -20 "$LOG_DIR/dns-filter.log"
fi

