#!/bin/bash
#
# XDP DNS 极限性能测试 - 拉满系统资源
#

set -e

DURATION="${1:-30}"
TARGET_PPS="${2:-100000}"

PROJECT_ROOT="/home/lxx/work/xdp-dns"
LOG_DIR="/tmp/xdp-stress-test"
mkdir -p "$LOG_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}清理中...${NC}"
    pkill -f dns-filter 2>/dev/null || true
    pkill -f dns_flood 2>/dev/null || true
    ip netns del ns_sender 2>/dev/null || true
    ip link del veth_xdp 2>/dev/null || true
    echo -e "${GREEN}清理完成${NC}"
}
trap cleanup EXIT INT TERM

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║           XDP DNS 极限性能测试 - 系统资源压力测试                       ║"
echo "╠═══════════════════════════════════════════════════════════════════════╣"
echo "║  目标: 测试 XDP 零拷贝数据包处理的极限性能                              ║"
echo "║  流程: 网卡驱动层拦截 -> bpf_redirect_map -> AF_XDP Socket -> 解析     ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 检查 root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}需要 root 权限${NC}"
    exit 1
fi

echo -e "${BOLD}测试参数:${NC}"
echo "  持续时间: ${DURATION}s"
echo "  目标流量: ${TARGET_PPS} pps"
echo "  CPU 核心: $(nproc)"
echo ""

# 1. 配置网络
echo -e "${CYAN}[1/5] 配置高性能网络环境...${NC}"
ip netns del ns_sender 2>/dev/null || true
ip link del veth_xdp 2>/dev/null || true

ip netns add ns_sender
ip link add veth_xdp type veth peer name veth_send
ip link set veth_send netns ns_sender

# 增大队列和缓冲区
ip link set veth_xdp up txqueuelen 10000
ip addr add 10.0.0.1/24 dev veth_xdp
ethtool -G veth_xdp rx 4096 tx 4096 2>/dev/null || true

ip netns exec ns_sender ip link set lo up
ip netns exec ns_sender ip link set veth_send up txqueuelen 10000
ip netns exec ns_sender ip addr add 10.0.0.2/24 dev veth_send

# ARP 配置
echo 1 > /proc/sys/net/ipv4/conf/veth_xdp/proxy_arp
VETH_MAC=$(ip link show veth_xdp | grep ether | awk '{print $2}')
ip netns exec ns_sender ip neigh add 10.0.0.1 lladdr $VETH_MAC dev veth_send nud permanent

echo -e "  ${GREEN}✓${NC} 网络配置完成"

# 2. 创建高性能配置
echo -e "${CYAN}[2/5] 创建极限性能配置...${NC}"
cat > "$LOG_DIR/config.yaml" << EOF
interface: veth_xdp
queue_id: 0
queue_count: 1
rules_path: ${PROJECT_ROOT}/configs/rules.yaml

xdp:
  num_frames: 16384
  frame_size: 2048
  fill_ring_num_descs: 8192
  completion_ring_num_descs: 8192
  rx_ring_num_descs: 8192
  tx_ring_num_descs: 8192

workers:
  num_workers: $(nproc)
  batch_size: 128

metrics:
  enabled: true
  listen: ":9090"
  path: "/metrics"
EOF
echo -e "  ${GREEN}✓${NC} Workers: $(nproc), Batch: 128, Ring: 8192"

# 3. 启动 XDP 程序
echo -e "${CYAN}[3/5] 启动 XDP DNS 分析系统...${NC}"
cd "$PROJECT_ROOT"
"$PROJECT_ROOT/build/dns-filter" -config "$LOG_DIR/config.yaml" > "$LOG_DIR/xdp.log" 2>&1 &
XDP_PID=$!
sleep 3

if ! kill -0 $XDP_PID 2>/dev/null; then
    echo -e "${RED}启动失败${NC}"
    cat "$LOG_DIR/xdp.log"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} PID: $XDP_PID"

# 4. 创建高性能流量生成器
echo -e "${CYAN}[4/5] 启动极限流量生成器...${NC}"
cat > "$LOG_DIR/dns_flood.py" << 'PYEOF'
#!/usr/bin/env python3
import socket
import struct
import sys
import time
import random
import multiprocessing as mp

def build_dns_query(domain, tid):
    flags = 0x0100
    header = struct.pack('>HHHHHH', tid & 0xFFFF, flags, 1, 0, 0, 0)
    question = b''
    for part in domain.split('.'):
        question += bytes([len(part)]) + part.encode()
    question += b'\x00'
    question += struct.pack('>HH', 1, 1)
    return header + question

def sender_worker(worker_id, target_ip, duration, rate_per_worker):
    domains = ["example.com", "test.com", "google.com", "facebook.com", 
               "amazon.com", "microsoft.com", "github.com", "reddit.com"]
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)
    
    end_time = time.time() + duration
    sent = 0
    tid = worker_id * 10000
    
    # 预生成查询
    queries = [build_dns_query(d, tid + i) for i, d in enumerate(domains * 100)]
    
    while time.time() < end_time:
        for q in queries:
            try:
                sock.sendto(q, (target_ip, 53))
                sent += 1
            except:
                pass
    
    sock.close()
    return sent

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    total_rate = int(sys.argv[3]) if len(sys.argv) > 3 else 100000
    num_workers = mp.cpu_count()
    
    print(f"启动 {num_workers} 个发送进程, 目标: {total_rate} pps, 时长: {duration}s")
    
    rate_per_worker = total_rate // num_workers
    start = time.time()
    
    with mp.Pool(num_workers) as pool:
        results = pool.starmap(sender_worker, 
            [(i, target_ip, duration, rate_per_worker) for i in range(num_workers)])
    
    total_sent = sum(results)
    elapsed = time.time() - start
    print(f"总计发送: {total_sent:,} 包, 实际速率: {total_sent/elapsed:,.0f} pps")

if __name__ == "__main__":
    main()
PYEOF

# 启动流量生成
echo ""
echo -e "${BOLD}开始极限性能测试 (${DURATION}s)...${NC}"
echo ""

# 启动发送器(后台)
ip netns exec ns_sender python3 "$LOG_DIR/dns_flood.py" "10.0.0.1" "$DURATION" "$TARGET_PPS" > "$LOG_DIR/sender.log" 2>&1 &
SENDER_PID=$!

# PPS 采样
declare -a PPS_SAMPLES
prev_rx=0
echo "采样 PPS 数据..."
echo ""

for ((i=1; i<=DURATION; i++)); do
    sleep 1
    stats=$(curl -s http://localhost:9090/stats 2>/dev/null || echo "{}")
    rx=$(echo "$stats" | grep -o '"received":[0-9]*' | cut -d: -f2)
    rx=${rx:-0}

    if [ $prev_rx -gt 0 ] && [ $rx -gt $prev_rx ]; then
        pps=$((rx - prev_rx))
        PPS_SAMPLES+=($pps)
        printf "  第 %2d 秒: %'12d pps  (累计: %'d)\n" $i $pps $rx
    elif [ $prev_rx -eq 0 ] && [ $rx -gt 0 ]; then
        printf "  第 %2d 秒: 开始接收...  (累计: %'d)\n" $i $rx
    else
        printf "  第 %2d 秒: %'12d pps  (累计: %'d)\n" $i 0 $rx
    fi
    prev_rx=$rx
done

wait $SENDER_PID 2>/dev/null || true

# 5. 收集结果
echo ""
echo -e "${CYAN}[5/5] 收集测试结果...${NC}"
sleep 1

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo ""

# 计算 PPS 统计
if [ ${#PPS_SAMPLES[@]} -gt 0 ]; then
    max_pps=0
    min_pps=999999999
    sum_pps=0

    for pps in "${PPS_SAMPLES[@]}"; do
        sum_pps=$((sum_pps + pps))
        [ $pps -gt $max_pps ] && max_pps=$pps
        [ $pps -lt $min_pps ] && min_pps=$pps
    done

    avg_pps=$((sum_pps / ${#PPS_SAMPLES[@]}))

    echo -e "${BOLD}PPS 性能统计:${NC}"
    echo ""
    echo "  ┌──────────────────────────────────────────────────┐"
    printf "  │  ${GREEN}最大 PPS${NC}:    %'18d pps        │\n" $max_pps
    printf "  │  ${CYAN}平均 PPS${NC}:    %'18d pps        │\n" $avg_pps
    printf "  │  ${YELLOW}最小 PPS${NC}:    %'18d pps        │\n" $min_pps
    printf "  │  采样次数:    %'18d 次         │\n" ${#PPS_SAMPLES[@]}
    echo "  └──────────────────────────────────────────────────┘"
else
    echo -e "${RED}没有采集到 PPS 数据!${NC}"
fi

echo ""
echo -e "${BOLD}发送端统计:${NC}"
cat "$LOG_DIR/sender.log" 2>/dev/null || echo "  无日志"

echo ""
echo -e "${BOLD}XDP 接收统计:${NC}"
final_stats=$(curl -s http://localhost:9090/stats 2>/dev/null)
if [ -n "$final_stats" ]; then
    echo "$final_stats" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    rx = data.get('received', 0)
    print(f'  DNS 包接收:     {rx:,}')
    print(f'  正常流量:       {data.get(\"allowed\", 0):,}')
    print(f'  威胁拦截:       {data.get(\"blocked\", 0):,}')
    print(f'  可疑记录:       {data.get(\"logged\", 0):,}')
    print(f'  解析错误:       {data.get(\"parse_errors\", 0):,}')
    print(f'  丢弃:           {data.get(\"dropped\", 0):,}')
except Exception as e:
    print(f'  解析错误: {e}')
" 2>/dev/null || echo "  统计: $final_stats"
fi

echo ""
echo -e "${GREEN}测试完成!${NC}"
echo "日志: $LOG_DIR/xdp.log"

