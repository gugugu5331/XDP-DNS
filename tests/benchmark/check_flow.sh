#!/bin/bash
#
# XDP DNS 完整流程检查脚本
#

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║           XDP DNS 数据流程完整性检查                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

check_pass=0
check_fail=0

check() {
    local name="$1"
    local result="$2"
    local detail="$3"
    
    if [ "$result" = "OK" ]; then
        echo -e "  ✅ $name"
        [ -n "$detail" ] && echo "     └─ $detail"
        ((check_pass++))
    else
        echo -e "  ❌ $name"
        [ -n "$detail" ] && echo "     └─ $detail"
        ((check_fail++))
    fi
}

echo "[1] 检查 BPF 程序文件..."
if [ -f "/home/lxx/work/xdp-dns/bpf/xdp_dns_filter_bpfel.o" ]; then
    size=$(ls -lh /home/lxx/work/xdp-dns/bpf/xdp_dns_filter_bpfel.o | awk '{print $5}')
    check "BPF 程序文件存在" "OK" "大小: $size"
else
    check "BPF 程序文件存在" "FAIL" "文件不存在"
fi

echo ""
echo "[2] 检查 XDP 程序是否已附加..."
xdp_attached=$(ip link show 2>/dev/null | grep -c "xdp")
if [ "$xdp_attached" -gt 0 ]; then
    iface=$(ip link show 2>/dev/null | grep "xdp" | head -1 | awk -F: '{print $2}' | tr -d ' ')
    check "XDP 程序已附加" "OK" "接口: $iface"
else
    check "XDP 程序已附加" "FAIL" "没有接口附加 XDP 程序"
fi

echo ""
echo "[3] 检查 BPF Maps..."
echo "  查找 dns_ports_map..."
dns_map_id=$(bpftool map list 2>/dev/null | grep "dns_ports_map" | awk '{print $1}' | tr -d ':')
if [ -n "$dns_map_id" ]; then
    check "dns_ports_map 存在" "OK" "Map ID: $dns_map_id"
    
    # 检查内容
    dns_ports=$(bpftool map dump id $dns_map_id 2>/dev/null)
    if echo "$dns_ports" | grep -q "key:"; then
        port_count=$(echo "$dns_ports" | grep -c "key:")
        check "dns_ports_map 已配置" "OK" "端口数量: $port_count"
        echo "     └─ 内容:"
        echo "$dns_ports" | head -5 | sed 's/^/        /'
    else
        check "dns_ports_map 已配置" "FAIL" "Map 为空，端口 53 未添加!"
    fi
else
    check "dns_ports_map 存在" "FAIL" "Map 不存在"
fi

echo ""
echo "  查找 qidconf_map..."
qid_map_id=$(bpftool map list 2>/dev/null | grep "qidconf_map" | awk '{print $1}' | tr -d ':')
if [ -n "$qid_map_id" ]; then
    check "qidconf_map 存在" "OK" "Map ID: $qid_map_id"
    
    qid_content=$(bpftool map dump id $qid_map_id 2>/dev/null)
    enabled=$(echo "$qid_content" | grep "value: 01" | wc -l)
    if [ "$enabled" -gt 0 ]; then
        check "qidconf_map 队列已启用" "OK" "启用的队列数: $enabled"
    else
        check "qidconf_map 队列已启用" "FAIL" "没有队列启用!"
    fi
else
    check "qidconf_map 存在" "FAIL" "Map 不存在"
fi

echo ""
echo "  查找 xsks_map..."
xsk_map_id=$(bpftool map list 2>/dev/null | grep "xsks_map" | awk '{print $1}' | tr -d ':')
if [ -n "$xsk_map_id" ]; then
    check "xsks_map 存在" "OK" "Map ID: $xsk_map_id"
    
    xsk_content=$(bpftool map dump id $xsk_map_id 2>/dev/null)
    sockets=$(echo "$xsk_content" | grep -c "value:")
    check "xsks_map socket 注册" "OK" "注册的 socket 数: $sockets"
else
    check "xsks_map 存在" "FAIL" "Map 不存在"
fi

echo ""
echo "[4] 检查 metrics_map..."
metrics_map_id=$(bpftool map list 2>/dev/null | grep "metrics_map" | awk '{print $1}' | tr -d ':')
if [ -n "$metrics_map_id" ]; then
    check "metrics_map 存在" "OK" "Map ID: $metrics_map_id"
    
    # 尝试读取统计
    metrics=$(bpftool map dump id $metrics_map_id 2>/dev/null)
    if [ -n "$metrics" ]; then
        echo "     └─ 统计数据:"
        echo "$metrics" | head -10 | sed 's/^/        /'
    fi
else
    check "metrics_map 存在" "FAIL" "Map 不存在"
fi

echo ""
echo "[5] 检查用户态程序..."
dns_filter_pid=$(pgrep -f "dns-filter" | head -1)
if [ -n "$dns_filter_pid" ]; then
    check "dns-filter 进程运行中" "OK" "PID: $dns_filter_pid"
else
    check "dns-filter 进程运行中" "FAIL" "进程未运行"
fi

echo ""
echo "[6] 检查 metrics 端点..."
if curl -s http://localhost:9090/stats >/dev/null 2>&1; then
    stats=$(curl -s http://localhost:9090/stats 2>/dev/null)
    check "Metrics 端点可访问" "OK" ""
    echo "     └─ 统计: $stats"
else
    check "Metrics 端点可访问" "FAIL" "无法连接到 :9090"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "检查结果: $check_pass 通过, $check_fail 失败"
echo ""

if [ $check_fail -gt 0 ]; then
    echo "⚠️  存在问题，数据流可能无法完全走通"
    exit 1
else
    echo "✅ 所有检查通过，数据流应该可以正常工作"
    exit 0
fi

