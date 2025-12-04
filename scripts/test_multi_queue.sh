#!/bin/bash
# 为虚拟网卡启用多 RX 队列 (用于测试)

set -e

echo "========================================"
echo "虚拟网卡多队列配置工具"
echo "========================================"
echo ""

INTERFACE=${1:-veth_xdp}
NUM_QUEUES=${2:-4}

# 检查网卡是否存在
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "❌ 网卡 $INTERFACE 不存在"
    echo ""
    echo "请先创建虚拟网卡:"
    echo "  sudo ip link add $INTERFACE type veth peer name veth_pair"
    exit 1
fi

echo "🔍 检查网卡信息:"
ip link show "$INTERFACE" | grep -E "mtu|qdisc" || true
echo ""

# 虚拟网卡配置
echo "⚙️  虚拟网卡通常不支持多队列硬件配置"
echo "   但我们可以通过以下方式实现多队列处理:"
echo ""
echo "选项 1: 使用 RSS (接收端缩放) - 硬件支持"
echo "  $ sudo ethtool -X $INTERFACE rxfh-indir equal 4"
echo ""
echo "选项 2: 使用 RPS (接收包转向) - 软件实现"
echo "  $ echo f > /sys/class/net/$INTERFACE/queues/rx-0/rps_cpus"
echo ""
echo "选项 3: 对于虚拟网卡 (veth), 可以配置多个 TX/RX 队列"
echo ""

# 尝试查询网卡队列支持
if command -v ethtool &> /dev/null; then
    echo "📊 尝试查询网卡队列支持..."
    echo ""
    sudo ethtool -l "$INTERFACE" 2>/dev/null || {
        echo "  ℹ️  此网卡可能不支持 ethtool 队列管理"
    }
else
    echo "⚠️  ethtool 未安装"
fi

echo ""
echo "💡 对于本测试环境的建议:"
echo ""
echo "1️⃣  启用 RPS (接收包转向):"
echo "   sudo bash -c 'echo f > /sys/class/net/$INTERFACE/queues/rx-0/rps_cpus'"
echo ""
echo "2️⃣  或使用 IRQ 亲和性配置:"
echo "   sudo irqbalance --foreground --debug"
echo ""
echo "3️⃣  验证 RSS 配置:"
echo "   sudo ethtool -x $INTERFACE"
echo ""
echo "========================================"

