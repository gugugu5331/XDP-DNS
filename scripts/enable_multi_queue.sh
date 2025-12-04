#!/bin/bash
# 启用网卡多 RX 队列支持

set -e

INTERFACE=${1:-eth0}
NUM_QUEUES=${2:-4}

echo "========================================"
echo "启用网卡多队列支持"
echo "========================================"
echo ""

# 检查网卡是否存在
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "❌ 错误: 网卡 $INTERFACE 不存在"
    exit 1
fi

echo "🔍 检查网卡: $INTERFACE"
echo ""

# 检查当前队列数
echo "📊 当前队列配置:"
if command -v ethtool &> /dev/null; then
    echo "  使用 ethtool 检查..."
    ethtool -l "$INTERFACE" 2>/dev/null | head -20 || echo "  ethtool 检查失败"
else
    echo "  ethtool 不可用，使用 sysfs 检查..."
    if [ -d "/sys/class/net/$INTERFACE/queues" ]; then
        rx_queues=$(ls -d /sys/class/net/$INTERFACE/queues/rx-* 2>/dev/null | wc -l)
        echo "  当前 RX 队列数: $rx_queues"
    fi
fi

echo ""
echo "⚙️  配置参数:"
echo "  - 网卡: $INTERFACE"
echo "  - 目标队列数: $NUM_QUEUES"
echo ""

# 尝试启用多队列
if command -v ethtool &> /dev/null; then
    echo "🔧 使用 ethtool 启用 $NUM_QUEUES 个队列..."
    
    # 获取网卡支持的最大队列数
    MAX_QUEUES=$(sudo ethtool -l "$INTERFACE" 2>/dev/null | grep -i "combined" | head -1 | awk '{print $NF}' || echo "$NUM_QUEUES")
    
    if [ -z "$MAX_QUEUES" ] || [ "$MAX_QUEUES" -lt 1 ]; then
        MAX_QUEUES=$NUM_QUEUES
    fi
    
    if [ "$NUM_QUEUES" -gt "$MAX_QUEUES" ]; then
        echo "⚠️  警告: 请求队列数 ($NUM_QUEUES) 超过最大支持 ($MAX_QUEUES)"
        NUM_QUEUES=$MAX_QUEUES
        echo "   已调整为: $NUM_QUEUES"
    fi
    
    echo "  启用 $NUM_QUEUES 个 RX/TX 队列..."
    sudo ethtool -L "$INTERFACE" combined "$NUM_QUEUES" 2>/dev/null || {
        echo "  ⚠️  combined 队列设置失败，尝试分别设置 RX 和 TX..."
        sudo ethtool -L "$INTERFACE" rx "$NUM_QUEUES" 2>/dev/null || echo "    RX 队列设置失败"
        sudo ethtool -L "$INTERFACE" tx "$NUM_QUEUES" 2>/dev/null || echo "    TX 队列设置失败"
    }
else
    echo "⚠️  ethtool 不可用，跳过队列配置"
    echo "   请手动运行: sudo ethtool -L $INTERFACE combined $NUM_QUEUES"
fi

echo ""
echo "✅ 验证配置结果:"
sleep 1

if command -v ethtool &> /dev/null; then
    echo "  使用 ethtool 验证..."
    sudo ethtool -l "$INTERFACE" 2>/dev/null | head -15 || echo "  验证失败"
else
    if [ -d "/sys/class/net/$INTERFACE/queues" ]; then
        rx_queues=$(ls -d /sys/class/net/$INTERFACE/queues/rx-* 2>/dev/null | wc -l)
        tx_queues=$(ls -d /sys/class/net/$INTERFACE/queues/tx-* 2>/dev/null | wc -l)
        echo "  RX 队列数: $rx_queues"
        echo "  TX 队列数: $tx_queues"
    fi
fi

echo ""
echo "========================================"
echo "✨ 多队列配置完成"
echo "========================================"
echo ""
echo "💡 使用提示:"
echo "   1. 更新 config.yaml:"
echo "      queue_start: 0"
echo "      queue_count: $NUM_QUEUES"
echo ""
echo "   2. 运行 XDP DNS Filter:"
echo "      sudo ./build/dns-filter -config configs/config.yaml"
echo ""

