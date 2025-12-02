#!/bin/bash
#
# XDP DNS 性能基准测试 - 核心流程验证
#
# 测试核心流程:
# 1. XDP 程序在网卡驱动层拦截数据包
# 2. 检查是否为 DNS 数据包
# 3. 通过 bpf_redirect_map() 零拷贝重定向到 AF_XDP Socket
# 4. 用户程序从共享内存读取并解析 DNS 数据
#
# 使用 veth 虚拟网卡对进行测试，避免对实际网络影响
#
# 使用: sudo ./xdp_perf_test.sh [测试时长(秒)]
#

set -e

# 参数
DURATION="${1:-10}"
PACKETS_PER_SEC="${2:-10000}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
LOG_DIR="/tmp/xdp-perf-test"
RESULT_DIR="$SCRIPT_DIR/results"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 测试用的 veth 对
VETH_XDP="veth0"      # XDP 程序绑定到这个接口
VETH_SEND="veth1"     # 从这个接口发送流量

# 清理函数
cleanup() {
    echo -e "\n${YELLOW}清理中...${NC}"

    # 停止 XDP 程序
    if [ -n "$XDP_PID" ] && kill -0 $XDP_PID 2>/dev/null; then
        kill $XDP_PID 2>/dev/null || true
        wait $XDP_PID 2>/dev/null || true
    fi

    # 停止流量生成器
    if [ -n "$TRAFFIC_PID" ] && kill -0 $TRAFFIC_PID 2>/dev/null; then
        kill $TRAFFIC_PID 2>/dev/null || true
    fi

    # 清理网络命名空间和 veth
    ip netns del ns_sender 2>/dev/null || true
    ip link del veth_xdp 2>/dev/null || true

    echo -e "${GREEN}清理完成${NC}"
}

trap cleanup EXIT INT TERM

# 打印标题
print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║         XDP DNS 高性能数据包处理 - 核心流程性能测试                    ║"
    echo "╠══════════════════════════════════════════════════════════════════════╣"
    echo "║  测试内容:                                                           ║"
    echo "║    1. XDP 在网卡驱动层拦截数据包                                      ║"
    echo "║    2. 识别 DNS 数据包 (UDP 端口 53)                                   ║"
    echo "║    3. bpf_redirect_map() 零拷贝重定向到 AF_XDP Socket                 ║"
    echo "║    4. 用户程序从共享内存读取并解析 DNS 数据                            ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# 检查权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 需要 root 权限运行 XDP 程序${NC}"
        echo "请使用: sudo $0 $*"
        exit 1
    fi
}

# 检查 veth 对和网络命名空间
check_veth() {
    echo -e "${CYAN}[1/6] 检查并配置网络环境...${NC}"

    # 清理旧的配置
    ip netns del ns_sender 2>/dev/null || true
    ip link del veth_xdp 2>/dev/null || true

    # 创建网络命名空间
    echo "  创建网络命名空间 ns_sender..."
    ip netns add ns_sender

    # 创建 veth 对
    echo "  创建 veth 对..."
    ip link add veth_xdp type veth peer name veth_send

    # 将发送端移到命名空间
    ip link set veth_send netns ns_sender

    # 配置主命名空间的 veth
    ip link set veth_xdp up
    ip addr add 10.0.0.1/24 dev veth_xdp

    # 配置命名空间内的 veth
    ip netns exec ns_sender ip link set lo up
    ip netns exec ns_sender ip link set veth_send up
    ip netns exec ns_sender ip addr add 10.0.0.2/24 dev veth_send

    # 关键: 启用 ARP 代理和转发
    echo "  配置 ARP 和路由..."
    echo 1 > /proc/sys/net/ipv4/conf/veth_xdp/proxy_arp
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # 获取 veth_xdp 的 MAC 地址
    VETH_XDP_MAC=$(ip link show veth_xdp | grep ether | awk '{print $2}')

    # 在命名空间内手动添加 ARP 表项
    ip netns exec ns_sender ip neigh add 10.0.0.1 lladdr $VETH_XDP_MAC dev veth_send nud permanent

    # 更新全局变量
    VETH_XDP="veth_xdp"
    VETH_SEND="veth_send"
    NETNS="ns_sender"

    # 验证连通性
    echo "  验证网络连通性..."
    if ip netns exec ns_sender ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} 网络连通性正常"
    else
        echo -e "  ${YELLOW}⚠${NC} ping 测试失败 (XDP 程序可能会处理)"
    fi

    echo -e "  ${GREEN}✓${NC} veth_xdp (XDP 绑定) <-> veth_send (ns_sender 命名空间)"
}

# 检查程序
check_program() {
    echo -e "${CYAN}[2/6] 检查 dns-filter 程序...${NC}"
    
    if [ ! -f "$BUILD_DIR/dns-filter" ]; then
        echo -e "${YELLOW}编译 dns-filter...${NC}"
        cd "$PROJECT_ROOT"
        make build-go
    fi
    
    echo -e "  ${GREEN}✓${NC} 程序已就绪: $BUILD_DIR/dns-filter"
}

# 创建目录
setup_dirs() {
    echo -e "${CYAN}[3/6] 创建工作目录...${NC}"
    mkdir -p "$LOG_DIR" "$RESULT_DIR"
    echo -e "  ${GREEN}✓${NC} 日志目录: $LOG_DIR"
    echo -e "  ${GREEN}✓${NC} 结果目录: $RESULT_DIR"
}

# 主函数
main() {
    print_header
    check_root
    
    echo -e "${BOLD}测试参数:${NC}"
    echo "  测试时长: ${DURATION}s"
    echo "  目标流量: ${PACKETS_PER_SEC} pps"
    echo ""
    
    check_veth
    check_program
    setup_dirs
    
    # 继续测试（第二部分在下一个脚本块）
    source "${SCRIPT_DIR}/xdp_perf_test_run.sh"
}

main "$@"

