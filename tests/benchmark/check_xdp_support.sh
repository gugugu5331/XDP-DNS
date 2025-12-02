#!/bin/bash
#
# 检查 XDP 支持情况
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              XDP 支持情况检查                                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

check_pass=0
check_total=0

check() {
    local name=$1
    local cmd=$2
    local expected=$3
    
    check_total=$((check_total + 1))
    echo -n "[$check_total] $name ... "
    
    if eval "$cmd" &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        check_pass=$((check_pass + 1))
        return 0
    else
        echo -e "${RED}✗${NC}"
        if [ -n "$expected" ]; then
            echo -e "    ${YELLOW}$expected${NC}"
        fi
        return 1
    fi
}

echo ""
echo -e "${YELLOW}系统检查:${NC}"
echo ""

# 检查内核版本
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
check "内核版本 >= 5.4" \
    "awk 'BEGIN {exit !('$KERNEL_VERSION' >= 5.4)}'" \
    "当前: $(uname -r), 需要: 5.4+"

# 检查 root 权限
check "Root 权限" \
    "[ \$EUID -eq 0 ]" \
    "请使用 sudo 运行"

# 检查 BPF 文件系统
check "BPF 文件系统" \
    "mount | grep -q bpf" \
    "需要挂载 bpffs: sudo mount -t bpf bpf /sys/fs/bpf"

echo ""
echo -e "${YELLOW}工具检查:${NC}"
echo ""

# 检查 clang
check "clang 编译器" \
    "command -v clang" \
    "安装: sudo apt-get install clang"

# 检查 llvm
check "LLVM 工具链" \
    "command -v llc" \
    "安装: sudo apt-get install llvm"

# 检查 bpftool
check "bpftool" \
    "command -v bpftool" \
    "安装: sudo apt-get install linux-tools-generic"

# 检查 dnsperf
check "dnsperf" \
    "command -v dnsperf" \
    "安装: sudo apt-get install dnsperf"

echo ""
echo -e "${YELLOW}网卡检查:${NC}"
echo ""

# 列出网卡
echo "可用网卡:"
ip -o link show | awk -F': ' '{print "  - " $2}' | grep -v lo

# 检查默认网卡
DEFAULT_IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
if [ -n "$DEFAULT_IFACE" ]; then
    echo ""
    echo "默认网卡: $DEFAULT_IFACE"
    
    # 检查网卡驱动
    DRIVER=$(ethtool -i $DEFAULT_IFACE 2>/dev/null | grep driver | awk '{print $2}')
    if [ -n "$DRIVER" ]; then
        echo "驱动: $DRIVER"
    fi
    
    # 检查 XDP 支持
    if ip link show $DEFAULT_IFACE 2>/dev/null | grep -q xdpgeneric; then
        echo -e "XDP 模式: ${GREEN}支持 (generic)${NC}"
    elif ip link show $DEFAULT_IFACE 2>/dev/null | grep -q xdpoffload; then
        echo -e "XDP 模式: ${GREEN}支持 (offload)${NC}"
    elif ip link show $DEFAULT_IFACE 2>/dev/null | grep -q xdpdrv; then
        echo -e "XDP 模式: ${GREEN}支持 (driver)${NC}"
    else
        echo -e "XDP 模式: ${YELLOW}未知 (需要实际测试)${NC}"
    fi
fi

echo ""
echo -e "${YELLOW}内存限制检查:${NC}"
echo ""

# 检查 locked memory limit
ULIMIT_L=$(ulimit -l)
echo "Locked memory limit: $ULIMIT_L KB"
if [ "$ULIMIT_L" = "unlimited" ] || [ "$ULIMIT_L" -gt 1024 ]; then
    echo -e "${GREEN}✓ 内存限制足够${NC}"
else
    echo -e "${YELLOW}⚠ 内存限制较小，可能需要增加${NC}"
    echo "临时增加: sudo ulimit -l unlimited"
    echo "永久增加: 编辑 /etc/security/limits.conf"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ $check_pass -eq $check_total ]; then
    echo -e "${GREEN}✓ 所有检查通过 ($check_pass/$check_total)${NC}"
    echo ""
    echo "可以运行 XDP 测试:"
    echo "  sudo make test-xdp-quick"
    exit 0
else
    echo -e "${YELLOW}⚠ 部分检查未通过 ($check_pass/$check_total)${NC}"
    echo ""
    echo "建议先修复上述问题再运行 XDP 测试"
    exit 1
fi

