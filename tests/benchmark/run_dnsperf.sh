#!/bin/bash
#
# DNS 威胁流量分析系统 - dnsperf 流量生成测试脚本
#
# 测试原理:
#   1. XDP DNS 分析系统监听网卡上的 DNS 流量
#   2. dnsperf 向真实 DNS 服务器发送查询，产生经过网卡的 DNS 流量
#   3. XDP 程序捕获并分析这些流量
#
# 使用方法:
#   ./run_dnsperf.sh [DNS服务器] [持续时间] [QPS] [并发数]
#
# 示例:
#   ./run_dnsperf.sh 8.8.8.8 10 1000 5
#

set -e

# 默认参数
DNS_SERVER="${1:-8.8.8.8}"
DURATION="${2:-10}"
QPS="${3:-1000}"
CLIENTS="${4:-5}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUERY_FILE="${SCRIPT_DIR}/dnsperf_queries.txt"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║          DNS 威胁流量分析系统 - dnsperf 流量生成测试             ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_header

# 检查 dnsperf
if ! command -v dnsperf &> /dev/null; then
    echo -e "${RED}错误: dnsperf 未安装${NC}"
    echo "请运行: sudo apt-get install dnsperf"
    exit 1
fi

# 检查查询文件
if [ ! -f "$QUERY_FILE" ]; then
    echo -e "${RED}错误: 查询文件不存在: $QUERY_FILE${NC}"
    exit 1
fi

echo -e "${CYAN}测试架构:${NC}"
echo ""
echo "  ┌──────────────┐     DNS查询      ┌──────────────┐"
echo "  │   dnsperf    │ ───────────────▶ │  DNS 服务器   │"
echo "  │ (流量生成器)  │ ◀─────────────── │  (${DNS_SERVER})  │"
echo "  └──────────────┘     DNS响应      └──────────────┘"
echo "         │"
echo "         │ 网卡流量"
echo "         ▼"
echo "  ┌──────────────┐"
echo "  │  XDP 程序    │ ◀── 在网卡驱动层捕获 DNS 流量"
echo "  │  AF_XDP      │"
echo "  └──────────────┘"
echo "         │"
echo "         ▼"
echo "  ┌──────────────┐"
echo "  │  威胁分析    │ ◀── 解析并匹配威胁规则"
echo "  │  (用户态)    │"
echo "  └──────────────┘"
echo ""

echo -e "${YELLOW}测试配置:${NC}"
echo "  DNS 服务器:   ${DNS_SERVER}:53"
echo "  测试时长:     ${DURATION} 秒"
echo "  目标 QPS:     ${QPS}"
echo "  并发客户端:   ${CLIENTS}"
echo "  查询文件:     ${QUERY_FILE}"
echo ""

# 统计查询文件
QUERY_COUNT=$(grep -v '^#' "$QUERY_FILE" | grep -v '^$' | wc -l)
echo -e "${YELLOW}查询统计:${NC}"
echo "  总查询数:     ${QUERY_COUNT}"
echo ""

echo -e "${GREEN}开始生成 DNS 流量...${NC}"
echo -e "${CYAN}(请确保 XDP DNS 分析系统正在另一个终端运行)${NC}"
echo ""

# 运行 dnsperf
dnsperf \
    -s "$DNS_SERVER" \
    -p 53 \
    -d "$QUERY_FILE" \
    -l "$DURATION" \
    -c "$CLIENTS" \
    -Q "$QPS" \
    -S 1

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}流量生成完成!${NC}"
echo ""
echo -e "${YELLOW}查看分析结果:${NC}"
echo "  1. 检查 XDP DNS 分析系统的终端输出"
echo "  2. 访问 Prometheus 指标: http://localhost:9090/metrics"
echo "  3. 查看统计: curl http://localhost:9090/stats"
echo ""
echo -e "${YELLOW}预期检测:${NC}"
echo "  - 威胁域名 (*.malware.com 等): 标记为 blocked"
echo "  - 可疑查询 (TXT/ANY):          标记为 logged"
echo "  - 正常域名:                     标记为 allowed"

