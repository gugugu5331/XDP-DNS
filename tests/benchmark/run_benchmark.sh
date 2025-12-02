#!/bin/bash
#
# XDP DNS Filter 完整性能对比测试脚本
#

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="${PROJECT_ROOT}/tests/benchmark/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     XDP DNS Filter - 完整性能对比测试                        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 创建结果目录
mkdir -p "${RESULTS_DIR}"

# 系统信息
echo -e "${YELLOW}[1/5] 收集系统信息...${NC}"
echo "========================================" > "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "测试时间: $(date)" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "主机名: $(hostname)" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "CPU 信息:" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
lscpu | grep -E "Model name|CPU\(s\)|Thread|Core|MHz|Cache" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "内存信息:" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
free -h >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "Go 版本: $(go version)" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo "GCC 版本: $(g++ --version | head -1)" >> "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"

cat "${RESULTS_DIR}/system_info_${TIMESTAMP}.txt"
echo ""

# 编译 C++ 库
echo -e "${YELLOW}[2/5] 编译 C++ 库...${NC}"
cd "${PROJECT_ROOT}/cpp"
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1
echo -e "${GREEN}✓ C++ 编译完成${NC}"
echo ""

# 运行 C++ 单元测试
echo -e "${YELLOW}[3/5] 运行 C++ 单元测试...${NC}"
./xdp_dns_tests --gtest_brief=1
echo ""

# 运行 C++ 基准测试
echo -e "${YELLOW}[4/5] 运行 C++ 性能基准测试...${NC}"
echo ""
./xdp_dns_benchmark --benchmark_format=console --benchmark_repetitions=3 \
    2>&1 | tee "${RESULTS_DIR}/cpp_benchmark_${TIMESTAMP}.txt"
echo ""

# 运行 Go 基准测试
echo -e "${YELLOW}[5/5] 运行 Go 性能基准测试...${NC}"
echo ""
cd "${PROJECT_ROOT}"
go test -bench=. -benchmem -benchtime=3s -count=3 ./pkg/dns/ ./pkg/filter/ \
    2>&1 | tee "${RESULTS_DIR}/go_benchmark_${TIMESTAMP}.txt"
echo ""

# 生成对比报告
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    性能对比报告                              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "测试结果已保存到: ${RESULTS_DIR}/"
echo ""
echo -e "${GREEN}完成!${NC}"

