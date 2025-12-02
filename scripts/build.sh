#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/build"
VERSION="${VERSION:-dev}"

echo "=== Building XDP DNS Filter ==="
echo "Version: ${VERSION}"
echo "Project root: ${PROJECT_ROOT}"

# 创建输出目录
mkdir -p ${OUTPUT_DIR}

# 1. 编译 eBPF 程序 (可选)
if [ -d "${PROJECT_ROOT}/bpf" ]; then
    echo "[1/3] Compiling eBPF program..."
    cd ${PROJECT_ROOT}/bpf

    # 检查是否安装了 clang
    if command -v clang &> /dev/null; then
        # 生成 vmlinux.h (如果不存在)
        if [ ! -f vmlinux.h ] && command -v bpftool &> /dev/null; then
            echo "Generating vmlinux.h..."
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null || true
        fi

        # 编译 eBPF 程序
        if [ -f xdp_dns_filter.c ]; then
            clang -O2 -g -target bpf \
                -D__TARGET_ARCH_x86_64 \
                -I/usr/include \
                -I. \
                -c xdp_dns_filter.c \
                -o ${OUTPUT_DIR}/xdp_dns_filter_bpfel.o 2>/dev/null || echo "BPF compilation skipped (missing headers)"
        fi
    else
        echo "Clang not found, skipping BPF compilation"
    fi
else
    echo "[1/3] Skipping BPF compilation (no bpf directory)"
fi

# 2. 下载依赖
echo "[2/3] Downloading dependencies..."
cd ${PROJECT_ROOT}
go mod tidy

# 3. 编译 Go 程序
echo "[3/3] Building Go binary..."
cd ${PROJECT_ROOT}

# 获取 git 版本信息
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.buildVersion=${VERSION}-${GIT_COMMIT}" \
    -o ${OUTPUT_DIR}/dns-filter \
    ./cmd/dns-filter

# 复制配置文件
echo "Copying configuration files..."
mkdir -p ${OUTPUT_DIR}/configs
cp -r ${PROJECT_ROOT}/configs/* ${OUTPUT_DIR}/configs/ 2>/dev/null || true

echo ""
echo "=== Build complete ==="
echo "Output directory: ${OUTPUT_DIR}/"
ls -la ${OUTPUT_DIR}/

