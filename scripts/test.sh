#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd ${PROJECT_ROOT}

echo "=== Running XDP DNS Filter Tests ==="

# 1. 单元测试
echo "[1/4] Running unit tests..."
go test -v -race ./pkg/...

# 2. 检查代码
echo "[2/4] Running go vet..."
go vet ./...

# 3. 格式检查
echo "[3/4] Checking code format..."
UNFORMATTED=$(gofmt -l ./pkg ./internal ./cmd 2>/dev/null || true)
if [ -n "$UNFORMATTED" ]; then
    echo "Warning: The following files are not formatted:"
    echo "$UNFORMATTED"
fi

# 4. 构建测试
echo "[4/4] Testing build..."
go build -o /dev/null ./cmd/dns-filter

echo ""
echo "=== All tests passed ==="

