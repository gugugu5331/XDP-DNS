# XDP DNS Filter Makefile

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR := build
BINARY := dns-filter
INTERFACE ?= eth0
CPP_BUILD_DIR := cpp/build

.PHONY: all build clean test install run help build-cpp

all: build

# 构建
build:
	@echo "Building XDP DNS Filter..."
	@./scripts/build.sh

# 仅构建 Go 程序 (不编译 BPF)
build-go:
	@echo "Building Go binary..."
	@mkdir -p $(BUILD_DIR)
	@go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) ./cmd/dns-filter
	@cp -r configs $(BUILD_DIR)/

# 构建 C++ 核心库
build-cpp:
	@echo "Building C++ core library..."
	@mkdir -p $(CPP_BUILD_DIR)
	@cd $(CPP_BUILD_DIR) && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$$(nproc)

# 构建带 C++ 优化的版本
build-with-cpp: build-cpp
	@echo "Building Go binary with C++ core..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 CGO_LDFLAGS="-L$(PWD)/$(CPP_BUILD_DIR) -lxdp_dns" \
		go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY)-cpp ./cmd/dns-filter
	@cp -r configs $(BUILD_DIR)/

# 编译 BPF 程序
build-bpf:
	@echo "Building BPF program..."
	@cd bpf && make

# 测试
test:
	@echo "Running tests..."
	@./scripts/test.sh

# 单元测试
unit-test:
	@go test -v -race ./pkg/...

# 基准测试
bench:
	@go test -bench=. -benchmem ./pkg/...

# 代码检查
lint:
	@go vet ./...
	@gofmt -l ./pkg ./internal ./cmd

# 格式化代码
fmt:
	@gofmt -w ./pkg ./internal ./cmd

# 清理
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@cd bpf && make clean 2>/dev/null || true

# 安装 (需要 root)
install:
	@echo "Installing XDP DNS Filter..."
	@sudo ./scripts/deploy.sh $(INTERFACE)

# 卸载
uninstall:
	@echo "Uninstalling XDP DNS Filter..."
	@sudo systemctl stop xdp-dns-filter 2>/dev/null || true
	@sudo systemctl disable xdp-dns-filter 2>/dev/null || true
	@sudo rm -f /etc/systemd/system/xdp-dns-filter.service
	@sudo rm -rf /opt/xdp-dns
	@sudo systemctl daemon-reload

# 运行 (开发模式)
run: build-go
	@echo "Running XDP DNS Filter (dev mode)..."
	@sudo $(BUILD_DIR)/$(BINARY) -config configs/config.yaml

# 依赖
deps:
	@go mod download
	@go mod tidy

# 生成
generate:
	@go generate ./...

# C++ 测试
test-cpp:
	@cd $(CPP_BUILD_DIR) && ctest --output-on-failure

# C++ 清理
clean-cpp:
	@rm -rf $(CPP_BUILD_DIR)

# 帮助
help:
	@echo "XDP DNS Filter - Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make build          - Build everything (BPF + Go)"
	@echo "  make build-go       - Build Go binary only"
	@echo "  make build-bpf      - Build BPF program only"
	@echo "  make build-cpp      - Build C++ core library"
	@echo "  make build-with-cpp - Build Go with C++ optimizations"
	@echo "  make test           - Run all tests"
	@echo "  make unit-test      - Run Go unit tests"
	@echo "  make test-cpp       - Run C++ tests"
	@echo "  make bench          - Run benchmarks"
	@echo "  make lint           - Run code linting"
	@echo "  make fmt            - Format code"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make clean-cpp      - Clean C++ build"
	@echo "  make install        - Install to system (requires root)"
	@echo "  make uninstall      - Uninstall from system"
	@echo "  make run            - Build and run (dev mode)"
	@echo "  make deps           - Download dependencies"
	@echo ""
	@echo "Environment variables:"
	@echo "  VERSION          - Build version (default: git tag)"
	@echo "  INTERFACE        - Network interface (default: eth0)"

