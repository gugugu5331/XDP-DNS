# XDP DNS 流量过滤系统 C++ 优化方案 (续)

## 4. 集成方案

### 4.1 项目目录结构调整

```
xdp-dns/
├── cpp/                          # C++ 核心库
│   ├── include/
│   │   └── xdp_dns/
│   │       ├── dns_parser.hpp
│   │       ├── domain_trie.hpp
│   │       ├── filter_engine.hpp
│   │       ├── packet_processor.hpp
│   │       ├── response_builder.hpp
│   │       └── cgo_bridge.h
│   ├── src/
│   │   ├── dns_parser.cpp
│   │   ├── domain_trie.cpp
│   │   ├── filter_engine.cpp
│   │   ├── packet_processor.cpp
│   │   ├── response_builder.cpp
│   │   └── cgo_bridge.cpp
│   ├── tests/
│   │   ├── dns_parser_test.cpp
│   │   ├── domain_trie_test.cpp
│   │   └── benchmark_test.cpp
│   └── CMakeLists.txt
├── pkg/
│   └── native/                   # CGO 封装
│       ├── native.go
│       └── native_test.go
├── cmd/dns-filter/
│   └── main.go                   # 使用 native 包
└── ...
```

### 4.2 CMake 构建配置

```cmake
# cpp/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(xdp_dns_cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 编译选项
add_compile_options(
    -O3
    -march=native
    -mtune=native
    -flto
    -fno-exceptions    # 减少代码体积
    -fno-rtti          # 不需要 RTTI
    -Wall -Wextra -Wpedantic
)

# 库文件
add_library(xdp_dns_core STATIC
    src/dns_parser.cpp
    src/domain_trie.cpp
    src/filter_engine.cpp
    src/packet_processor.cpp
    src/response_builder.cpp
)

target_include_directories(xdp_dns_core PUBLIC include)

# CGO 共享库
add_library(xdp_dns SHARED src/cgo_bridge.cpp)
target_link_libraries(xdp_dns PRIVATE xdp_dns_core)

# 测试
enable_testing()
find_package(GTest REQUIRED)

add_executable(xdp_dns_tests
    tests/dns_parser_test.cpp
    tests/domain_trie_test.cpp
)
target_link_libraries(xdp_dns_tests xdp_dns_core GTest::gtest_main)
add_test(NAME xdp_dns_tests COMMAND xdp_dns_tests)

# 基准测试
find_package(benchmark QUIET)
if(benchmark_FOUND)
    add_executable(xdp_dns_benchmark tests/benchmark_test.cpp)
    target_link_libraries(xdp_dns_benchmark xdp_dns_core benchmark::benchmark)
endif()
```

### 4.3 CGO 封装层

```go
// pkg/native/native.go
package native

/*
#cgo CFLAGS: -I${SRCDIR}/../../cpp/include
#cgo LDFLAGS: -L${SRCDIR}/../../cpp/build -lxdp_dns -lstdc++

#include "xdp_dns/cgo_bridge.h"
#include <stdlib.h>
*/
import "C"
import (
    "errors"
    "unsafe"
)

// FilterAction 过滤动作
type FilterAction int

const (
    ActionAllow    FilterAction = C.ACTION_ALLOW
    ActionBlock    FilterAction = C.ACTION_BLOCK
    ActionRedirect FilterAction = C.ACTION_REDIRECT
    ActionLog      FilterAction = C.ACTION_LOG
)

// FilterResult 过滤结果
type FilterResult struct {
    Action     FilterAction
    RedirectIP uint32
    TTL        uint32
    RuleID     string
}

// Init 初始化 C++ 核心库
func Init(configPath string) error {
    cPath := C.CString(configPath)
    defer C.free(unsafe.Pointer(cPath))
    
    if ret := C.xdp_dns_init(cPath); ret != 0 {
        return errors.New("failed to initialize xdp_dns core")
    }
    return nil
}

// Cleanup 清理资源
func Cleanup() {
    C.xdp_dns_cleanup()
}

// ProcessPacket 处理数据包 (热路径)
func ProcessPacket(packetData []byte, responseBuf []byte) (FilterResult, int) {
    var result C.FilterResult
    var responseLen C.size_t = C.size_t(len(responseBuf))
    
    result = C.xdp_dns_process_packet(
        (*C.uint8_t)(unsafe.Pointer(&packetData[0])),
        C.size_t(len(packetData)),
        (*C.uint8_t)(unsafe.Pointer(&responseBuf[0])),
        &responseLen,
    )
    
    return FilterResult{
        Action:     FilterAction(result.action),
        RedirectIP: uint32(result.redirect_ip),
        TTL:        uint32(result.ttl),
        RuleID:     C.GoString(result.rule_id),
    }, int(responseLen)
}

// Stats 统计信息
type Stats struct {
    PacketsReceived   uint64
    PacketsAllowed    uint64
    PacketsBlocked    uint64
    PacketsRedirected uint64
    ParseErrors       uint64
    AvgLatencyNs      uint64
}

// GetStats 获取统计信息
func GetStats() Stats {
    var cStats C.XDPDNSStats
    C.xdp_dns_get_stats(&cStats)
    
    return Stats{
        PacketsReceived:   uint64(cStats.packets_received),
        PacketsAllowed:    uint64(cStats.packets_allowed),
        PacketsBlocked:    uint64(cStats.packets_blocked),
        PacketsRedirected: uint64(cStats.packets_redirected),
        ParseErrors:       uint64(cStats.parse_errors),
        AvgLatencyNs:      uint64(cStats.avg_latency_ns),
    }
}
```

### 4.4 Makefile 集成

```makefile
# 更新 Makefile
.PHONY: build-cpp

build-cpp:
	@echo "Building C++ core library..."
	@mkdir -p cpp/build
	@cd cpp/build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)

build: build-cpp build-go

build-go: build-cpp
	@echo "Building Go binary with C++ core..."
	CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY) ./cmd/dns-filter

test-cpp:
	@cd cpp/build && ctest --output-on-failure

bench-cpp:
	@cd cpp/build && ./xdp_dns_benchmark

clean-cpp:
	@rm -rf cpp/build
```

---

*文档继续在 CPP_OPTIMIZATION_PROPOSAL_PART3.md*

