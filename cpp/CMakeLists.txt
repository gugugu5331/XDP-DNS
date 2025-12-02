cmake_minimum_required(VERSION 3.16)
project(xdp_dns_cpp VERSION 1.0.0 LANGUAGES CXX)

# C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 编译选项
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        -O3
        -march=native
        -mtune=native
        -flto
        -fno-exceptions
        -DNDEBUG
    )
else()
    add_compile_options(
        -O0
        -g
        -fsanitize=address,undefined
    )
    add_link_options(-fsanitize=address,undefined)
endif()

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter
)

# 头文件目录
include_directories(${CMAKE_SOURCE_DIR}/include)

# 核心静态库
add_library(xdp_dns_core STATIC
    src/dns_parser.cpp
    src/domain_trie.cpp
    src/filter_engine.cpp
)

target_include_directories(xdp_dns_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# CGO 共享库
add_library(xdp_dns SHARED
    src/cgo_bridge.cpp
)

target_link_libraries(xdp_dns PRIVATE xdp_dns_core)

# 设置共享库版本
set_target_properties(xdp_dns PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME xdp_dns
)

# 安装
install(TARGETS xdp_dns xdp_dns_core
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
)

# 测试
option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
    
    # 尝试查找 GTest
    find_package(GTest QUIET)
    
    if(GTest_FOUND)
        add_executable(xdp_dns_tests
            tests/dns_parser_test.cpp
            tests/domain_trie_test.cpp
        )
        target_link_libraries(xdp_dns_tests
            xdp_dns_core
            GTest::gtest
            GTest::gtest_main
        )
        add_test(NAME xdp_dns_tests COMMAND xdp_dns_tests)
    else()
        message(STATUS "GTest not found, skipping tests")
    endif()
    
    # 基准测试
    find_package(benchmark QUIET)
    if(benchmark_FOUND)
        add_executable(xdp_dns_benchmark
            tests/benchmark_test.cpp
        )
        target_link_libraries(xdp_dns_benchmark
            xdp_dns_core
            benchmark::benchmark
            benchmark::benchmark_main
        )
    else()
        message(STATUS "Google Benchmark not found, skipping benchmarks")
    endif()
endif()

# pkg-config 文件
configure_file(
    ${CMAKE_SOURCE_DIR}/xdp_dns.pc.in
    ${CMAKE_BINARY_DIR}/xdp_dns.pc
    @ONLY
)
install(FILES ${CMAKE_BINARY_DIR}/xdp_dns.pc
    DESTINATION lib/pkgconfig
)

# 打印配置信息
message(STATUS "")
message(STATUS "XDP DNS C++ Configuration:")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  Build type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Tests:        ${BUILD_TESTS}")
message(STATUS "")

