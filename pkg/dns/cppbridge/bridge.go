// Package cppbridge 提供 C++ DNS 解析和响应构建的 Go 绑定
//
// 混合架构:
// - C++ 负责: DNS 解析 (55x faster) + 响应构建 (900x faster)
// - Go 负责:  Trie 匹配 (2-3x faster than C++) + 规则管理
package cppbridge

/*
#cgo CFLAGS: -I${SRCDIR}/../../../cpp/include
#cgo LDFLAGS: -L${SRCDIR}/../../../cpp/build -lxdp_dns -lstdc++
#include "xdp_dns/cgo_bridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// 错误定义
var (
	ErrInvalidParam   = errors.New("invalid parameter")
	ErrParseFailed    = errors.New("DNS parse failed")
	ErrBufferTooSmall = errors.New("buffer too small")
	ErrNotInitialized = errors.New("not initialized")
	ErrNotDNSQuery    = errors.New("not a DNS query")
)

// ParseResult DNS 解析结果
type ParseResult struct {
	ID          uint16
	Flags       uint16
	QType       uint16
	QClass      uint16
	NameOffset  uint64
	QuestionEnd uint64
	Domain      string
}

// Stats C++ 层统计信息
type Stats struct {
	PacketsReceived   uint64
	PacketsParsed     uint64
	PacketsAllowed    uint64
	PacketsBlocked    uint64
	PacketsRedirected uint64
	ParseErrors       uint64
	ResponseBuilt     uint64
	TotalLatencyNS    uint64
}

// Init 初始化 C++ 库
func Init() error {
	ret := C.xdp_dns_init()
	if ret != 0 {
		return ErrNotInitialized
	}
	return nil
}

// Cleanup 清理 C++ 库资源
func Cleanup() {
	C.xdp_dns_cleanup()
}

// Parse 使用 C++ 高性能解析器解析 DNS 查询
// 性能: ~12ns (比 Go 快 55 倍)
func Parse(packet []byte) (*ParseResult, error) {
	if len(packet) < 12 {
		return nil, ErrInvalidParam
	}

	var result C.XDPDNSParseResult

	ret := C.xdp_dns_parse(
		(*C.uint8_t)(unsafe.Pointer(&packet[0])),
		C.size_t(len(packet)),
		&result,
	)

	if ret != 0 {
		return nil, codeToError(int(ret))
	}

	return &ParseResult{
		ID:          uint16(result.id),
		Flags:       uint16(result.flags),
		QType:       uint16(result.qtype),
		QClass:      uint16(result.qclass),
		NameOffset:  uint64(result.name_offset),
		QuestionEnd: uint64(result.question_end),
		Domain:      C.GoStringN(&result.domain[0], C.int(result.domain_len)),
	}, nil
}

// BuildNXDomain 使用 C++ 构建 NXDOMAIN 响应
// 性能: ~29ns (比 Go 快 51 倍)
func BuildNXDomain(originalPacket []byte) ([]byte, error) {
	if len(originalPacket) < 12 {
		return nil, ErrInvalidParam
	}

	// 响应最大与查询相同大小
	response := make([]byte, len(originalPacket))
	var responseLen C.size_t = C.size_t(len(response))

	ret := C.xdp_dns_build_nxdomain(
		(*C.uint8_t)(unsafe.Pointer(&originalPacket[0])),
		C.size_t(len(originalPacket)),
		(*C.uint8_t)(unsafe.Pointer(&response[0])),
		C.size_t(len(response)),
		&responseLen,
	)

	if ret != 0 {
		return nil, codeToError(int(ret))
	}

	return response[:responseLen], nil
}

// BuildAResponse 使用 C++ 构建 A 记录响应
// 性能: ~4ns (比 Go 快 900 倍)
func BuildAResponse(originalPacket []byte, ipv4 uint32, ttl uint32) ([]byte, error) {
	if len(originalPacket) < 12 {
		return nil, ErrInvalidParam
	}

	// A 记录响应 = 查询 + 16 字节
	response := make([]byte, len(originalPacket)+16)
	var responseLen C.size_t = C.size_t(len(response))

	ret := C.xdp_dns_build_a_response(
		(*C.uint8_t)(unsafe.Pointer(&originalPacket[0])),
		C.size_t(len(originalPacket)),
		C.uint32_t(ipv4),
		C.uint32_t(ttl),
		(*C.uint8_t)(unsafe.Pointer(&response[0])),
		C.size_t(len(response)),
		&responseLen,
	)

	if ret != 0 {
		return nil, codeToError(int(ret))
	}

	return response[:responseLen], nil
}

