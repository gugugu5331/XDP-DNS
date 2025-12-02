package cppbridge

/*
#include "xdp_dns/cgo_bridge.h"
*/
import "C"
import (
	"unsafe"
)

// BuildAAAAResponse 使用 C++ 构建 AAAA 记录响应 (IPv6)
func BuildAAAAResponse(originalPacket []byte, ipv6 [16]byte, ttl uint32) ([]byte, error) {
	if len(originalPacket) < 12 {
		return nil, ErrInvalidParam
	}

	// AAAA 记录响应 = 查询 + 28 字节
	response := make([]byte, len(originalPacket)+28)
	var responseLen C.size_t = C.size_t(len(response))

	ret := C.xdp_dns_build_aaaa_response(
		(*C.uint8_t)(unsafe.Pointer(&originalPacket[0])),
		C.size_t(len(originalPacket)),
		(*C.uint8_t)(unsafe.Pointer(&ipv6[0])),
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

// GetStats 获取 C++ 层统计信息
func GetStats() Stats {
	var cStats C.XDPDNSStats
	C.xdp_dns_get_stats(&cStats)

	return Stats{
		PacketsReceived:   uint64(cStats.packets_received),
		PacketsParsed:     uint64(cStats.packets_parsed),
		PacketsAllowed:    uint64(cStats.packets_allowed),
		PacketsBlocked:    uint64(cStats.packets_blocked),
		PacketsRedirected: uint64(cStats.packets_redirected),
		ParseErrors:       uint64(cStats.parse_errors),
		ResponseBuilt:     uint64(cStats.response_built),
		TotalLatencyNS:    uint64(cStats.total_latency_ns),
	}
}

// ResetStats 重置 C++ 层统计
func ResetStats() {
	C.xdp_dns_reset_stats()
}

// codeToError 将 C 错误码转换为 Go 错误
func codeToError(code int) error {
	switch code {
	case 0:
		return nil
	case -1:
		return ErrInvalidParam
	case -2:
		return ErrParseFailed
	case -3:
		return ErrBufferTooSmall
	case -4:
		return ErrNotInitialized
	case -5:
		return ErrNotDNSQuery
	default:
		return ErrParseFailed
	}
}

