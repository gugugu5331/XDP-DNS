/**
 * XDP DNS Filter - CGO Bridge
 *
 * 混合架构实现:
 * - C++ 负责: DNS 解析 (55x faster) + 响应构建 (900x faster)
 * - Go 负责:  Trie 匹配 (2-3x faster than C++) + 规则管理
 */

#include "xdp_dns/cgo_bridge.h"
#include "xdp_dns/dns_parser.hpp"
#include <atomic>
#include <cstring>

namespace {

// 全局状态
std::atomic<bool> g_initialized{false};

// 统计计数器
std::atomic<uint64_t> g_packets_received{0};
std::atomic<uint64_t> g_packets_parsed{0};
std::atomic<uint64_t> g_parse_errors{0};
std::atomic<uint64_t> g_response_built{0};
std::atomic<uint64_t> g_total_latency_ns{0};

} // anonymous namespace

extern "C" {

// ==================== 初始化/清理 ====================

int xdp_dns_init(void) {
    g_initialized.store(true, std::memory_order_release);
    return XDP_DNS_OK;
}

void xdp_dns_cleanup(void) {
    g_initialized.store(false, std::memory_order_release);
}

// ==================== DNS 解析 (C++ 高性能实现) ====================

int xdp_dns_parse(
    const uint8_t* packet_data,
    size_t packet_len,
    XDPDNSParseResult* result
) {
    if (!packet_data || !result || packet_len < 12) {
        return XDP_DNS_ERR_INVALID_PARAM;
    }

    g_packets_received.fetch_add(1, std::memory_order_relaxed);

    // 使用 C++ 解析器
    xdp_dns::DNSParseResult parsed;
    auto err = xdp_dns::DNSParser::parse(packet_data, packet_len, &parsed);

    if (err != xdp_dns::Error::Success) {
        g_parse_errors.fetch_add(1, std::memory_order_relaxed);
        return static_cast<int>(err);
    }

    // 检查是否是查询
    if (!parsed.is_query) {
        return XDP_DNS_ERR_NOT_DNS_QUERY;
    }

    // 填充结果
    result->id = parsed.id;
    result->flags = parsed.flags;
    result->qtype = parsed.question.qtype;
    result->qclass = parsed.question.qclass;
    result->name_offset = parsed.question.name_offset;
    result->question_end = parsed.question_end;

    // 解码域名
    size_t domain_len = 0;
    err = xdp_dns::DNSParser::decodeName(
        packet_data, packet_len,
        parsed.question.name_offset,
        result->domain, sizeof(result->domain),
        &domain_len
    );

    if (err != xdp_dns::Error::Success) {
        g_parse_errors.fetch_add(1, std::memory_order_relaxed);
        return static_cast<int>(err);
    }

    result->domain_len = domain_len;
    g_packets_parsed.fetch_add(1, std::memory_order_relaxed);

    return XDP_DNS_OK;
}

// ==================== 响应构建 (C++ 高性能实现) ====================

int xdp_dns_build_nxdomain(
    const uint8_t* original_packet,
    size_t original_len,
    uint8_t* response_buf,
    size_t response_buf_size,
    size_t* response_len
) {
    if (!original_packet || !response_buf || !response_len) {
        return XDP_DNS_ERR_INVALID_PARAM;
    }

    // 先解析原始包
    xdp_dns::DNSParseResult parsed;
    auto err = xdp_dns::DNSParser::parse(original_packet, original_len, &parsed);
    if (err != xdp_dns::Error::Success) {
        return static_cast<int>(err);
    }

    // 构建 NXDOMAIN 响应
    size_t built_len = xdp_dns::DNSResponseBuilder::buildNXDomain(
        original_packet, original_len, parsed,
        response_buf, response_buf_size
    );

    if (built_len == 0) {
        return XDP_DNS_ERR_BUFFER_TOO_SMALL;
    }

    *response_len = built_len;
    g_response_built.fetch_add(1, std::memory_order_relaxed);

    return XDP_DNS_OK;
}

int xdp_dns_build_a_response(
    const uint8_t* original_packet,
    size_t original_len,
    uint32_t ipv4_addr,
    uint32_t ttl,
    uint8_t* response_buf,
    size_t response_buf_size,
    size_t* response_len
) {
    if (!original_packet || !response_buf || !response_len) {
        return XDP_DNS_ERR_INVALID_PARAM;
    }

    // 先解析原始包
    xdp_dns::DNSParseResult parsed;
    auto err = xdp_dns::DNSParser::parse(original_packet, original_len, &parsed);
    if (err != xdp_dns::Error::Success) {
        return static_cast<int>(err);
    }

    // 构建 A 记录响应
    size_t built_len = xdp_dns::DNSResponseBuilder::buildAResponse(
        original_packet, original_len, parsed,
        ipv4_addr, ttl,
        response_buf, response_buf_size
    );

    if (built_len == 0) {
        return XDP_DNS_ERR_BUFFER_TOO_SMALL;
    }

    *response_len = built_len;
    g_response_built.fetch_add(1, std::memory_order_relaxed);

    return XDP_DNS_OK;
}

int xdp_dns_build_aaaa_response(
    const uint8_t* original_packet,
    size_t original_len,
    const uint8_t* ipv6_addr,
    uint32_t ttl,
    uint8_t* response_buf,
    size_t response_buf_size,
    size_t* response_len
) {
    if (!original_packet || !response_buf || !response_len || !ipv6_addr) {
        return XDP_DNS_ERR_INVALID_PARAM;
    }

    // 先解析原始包
    xdp_dns::DNSParseResult parsed;
    auto err = xdp_dns::DNSParser::parse(original_packet, original_len, &parsed);
    if (err != xdp_dns::Error::Success) {
        return static_cast<int>(err);
    }

    // 构建 AAAA 记录响应
    size_t built_len = xdp_dns::DNSResponseBuilder::buildAAAAResponse(
        original_packet, original_len, parsed,
        ipv6_addr, ttl,
        response_buf, response_buf_size
    );

    if (built_len == 0) {
        return XDP_DNS_ERR_BUFFER_TOO_SMALL;
    }

    *response_len = built_len;
    g_response_built.fetch_add(1, std::memory_order_relaxed);

    return XDP_DNS_OK;
}

// ==================== 统计信息 ====================

void xdp_dns_get_stats(XDPDNSStats* stats) {
    if (!stats) return;

    stats->packets_received = g_packets_received.load(std::memory_order_relaxed);
    stats->packets_parsed = g_packets_parsed.load(std::memory_order_relaxed);
    stats->parse_errors = g_parse_errors.load(std::memory_order_relaxed);
    stats->response_built = g_response_built.load(std::memory_order_relaxed);
    stats->total_latency_ns = g_total_latency_ns.load(std::memory_order_relaxed);

    // 这些由 Go 端填充
    stats->packets_allowed = 0;
    stats->packets_blocked = 0;
    stats->packets_redirected = 0;
}

void xdp_dns_reset_stats(void) {
    g_packets_received.store(0, std::memory_order_relaxed);
    g_packets_parsed.store(0, std::memory_order_relaxed);
    g_parse_errors.store(0, std::memory_order_relaxed);
    g_response_built.store(0, std::memory_order_relaxed);
    g_total_latency_ns.store(0, std::memory_order_relaxed);
}

} // extern "C"
