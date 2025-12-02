#ifndef XDP_DNS_CGO_BRIDGE_H
#define XDP_DNS_CGO_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== 类型定义 ====================

// 过滤动作 (与 Go 保持一致)
typedef enum {
    XDP_DNS_ACTION_ALLOW = 0,
    XDP_DNS_ACTION_BLOCK = 1,
    XDP_DNS_ACTION_REDIRECT = 2,
    XDP_DNS_ACTION_LOG = 3
} XDPDNSAction;

// DNS 查询类型
typedef enum {
    XDP_DNS_TYPE_A = 1,
    XDP_DNS_TYPE_AAAA = 28,
    XDP_DNS_TYPE_CNAME = 5,
    XDP_DNS_TYPE_MX = 15,
    XDP_DNS_TYPE_TXT = 16,
    XDP_DNS_TYPE_NS = 2,
    XDP_DNS_TYPE_SOA = 6,
    XDP_DNS_TYPE_PTR = 12
} XDPDNSType;

// DNS 解析结果 (传递给 Go 进行匹配)
typedef struct {
    uint16_t id;                    // DNS ID
    uint16_t flags;                 // DNS flags
    uint16_t qtype;                 // 查询类型
    uint16_t qclass;                // 查询类别
    size_t   name_offset;           // 域名在包中的偏移
    size_t   question_end;          // 问题部分结束位置
    char     domain[256];           // 解码后的域名
    size_t   domain_len;            // 域名长度
} XDPDNSParseResult;

// 统计信息
typedef struct {
    uint64_t packets_received;
    uint64_t packets_parsed;
    uint64_t packets_allowed;
    uint64_t packets_blocked;
    uint64_t packets_redirected;
    uint64_t parse_errors;
    uint64_t response_built;
    uint64_t total_latency_ns;
} XDPDNSStats;

// 错误码
typedef enum {
    XDP_DNS_OK = 0,
    XDP_DNS_ERR_INVALID_PARAM = -1,
    XDP_DNS_ERR_PARSE_FAILED = -2,
    XDP_DNS_ERR_BUFFER_TOO_SMALL = -3,
    XDP_DNS_ERR_NOT_INITIALIZED = -4,
    XDP_DNS_ERR_NOT_DNS_QUERY = -5,
} XDPDNSError;

// ==================== 初始化/清理 ====================

/**
 * 初始化 XDP DNS 核心库
 * @return 0 成功，负值错误
 */
int xdp_dns_init(void);

/**
 * 清理资源
 */
void xdp_dns_cleanup(void);

// ==================== DNS 解析 (C++ 高性能实现) ====================

/**
 * 解析 DNS 查询包 - 供 Go 调用
 *
 * 这是混合架构的核心: C++ 负责快速解析，Go 负责规则匹配
 *
 * @param packet_data   数据包数据 (从 UDP payload 开始)
 * @param packet_len    数据包长度
 * @param result        解析结果输出
 * @return 0 成功，负值错误
 */
int xdp_dns_parse(
    const uint8_t* packet_data,
    size_t packet_len,
    XDPDNSParseResult* result
);

// ==================== 响应构建 (C++ 高性能实现) ====================

/**
 * 构建 NXDOMAIN 响应
 *
 * @param original_packet  原始 DNS 查询包
 * @param original_len     原始包长度
 * @param response_buf     响应缓冲区
 * @param response_buf_size 缓冲区大小
 * @param response_len     输出: 响应长度
 * @return 0 成功
 */
int xdp_dns_build_nxdomain(
    const uint8_t* original_packet,
    size_t original_len,
    uint8_t* response_buf,
    size_t response_buf_size,
    size_t* response_len
);

/**
 * 构建 A 记录响应 (用于重定向)
 *
 * @param original_packet  原始 DNS 查询包
 * @param original_len     原始包长度
 * @param ipv4_addr        IPv4 地址 (网络字节序)
 * @param ttl              TTL
 * @param response_buf     响应缓冲区
 * @param response_buf_size 缓冲区大小
 * @param response_len     输出: 响应长度
 * @return 0 成功
 */
int xdp_dns_build_a_response(
    const uint8_t* original_packet,
    size_t original_len,
    uint32_t ipv4_addr,
    uint32_t ttl,
    uint8_t* response_buf,
    size_t response_buf_size,
    size_t* response_len
);

/**
 * 构建 AAAA 记录响应 (IPv6 重定向)
 *
 * @param original_packet  原始 DNS 查询包
 * @param original_len     原始包长度
 * @param ipv6_addr        IPv6 地址 (16 字节, 网络字节序)
 * @param ttl              TTL
 * @param response_buf     响应缓冲区
 * @param response_buf_size 缓冲区大小
 * @param response_len     输出: 响应长度
 * @return 0 成功
 */
int xdp_dns_build_aaaa_response(
    const uint8_t* original_packet,
    size_t original_len,
    const uint8_t* ipv6_addr,
    uint32_t ttl,
    uint8_t* response_buf,
    size_t response_buf_size,
    size_t* response_len
);

// ==================== 统计信息 ====================

/**
 * 获取统计信息
 */
void xdp_dns_get_stats(XDPDNSStats* stats);

/**
 * 重置统计
 */
void xdp_dns_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif // XDP_DNS_CGO_BRIDGE_H

