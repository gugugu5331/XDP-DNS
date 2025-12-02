#ifndef __XDP_DNS_FILTER_H__
#define __XDP_DNS_FILTER_H__

#include <linux/types.h>

// 常量定义
#define MAX_SOCKS 64
#define DNS_PORT 53
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

// DNS 头部结构
struct dns_hdr {
    __u16 id;           // 事务ID
    __u16 flags;        // 标志位
    __u16 qdcount;      // 问题数
    __u16 ancount;      // 回答数
    __u16 nscount;      // 授权数
    __u16 arcount;      // 附加数
} __attribute__((packed));

// 数据包元信息 (传递给用户态)
struct pkt_meta {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 pkt_len;
    __u8  is_query;     // 1=查询, 0=响应
    __u8  protocol;     // IP 协议类型
};

// 统计指标结构
struct metrics {
    __u64 total_packets;    // 总数据包数
    __u64 dns_packets;      // DNS 数据包数
    __u64 redirected;       // 重定向到用户态的数量
    __u64 blocked;          // 被阻止的数量
    __u64 passed;           // 直接通过的数量
};

// LPM Trie 键结构 (用于IP黑名单)
struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

// DNS 查询类型
enum dns_qtype {
    DNS_TYPE_A     = 1,
    DNS_TYPE_NS    = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_SOA   = 6,
    DNS_TYPE_PTR   = 12,
    DNS_TYPE_MX    = 15,
    DNS_TYPE_TXT   = 16,
    DNS_TYPE_AAAA  = 28,
    DNS_TYPE_ANY   = 255,
};

// XDP 动作
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4

// 指标映射键
#define METRICS_KEY_TOTAL     0
#define METRICS_KEY_DNS       1
#define METRICS_KEY_REDIRECT  2
#define METRICS_KEY_BLOCKED   3

// DNS 标志位掩码
#define DNS_FLAG_QR     0x8000  // Query/Response
#define DNS_FLAG_OPCODE 0x7800  // Operation code
#define DNS_FLAG_AA     0x0400  // Authoritative answer
#define DNS_FLAG_TC     0x0200  // Truncated
#define DNS_FLAG_RD     0x0100  // Recursion desired
#define DNS_FLAG_RA     0x0080  // Recursion available
#define DNS_FLAG_Z      0x0070  // Reserved
#define DNS_FLAG_RCODE  0x000F  // Response code

#endif /* __XDP_DNS_FILTER_H__ */

