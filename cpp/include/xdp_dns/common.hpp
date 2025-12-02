#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cctype>

namespace xdp_dns {

// 错误码
enum class Error : int {
    Success = 0,
    PacketTooShort = -1,
    InvalidHeader = -2,
    TruncatedMessage = -3,
    PointerLoop = -4,
    InvalidLabel = -5,
    BufferTooSmall = -6,
    NotQuery = -7,
};

// 网络字节序转换 (使用编译器内置函数)
inline uint16_t ntohs(uint16_t n) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap16(n);
#else
    return n;
#endif
}

inline uint32_t ntohl(uint32_t n) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(n);
#else
    return n;
#endif
}

inline uint16_t htons(uint16_t h) {
    return ntohs(h);
}

inline uint32_t htonl(uint32_t h) {
    return ntohl(h);
}

// DNS 类型
namespace dns_type {
    constexpr uint16_t A     = 1;
    constexpr uint16_t NS    = 2;
    constexpr uint16_t CNAME = 5;
    constexpr uint16_t SOA   = 6;
    constexpr uint16_t PTR   = 12;
    constexpr uint16_t MX    = 15;
    constexpr uint16_t TXT   = 16;
    constexpr uint16_t AAAA  = 28;
    constexpr uint16_t ANY   = 255;
}

// DNS 类别
namespace dns_class {
    constexpr uint16_t IN = 1;
}

// DNS 响应码
namespace dns_rcode {
    constexpr uint8_t NOERROR  = 0;
    constexpr uint8_t FORMERR  = 1;
    constexpr uint8_t SERVFAIL = 2;
    constexpr uint8_t NXDOMAIN = 3;
    constexpr uint8_t NOTIMP   = 4;
    constexpr uint8_t REFUSED  = 5;
}

// 过滤动作
enum class Action : uint8_t {
    Allow = 0,
    Block = 1,
    Redirect = 2,
    Log = 3,
};

// 过滤规则
struct Rule {
    uint32_t id;
    Action action;
    uint32_t redirect_ip;  // 网络字节序
    uint32_t ttl;
    char rule_id[32];
    
    Rule() : id(0), action(Action::Allow), redirect_ip(0), ttl(300) {
        rule_id[0] = '\0';
    }
};

// 过滤结果
struct FilterResult {
    Action action;
    const Rule* matched_rule;
    
    FilterResult() : action(Action::Allow), matched_rule(nullptr) {}
    FilterResult(Action a, const Rule* r = nullptr) : action(a), matched_rule(r) {}
};

// 域名最大长度
constexpr size_t MAX_DOMAIN_LENGTH = 255;
constexpr size_t MAX_LABEL_LENGTH = 63;
constexpr size_t MAX_LABELS = 128;

// DNS 头部大小
constexpr size_t DNS_HEADER_SIZE = 12;

// 最小 DNS 查询大小: 头部 + 最小域名(1字节) + 类型(2) + 类别(2)
constexpr size_t MIN_DNS_QUERY_SIZE = DNS_HEADER_SIZE + 5;

} // namespace xdp_dns

