#pragma once

#include "common.hpp"

namespace xdp_dns {

// DNS 头部结构 (网络字节序)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
    
    // 获取解析后的值
    uint16_t getId() const { return ntohs(id); }
    uint16_t getFlags() const { return ntohs(flags); }
    uint16_t getQDCount() const { return ntohs(qd_count); }
    uint16_t getANCount() const { return ntohs(an_count); }
    
    // 标志位检查
    bool isQuery() const { return (getFlags() & 0x8000) == 0; }
    bool isResponse() const { return !isQuery(); }
    uint8_t getRCode() const { return getFlags() & 0x000F; }
    bool isRecursionDesired() const { return (getFlags() & 0x0100) != 0; }
} __attribute__((packed));

static_assert(sizeof(DNSHeader) == 12, "DNSHeader size must be 12 bytes");

// DNS 问题结构 (零拷贝)
struct DNSQuestion {
    const uint8_t* name_start;   // 域名起始位置
    size_t name_offset;          // 相对于包开始的偏移
    size_t name_wire_len;        // 线上格式长度
    uint16_t qtype;
    uint16_t qclass;
};

// DNS 解析结果
struct DNSParseResult {
    const DNSHeader* header;
    DNSQuestion question;
    size_t total_consumed;       // 消费的总字节数
    size_t question_end;         // 问题部分结束位置
    uint16_t id;                 // DNS ID (主机字节序)
    uint16_t flags;              // DNS flags (主机字节序)
    bool is_query;               // 是否是查询
};

// DNS 解析器类
class DNSParser {
public:
    // 解析 DNS 查询 (只解析第一个问题)
    static Error parse(
        const uint8_t* data,
        size_t len,
        DNSParseResult* result
    );
    
    // 解码域名到缓冲区
    static Error decodeName(
        const uint8_t* packet,
        size_t packet_len,
        size_t name_offset,
        char* out_buf,
        size_t buf_size,
        size_t* out_len
    );
    
    // 域名比较 (大小写不敏感)
    static bool domainEquals(
        const uint8_t* packet,
        size_t packet_len,
        const DNSQuestion& q,
        const char* domain,
        size_t domain_len
    );
    
    // 域名后缀匹配 (用于通配符)
    static bool domainEndsWith(
        const uint8_t* packet,
        size_t packet_len,
        const DNSQuestion& q,
        const char* suffix,
        size_t suffix_len
    );

private:
    // 解析域名，返回结束位置
    static Error parseName(
        const uint8_t* data,
        size_t len,
        size_t offset,
        size_t* end_offset,
        size_t* wire_len
    );
    
    // 计算域名长度（不解码）
    static Error getNameLength(
        const uint8_t* data,
        size_t len,
        size_t offset,
        size_t* decoded_len
    );
};

// DNS 响应构建器
class DNSResponseBuilder {
public:
    // 构建 NXDOMAIN 响应
    static size_t buildNXDomain(
        const uint8_t* query,
        size_t query_len,
        const DNSParseResult& parsed,
        uint8_t* response,
        size_t response_buf_size
    );
    
    // 构建 A 记录响应
    static size_t buildAResponse(
        const uint8_t* query,
        size_t query_len,
        const DNSParseResult& parsed,
        uint32_t ip,           // 网络字节序
        uint32_t ttl,
        uint8_t* response,
        size_t response_buf_size
    );

    // 构建 AAAA 记录响应 (IPv6)
    static size_t buildAAAAResponse(
        const uint8_t* query,
        size_t query_len,
        const DNSParseResult& parsed,
        const uint8_t* ipv6,   // 16 字节, 网络字节序
        uint32_t ttl,
        uint8_t* response,
        size_t response_buf_size
    );

    // 构建 REFUSED 响应
    static size_t buildRefused(
        const uint8_t* query,
        size_t query_len,
        const DNSParseResult& parsed,
        uint8_t* response,
        size_t response_buf_size
    );

private:
    // 复制问题部分
    static size_t copyQuestion(
        const uint8_t* query,
        const DNSParseResult& parsed,
        uint8_t* response,
        size_t offset
    );
};

} // namespace xdp_dns

