#include "xdp_dns/dns_parser.hpp"

namespace xdp_dns {

Error DNSParser::parse(
    const uint8_t* data,
    size_t len,
    DNSParseResult* result
) {
    if (!data || !result) {
        return Error::InvalidHeader;
    }

    if (len < MIN_DNS_QUERY_SIZE) {
        return Error::PacketTooShort;
    }

    // 解析头部
    result->header = reinterpret_cast<const DNSHeader*>(data);

    // 填充解析结果
    result->id = result->header->getId();
    result->flags = result->header->getFlags();
    result->is_query = result->header->isQuery();

    // 检查是否有问题
    if (result->header->getQDCount() == 0) {
        return Error::InvalidHeader;
    }

    // 解析第一个问题
    size_t offset = DNS_HEADER_SIZE;
    result->question.name_start = data + offset;
    result->question.name_offset = offset;

    size_t name_end = 0;
    size_t wire_len = 0;
    Error err = parseName(data, len, offset, &name_end, &wire_len);
    if (err != Error::Success) {
        return err;
    }

    result->question.name_wire_len = wire_len;

    // 检查是否有足够空间存储类型和类别
    if (name_end + 4 > len) {
        return Error::TruncatedMessage;
    }

    result->question.qtype = ntohs(*reinterpret_cast<const uint16_t*>(data + name_end));
    result->question.qclass = ntohs(*reinterpret_cast<const uint16_t*>(data + name_end + 2));
    result->total_consumed = name_end + 4;
    result->question_end = name_end + 4;  // 问题部分结束位置

    return Error::Success;
}

Error DNSParser::parseName(
    const uint8_t* data,
    size_t len,
    size_t offset,
    size_t* end_offset,
    size_t* wire_len
) {
    size_t original_offset = offset;
    bool jumped = false;
    int jump_count = 0;
    size_t total_len = 0;
    
    while (jump_count < MAX_LABELS) {
        if (offset >= len) {
            return Error::TruncatedMessage;
        }
        
        uint8_t label_len = data[offset];
        
        // 域名结束
        if (label_len == 0) {
            if (!jumped) {
                *end_offset = offset + 1;
            } else {
                *end_offset = original_offset + 2;
            }
            *wire_len = total_len + 1;  // 包含结束符
            return Error::Success;
        }
        
        // 压缩指针
        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= len) {
                return Error::TruncatedMessage;
            }
            
            uint16_t ptr = ((label_len & 0x3F) << 8) | data[offset + 1];
            if (ptr >= len) {
                return Error::PointerLoop;
            }
            
            if (!jumped) {
                original_offset = offset;
                jumped = true;
            }
            
            offset = ptr;
            jump_count++;
            continue;
        }
        
        // 普通标签
        if (label_len > MAX_LABEL_LENGTH) {
            return Error::InvalidLabel;
        }
        
        if (offset + 1 + label_len > len) {
            return Error::TruncatedMessage;
        }
        
        total_len += 1 + label_len;
        offset += 1 + label_len;
    }
    
    return Error::PointerLoop;
}

Error DNSParser::decodeName(
    const uint8_t* packet,
    size_t packet_len,
    size_t name_offset,
    char* out_buf,
    size_t buf_size,
    size_t* out_len
) {
    size_t offset = name_offset;
    size_t buf_pos = 0;
    int jump_count = 0;
    bool first_label = true;
    
    while (jump_count < MAX_LABELS) {
        if (offset >= packet_len) {
            return Error::TruncatedMessage;
        }
        
        uint8_t label_len = packet[offset];
        
        if (label_len == 0) {
            if (buf_pos > 0 && buf_pos < buf_size) {
                out_buf[buf_pos] = '\0';
            }
            *out_len = buf_pos;
            return Error::Success;
        }
        
        // 压缩指针
        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= packet_len) {
                return Error::TruncatedMessage;
            }
            offset = ((label_len & 0x3F) << 8) | packet[offset + 1];
            jump_count++;
            continue;
        }
        
        // 添加点分隔符
        if (!first_label) {
            if (buf_pos >= buf_size) {
                return Error::BufferTooSmall;
            }
            out_buf[buf_pos++] = '.';
        }
        first_label = false;
        
        // 复制标签
        if (buf_pos + label_len > buf_size) {
            return Error::BufferTooSmall;
        }
        
        offset++;
        for (uint8_t i = 0; i < label_len; i++) {
            out_buf[buf_pos++] = std::tolower(packet[offset + i]);
        }
        offset += label_len;
    }
    
    return Error::PointerLoop;
}

bool DNSParser::domainEquals(
    const uint8_t* packet,
    size_t packet_len,
    const DNSQuestion& q,
    const char* domain,
    size_t domain_len
) {
    size_t offset = q.name_offset;
    size_t domain_pos = 0;
    int jump_count = 0;

    while (jump_count < MAX_LABELS) {
        if (offset >= packet_len) return false;

        uint8_t label_len = packet[offset];

        if (label_len == 0) {
            return domain_pos == domain_len;
        }

        // 压缩指针
        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= packet_len) return false;
            offset = ((label_len & 0x3F) << 8) | packet[offset + 1];
            jump_count++;
            continue;
        }

        offset++;

        // 比较标签
        for (uint8_t i = 0; i < label_len; i++) {
            if (domain_pos >= domain_len) return false;
            char c1 = std::tolower(packet[offset + i]);
            char c2 = std::tolower(domain[domain_pos++]);
            if (c1 != c2) return false;
        }

        offset += label_len;

        // 检查是否需要点分隔符
        if (packet[offset] != 0) {
            if (domain_pos >= domain_len || domain[domain_pos] != '.') {
                return false;
            }
            domain_pos++;
        }
    }

    return false;
}

bool DNSParser::domainEndsWith(
    const uint8_t* packet,
    size_t packet_len,
    const DNSQuestion& q,
    const char* suffix,
    size_t suffix_len
) {
    // 先解码域名
    char domain_buf[MAX_DOMAIN_LENGTH + 1];
    size_t domain_len = 0;

    if (decodeName(packet, packet_len, q.name_offset,
                   domain_buf, sizeof(domain_buf), &domain_len) != Error::Success) {
        return false;
    }

    if (domain_len < suffix_len) return false;

    // 比较后缀
    size_t start = domain_len - suffix_len;
    for (size_t i = 0; i < suffix_len; i++) {
        if (std::tolower(domain_buf[start + i]) != std::tolower(suffix[i])) {
            return false;
        }
    }

    // 确保是完整的标签匹配
    if (start > 0 && domain_buf[start - 1] != '.') {
        return false;
    }

    return true;
}

// ==================== DNS Response Builder ====================

size_t DNSResponseBuilder::buildNXDomain(
    const uint8_t* query,
    size_t query_len,
    const DNSParseResult& parsed,
    uint8_t* response,
    size_t response_buf_size
) {
    if (response_buf_size < parsed.total_consumed) {
        return 0;
    }

    // 复制查询
    std::memcpy(response, query, parsed.total_consumed);

    // 修改标志位: QR=1, AA=0, TC=0, RD=1, RA=1, RCODE=3(NXDOMAIN)
    DNSHeader* hdr = reinterpret_cast<DNSHeader*>(response);
    uint16_t flags = parsed.header->getFlags();
    flags |= 0x8000;  // QR = 1 (response)
    flags |= 0x0080;  // RA = 1
    flags &= 0xFFF0;  // Clear RCODE
    flags |= 0x0003;  // RCODE = 3 (NXDOMAIN)
    hdr->flags = htons(flags);

    // 设置计数
    hdr->an_count = 0;
    hdr->ns_count = 0;
    hdr->ar_count = 0;

    return parsed.total_consumed;
}

size_t DNSResponseBuilder::buildAResponse(
    const uint8_t* query,
    size_t query_len,
    const DNSParseResult& parsed,
    uint32_t ip,
    uint32_t ttl,
    uint8_t* response,
    size_t response_buf_size
) {
    // 需要空间: 查询 + 回答记录 (域名指针2 + 类型2 + 类别2 + TTL4 + 长度2 + IP4 = 16)
    size_t answer_size = 16;
    size_t total_size = parsed.total_consumed + answer_size;

    if (response_buf_size < total_size) {
        return 0;
    }

    // 复制查询
    std::memcpy(response, query, parsed.total_consumed);

    // 修改标志位
    DNSHeader* hdr = reinterpret_cast<DNSHeader*>(response);
    uint16_t flags = parsed.header->getFlags();
    flags |= 0x8000;  // QR = 1
    flags |= 0x0400;  // AA = 1
    flags |= 0x0080;  // RA = 1
    flags &= 0xFFF0;  // RCODE = 0
    hdr->flags = htons(flags);
    hdr->an_count = htons(1);

    // 写入回答记录
    size_t offset = parsed.total_consumed;

    // 域名指针 (指向问题中的域名)
    response[offset++] = 0xC0;
    response[offset++] = DNS_HEADER_SIZE;

    // 类型 A
    *reinterpret_cast<uint16_t*>(response + offset) = htons(dns_type::A);
    offset += 2;

    // 类别 IN
    *reinterpret_cast<uint16_t*>(response + offset) = htons(dns_class::IN);
    offset += 2;

    // TTL
    *reinterpret_cast<uint32_t*>(response + offset) = htonl(ttl);
    offset += 4;

    // RDLENGTH
    *reinterpret_cast<uint16_t*>(response + offset) = htons(4);
    offset += 2;

    // IP 地址
    *reinterpret_cast<uint32_t*>(response + offset) = ip;
    offset += 4;

    return offset;
}

size_t DNSResponseBuilder::buildAAAAResponse(
    const uint8_t* query,
    size_t query_len,
    const DNSParseResult& parsed,
    const uint8_t* ipv6,
    uint32_t ttl,
    uint8_t* response,
    size_t response_buf_size
) {
    // 需要空间: 查询 + 回答记录 (域名指针2 + 类型2 + 类别2 + TTL4 + 长度2 + IPv6 16 = 28)
    size_t answer_size = 28;
    size_t total_size = parsed.total_consumed + answer_size;

    if (response_buf_size < total_size) {
        return 0;
    }

    // 复制查询
    std::memcpy(response, query, parsed.total_consumed);

    // 修改标志位
    DNSHeader* hdr = reinterpret_cast<DNSHeader*>(response);
    uint16_t flags = parsed.header->getFlags();
    flags |= 0x8000;  // QR = 1
    flags |= 0x0400;  // AA = 1
    flags |= 0x0080;  // RA = 1
    flags &= 0xFFF0;  // RCODE = 0
    hdr->flags = htons(flags);
    hdr->an_count = htons(1);

    // 写入回答记录
    size_t offset = parsed.total_consumed;

    // 域名指针 (指向问题中的域名)
    response[offset++] = 0xC0;
    response[offset++] = DNS_HEADER_SIZE;

    // 类型 AAAA (28)
    *reinterpret_cast<uint16_t*>(response + offset) = htons(dns_type::AAAA);
    offset += 2;

    // 类别 IN
    *reinterpret_cast<uint16_t*>(response + offset) = htons(dns_class::IN);
    offset += 2;

    // TTL
    *reinterpret_cast<uint32_t*>(response + offset) = htonl(ttl);
    offset += 4;

    // RDLENGTH (16 for IPv6)
    *reinterpret_cast<uint16_t*>(response + offset) = htons(16);
    offset += 2;

    // IPv6 地址 (16 字节)
    std::memcpy(response + offset, ipv6, 16);
    offset += 16;

    return offset;
}

size_t DNSResponseBuilder::buildRefused(
    const uint8_t* query,
    size_t query_len,
    const DNSParseResult& parsed,
    uint8_t* response,
    size_t response_buf_size
) {
    if (response_buf_size < parsed.total_consumed) {
        return 0;
    }

    std::memcpy(response, query, parsed.total_consumed);

    DNSHeader* hdr = reinterpret_cast<DNSHeader*>(response);
    uint16_t flags = parsed.header->getFlags();
    flags |= 0x8000;  // QR = 1
    flags |= 0x0080;  // RA = 1
    flags &= 0xFFF0;
    flags |= 0x0005;  // RCODE = 5 (REFUSED)
    hdr->flags = htons(flags);

    hdr->an_count = 0;
    hdr->ns_count = 0;
    hdr->ar_count = 0;

    return parsed.total_consumed;
}

} // namespace xdp_dns

