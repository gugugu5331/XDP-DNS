#include <gtest/gtest.h>
#include "xdp_dns/dns_parser.hpp"

using namespace xdp_dns;

// 构造测试 DNS 查询包
std::vector<uint8_t> buildDNSQuery(const std::string& domain, uint16_t qtype = 1) {
    std::vector<uint8_t> packet;
    
    // 头部
    packet.insert(packet.end(), {
        0x12, 0x34,  // ID
        0x01, 0x00,  // Flags (standard query, RD=1)
        0x00, 0x01,  // QDCount = 1
        0x00, 0x00,  // ANCount = 0
        0x00, 0x00,  // NSCount = 0
        0x00, 0x00   // ARCount = 0
    });
    
    // 域名
    size_t start = 0;
    for (size_t i = 0; i <= domain.size(); i++) {
        if (i == domain.size() || domain[i] == '.') {
            size_t len = i - start;
            packet.push_back(static_cast<uint8_t>(len));
            for (size_t j = start; j < i; j++) {
                packet.push_back(static_cast<uint8_t>(domain[j]));
            }
            start = i + 1;
        }
    }
    packet.push_back(0);  // 结束符
    
    // 类型和类别
    packet.push_back(static_cast<uint8_t>(qtype >> 8));
    packet.push_back(static_cast<uint8_t>(qtype & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x01);  // Class IN
    
    return packet;
}

TEST(DNSParserTest, ParseSimpleQuery) {
    auto packet = buildDNSQuery("example.com");
    
    DNSParseResult result;
    auto err = DNSParser::parse(packet.data(), packet.size(), &result);
    
    ASSERT_EQ(err, Error::Success);
    EXPECT_EQ(result.header->getId(), 0x1234);
    EXPECT_TRUE(result.header->isQuery());
    EXPECT_EQ(result.question.qtype, dns_type::A);
    EXPECT_EQ(result.question.qclass, dns_class::IN);
}

TEST(DNSParserTest, DecodeDomainName) {
    auto packet = buildDNSQuery("www.example.com");
    
    DNSParseResult result;
    auto err = DNSParser::parse(packet.data(), packet.size(), &result);
    ASSERT_EQ(err, Error::Success);
    
    char domain[256];
    size_t domain_len = 0;
    err = DNSParser::decodeName(
        packet.data(), packet.size(),
        result.question.name_offset,
        domain, sizeof(domain), &domain_len
    );
    
    ASSERT_EQ(err, Error::Success);
    EXPECT_EQ(std::string(domain, domain_len), "www.example.com");
}

TEST(DNSParserTest, DomainEquals) {
    auto packet = buildDNSQuery("Example.COM");
    
    DNSParseResult result;
    DNSParser::parse(packet.data(), packet.size(), &result);
    
    // 大小写不敏感比较
    EXPECT_TRUE(DNSParser::domainEquals(
        packet.data(), packet.size(), result.question,
        "example.com", 11
    ));
    
    EXPECT_FALSE(DNSParser::domainEquals(
        packet.data(), packet.size(), result.question,
        "other.com", 9
    ));
}

TEST(DNSParserTest, DomainEndsWith) {
    auto packet = buildDNSQuery("sub.example.com");

    DNSParseResult result;
    DNSParser::parse(packet.data(), packet.size(), &result);

    // 完整域名后缀匹配
    EXPECT_TRUE(DNSParser::domainEndsWith(
        packet.data(), packet.size(), result.question,
        "sub.example.com", 15  // 完整匹配
    ));

    // 测试完整标签匹配
    EXPECT_TRUE(DNSParser::domainEndsWith(
        packet.data(), packet.size(), result.question,
        "example.com", 11  // 完整标签
    ));

    // 不匹配不完整的标签
    EXPECT_FALSE(DNSParser::domainEndsWith(
        packet.data(), packet.size(), result.question,
        "ample.com", 9  // 部分标签，不应匹配
    ));

    EXPECT_FALSE(DNSParser::domainEndsWith(
        packet.data(), packet.size(), result.question,
        "org", 3
    ));
}

TEST(DNSParserTest, PacketTooShort) {
    uint8_t short_packet[] = {0x12, 0x34, 0x01};
    
    DNSParseResult result;
    auto err = DNSParser::parse(short_packet, sizeof(short_packet), &result);
    
    EXPECT_EQ(err, Error::PacketTooShort);
}

TEST(DNSParserTest, BuildNXDomainResponse) {
    auto query = buildDNSQuery("blocked.example.com");
    
    DNSParseResult parsed;
    DNSParser::parse(query.data(), query.size(), &parsed);
    
    uint8_t response[512];
    size_t resp_len = DNSResponseBuilder::buildNXDomain(
        query.data(), query.size(), parsed,
        response, sizeof(response)
    );
    
    EXPECT_GT(resp_len, 0);
    
    // 验证响应
    auto* hdr = reinterpret_cast<const DNSHeader*>(response);
    EXPECT_EQ(hdr->getId(), 0x1234);
    EXPECT_TRUE(hdr->isResponse());
    EXPECT_EQ(hdr->getRCode(), dns_rcode::NXDOMAIN);
}

TEST(DNSParserTest, BuildAResponse) {
    auto query = buildDNSQuery("redirect.example.com");
    
    DNSParseResult parsed;
    DNSParser::parse(query.data(), query.size(), &parsed);
    
    uint32_t ip = htonl(0xC0A80164);  // 192.168.1.100
    uint32_t ttl = 300;
    
    uint8_t response[512];
    size_t resp_len = DNSResponseBuilder::buildAResponse(
        query.data(), query.size(), parsed,
        ip, ttl,
        response, sizeof(response)
    );
    
    EXPECT_GT(resp_len, 0);
    
    auto* hdr = reinterpret_cast<const DNSHeader*>(response);
    EXPECT_TRUE(hdr->isResponse());
    EXPECT_EQ(hdr->getRCode(), dns_rcode::NOERROR);
    EXPECT_EQ(hdr->getANCount(), 1);
}

