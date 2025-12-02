#include <benchmark/benchmark.h>
#include "xdp_dns/dns_parser.hpp"
#include "xdp_dns/domain_trie.hpp"
#include <random>
#include <vector>

using namespace xdp_dns;

// 构造 DNS 查询包
std::vector<uint8_t> buildQuery(const std::string& domain) {
    std::vector<uint8_t> packet = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    size_t start = 0;
    for (size_t i = 0; i <= domain.size(); i++) {
        if (i == domain.size() || domain[i] == '.') {
            size_t len = i - start;
            packet.push_back(static_cast<uint8_t>(len));
            for (size_t j = start; j < i; j++) {
                packet.push_back(domain[j]);
            }
            start = i + 1;
        }
    }
    packet.push_back(0);
    packet.insert(packet.end(), {0x00, 0x01, 0x00, 0x01});
    
    return packet;
}

// ==================== DNS 解析基准测试 ====================

static void BM_DNSParse(benchmark::State& state) {
    auto packet = buildQuery("www.example.com");
    
    for (auto _ : state) {
        DNSParseResult result;
        auto err = DNSParser::parse(packet.data(), packet.size(), &result);
        benchmark::DoNotOptimize(err);
        benchmark::DoNotOptimize(result);
    }
    
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DNSParse);

static void BM_DNSDecodeName(benchmark::State& state) {
    auto packet = buildQuery("subdomain.example.com");
    DNSParseResult parsed;
    DNSParser::parse(packet.data(), packet.size(), &parsed);
    
    char domain[256];
    size_t domain_len;
    
    for (auto _ : state) {
        DNSParser::decodeName(
            packet.data(), packet.size(),
            parsed.question.name_offset,
            domain, sizeof(domain), &domain_len
        );
        benchmark::DoNotOptimize(domain);
    }
    
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DNSDecodeName);

static void BM_DNSDomainEquals(benchmark::State& state) {
    auto packet = buildQuery("www.example.com");
    DNSParseResult parsed;
    DNSParser::parse(packet.data(), packet.size(), &parsed);
    
    const char* target = "www.example.com";
    size_t target_len = strlen(target);
    
    for (auto _ : state) {
        bool result = DNSParser::domainEquals(
            packet.data(), packet.size(), parsed.question,
            target, target_len
        );
        benchmark::DoNotOptimize(result);
    }
    
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DNSDomainEquals);

// ==================== 域名 Trie 基准测试 ====================

static void BM_TrieMatch(benchmark::State& state) {
    DomainTrie trie;
    std::vector<Rule> rules(1000);
    
    // 插入 1000 条规则
    for (int i = 0; i < 1000; i++) {
        rules[i].id = i;
        rules[i].action = Action::Block;
        std::string domain = "domain" + std::to_string(i) + ".example.com";
        trie.insert(domain, &rules[i]);
    }
    
    // 添加通配符规则
    Rule wildcard_rule;
    wildcard_rule.action = Action::Log;
    trie.insert("*.test.com", &wildcard_rule);
    
    for (auto _ : state) {
        auto result = trie.match("domain500.example.com");
        benchmark::DoNotOptimize(result);
    }
    
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_TrieMatch);

static void BM_TrieMatchWildcard(benchmark::State& state) {
    DomainTrie trie;
    Rule rule;
    rule.action = Action::Block;
    trie.insert("*.example.com", &rule);
    
    for (auto _ : state) {
        auto result = trie.match("sub.domain.example.com");
        benchmark::DoNotOptimize(result);
    }
    
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_TrieMatchWildcard);

// ==================== 响应构建基准测试 ====================

static void BM_BuildNXDomain(benchmark::State& state) {
    auto query = buildQuery("blocked.example.com");
    DNSParseResult parsed;
    DNSParser::parse(query.data(), query.size(), &parsed);
    
    uint8_t response[512];
    
    for (auto _ : state) {
        size_t len = DNSResponseBuilder::buildNXDomain(
            query.data(), query.size(), parsed,
            response, sizeof(response)
        );
        benchmark::DoNotOptimize(len);
        benchmark::DoNotOptimize(response);
    }
    
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_BuildNXDomain);

static void BM_BuildAResponse(benchmark::State& state) {
    auto query = buildQuery("redirect.example.com");
    DNSParseResult parsed;
    DNSParser::parse(query.data(), query.size(), &parsed);
    
    uint32_t ip = htonl(0xC0A80164);
    uint8_t response[512];
    
    for (auto _ : state) {
        size_t len = DNSResponseBuilder::buildAResponse(
            query.data(), query.size(), parsed,
            ip, 300,
            response, sizeof(response)
        );
        benchmark::DoNotOptimize(len);
    }
    
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_BuildAResponse);

BENCHMARK_MAIN();

