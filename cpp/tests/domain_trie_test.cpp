#include <gtest/gtest.h>
#include "xdp_dns/domain_trie.hpp"

using namespace xdp_dns;

class DomainTrieTest : public ::testing::Test {
protected:
    DomainTrie trie;
    
    // 创建测试规则
    static Rule makeRule(uint32_t id, Action action, const char* rule_id) {
        Rule rule;
        rule.id = id;
        rule.action = action;
        rule.redirect_ip = 0;
        rule.ttl = 300;
        strncpy(rule.rule_id, rule_id, sizeof(rule.rule_id) - 1);
        return rule;
    }
};

TEST_F(DomainTrieTest, ExactMatch) {
    Rule rule1 = makeRule(1, Action::Block, "rule1");
    trie.insert("example.com", &rule1);
    
    const Rule* matched = trie.match("example.com");
    ASSERT_NE(matched, nullptr);
    EXPECT_EQ(matched->id, 1);
    EXPECT_EQ(matched->action, Action::Block);
    
    // 不匹配子域名
    EXPECT_EQ(trie.match("sub.example.com"), nullptr);
    
    // 不匹配其他域名
    EXPECT_EQ(trie.match("other.com"), nullptr);
}

TEST_F(DomainTrieTest, WildcardMatch) {
    Rule rule1 = makeRule(1, Action::Block, "wildcard");
    trie.insert("*.example.com", &rule1);
    
    // 匹配子域名
    const Rule* matched = trie.match("sub.example.com");
    ASSERT_NE(matched, nullptr);
    EXPECT_EQ(matched->id, 1);
    
    // 匹配多级子域名
    matched = trie.match("a.b.c.example.com");
    ASSERT_NE(matched, nullptr);
    EXPECT_EQ(matched->id, 1);
    
    // 也匹配根域名
    matched = trie.match("example.com");
    EXPECT_NE(matched, nullptr);
}

TEST_F(DomainTrieTest, MixedRules) {
    Rule rule1 = makeRule(1, Action::Block, "exact");
    Rule rule2 = makeRule(2, Action::Redirect, "wildcard");
    
    trie.insert("blocked.example.com", &rule1);
    trie.insert("*.example.com", &rule2);
    
    // 精确匹配优先
    const Rule* matched = trie.match("blocked.example.com");
    ASSERT_NE(matched, nullptr);
    EXPECT_EQ(matched->id, 1);
    
    // 通配符匹配其他子域名
    matched = trie.match("other.example.com");
    ASSERT_NE(matched, nullptr);
    EXPECT_EQ(matched->id, 2);
}

TEST_F(DomainTrieTest, CaseInsensitive) {
    Rule rule1 = makeRule(1, Action::Block, "rule1");
    trie.insert("Example.COM", &rule1);
    
    // 应该匹配不同大小写
    EXPECT_NE(trie.match("example.com"), nullptr);
    EXPECT_NE(trie.match("EXAMPLE.COM"), nullptr);
    EXPECT_NE(trie.match("ExAmPlE.cOm"), nullptr);
}

TEST_F(DomainTrieTest, Remove) {
    Rule rule1 = makeRule(1, Action::Block, "rule1");
    trie.insert("example.com", &rule1);
    
    EXPECT_NE(trie.match("example.com"), nullptr);
    
    bool removed = trie.remove("example.com");
    EXPECT_TRUE(removed);
    
    EXPECT_EQ(trie.match("example.com"), nullptr);
}

TEST_F(DomainTrieTest, Size) {
    EXPECT_EQ(trie.size(), 0);
    
    Rule rule1 = makeRule(1, Action::Block, "rule1");
    Rule rule2 = makeRule(2, Action::Block, "rule2");
    
    trie.insert("a.com", &rule1);
    EXPECT_EQ(trie.size(), 1);
    
    trie.insert("b.com", &rule2);
    EXPECT_EQ(trie.size(), 2);
    
    trie.remove("a.com");
    EXPECT_EQ(trie.size(), 1);
    
    trie.clear();
    EXPECT_EQ(trie.size(), 0);
}

TEST_F(DomainTrieTest, EmptyDomain) {
    Rule rule1 = makeRule(1, Action::Block, "rule1");
    
    // 空域名不应该被插入
    trie.insert("", &rule1);
    EXPECT_EQ(trie.size(), 0);
    
    // 空域名匹配应该返回 nullptr
    EXPECT_EQ(trie.match(""), nullptr);
}

// ==================== FilterEngine Tests ====================

class FilterEngineTest : public ::testing::Test {
protected:
    FilterEngine engine;
};

TEST_F(FilterEngineTest, BasicFiltering) {
    Rule rule;
    rule.action = Action::Block;
    strncpy(rule.rule_id, "test-block", sizeof(rule.rule_id));
    
    engine.addRule(rule, "blocked.com", 11);
    
    auto result = engine.check("blocked.com", 11, dns_type::A);
    EXPECT_EQ(result.action, Action::Block);
    
    result = engine.check("allowed.com", 11, dns_type::A);
    EXPECT_EQ(result.action, Action::Allow);
}

TEST_F(FilterEngineTest, Statistics) {
    Rule rule;
    rule.action = Action::Block;
    engine.addRule(rule, "blocked.com", 11);
    
    engine.check("blocked.com", 11, dns_type::A);
    engine.check("blocked.com", 11, dns_type::A);
    engine.check("allowed.com", 11, dns_type::A);
    
    auto stats = engine.getStats();
    EXPECT_EQ(stats.total_checks, 3);
    EXPECT_EQ(stats.blocked, 2);
    EXPECT_EQ(stats.allowed, 1);
    
    engine.resetStats();
    stats = engine.getStats();
    EXPECT_EQ(stats.total_checks, 0);
}

