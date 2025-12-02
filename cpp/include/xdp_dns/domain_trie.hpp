#pragma once

#include "common.hpp"
#include <string>
#include <unordered_map>
#include <memory>
#include <shared_mutex>
#include <vector>
#include <atomic>
#include <mutex>

namespace xdp_dns {

// Trie 节点
struct TrieNode {
    std::unordered_map<std::string, std::unique_ptr<TrieNode>> children;
    const Rule* exact_rule = nullptr;     // 精确匹配规则
    const Rule* wildcard_rule = nullptr;  // 通配符规则
    
    TrieNode() = default;
};

// 域名 Trie - 线程安全
class DomainTrie {
public:
    DomainTrie();
    ~DomainTrie() = default;
    
    // 禁止拷贝
    DomainTrie(const DomainTrie&) = delete;
    DomainTrie& operator=(const DomainTrie&) = delete;
    
    // 插入规则
    void insert(const char* domain, size_t domain_len, const Rule* rule);
    void insert(const std::string& domain, const Rule* rule);
    
    // 匹配域名
    const Rule* match(const char* domain, size_t domain_len) const;
    const Rule* match(const std::string& domain) const;
    
    // 删除规则
    bool remove(const char* domain, size_t domain_len);
    bool remove(const std::string& domain);
    
    // 清空所有规则
    void clear();
    
    // 获取规则数量
    size_t size() const;
    
    // 批量更新规则 (最小化锁时间)
    void updateRules(const std::vector<std::pair<std::string, Rule>>& rules);

private:
    // 将域名分割为标签并反转
    static std::vector<std::string> splitAndReverse(const char* domain, size_t len);
    
    // 内部匹配实现 (无锁)
    const Rule* matchImpl(const TrieNode* node, 
                          const std::vector<std::string>& labels) const;
    
    // 内部插入实现 (无锁)
    void insertImpl(TrieNode* node, 
                    const std::vector<std::string>& labels,
                    bool is_wildcard,
                    const Rule* rule);

    mutable std::shared_mutex mutex_;
    std::unique_ptr<TrieNode> root_;
    size_t rule_count_;
    
    // 规则存储 (保持规则生命周期)
    std::vector<std::unique_ptr<Rule>> rules_storage_;
};

// 过滤引擎 - 组合 Trie 和其他匹配逻辑
class FilterEngine {
public:
    FilterEngine();
    ~FilterEngine() = default;

    // 加载规则
    Error loadRules(const char* yaml_content, size_t len);

    // 检查域名
    FilterResult check(const char* domain, size_t domain_len, uint16_t qtype) const;

    // 添加单条规则
    void addRule(const Rule& rule, const char* domain, size_t domain_len);

    // 删除规则
    bool removeRule(const char* rule_id);

    // 获取统计
    struct Stats {
        uint64_t total_checks;
        uint64_t allowed;
        uint64_t blocked;
        uint64_t redirected;
        uint64_t logged;
    };
    Stats getStats() const;
    void resetStats();

private:
    DomainTrie trie_;

    // 规则存储 (保持规则生命周期)
    mutable std::mutex rules_mutex_;
    std::vector<std::unique_ptr<Rule>> rules_storage_;

    // 统计计数器 (原子操作)
    mutable std::atomic<uint64_t> total_checks_{0};
    mutable std::atomic<uint64_t> allowed_{0};
    mutable std::atomic<uint64_t> blocked_{0};
    mutable std::atomic<uint64_t> redirected_{0};
    mutable std::atomic<uint64_t> logged_{0};
};

} // namespace xdp_dns

