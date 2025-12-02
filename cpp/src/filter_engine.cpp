#include "xdp_dns/domain_trie.hpp"

namespace xdp_dns {

// ==================== FilterEngine ====================

FilterEngine::FilterEngine() = default;

FilterResult FilterEngine::check(
    const char* domain,
    size_t domain_len,
    uint16_t qtype
) const {
    total_checks_.fetch_add(1, std::memory_order_relaxed);
    
    const Rule* rule = trie_.match(domain, domain_len);
    
    if (!rule) {
        allowed_.fetch_add(1, std::memory_order_relaxed);
        return FilterResult(Action::Allow);
    }
    
    // 更新统计
    switch (rule->action) {
        case Action::Block:
            blocked_.fetch_add(1, std::memory_order_relaxed);
            break;
        case Action::Redirect:
            redirected_.fetch_add(1, std::memory_order_relaxed);
            break;
        case Action::Log:
            logged_.fetch_add(1, std::memory_order_relaxed);
            break;
        default:
            allowed_.fetch_add(1, std::memory_order_relaxed);
            break;
    }
    
    return FilterResult(rule->action, rule);
}

void FilterEngine::addRule(
    const Rule& rule,
    const char* domain,
    size_t domain_len
) {
    // 创建规则副本并存储
    auto rule_copy = std::make_unique<Rule>(rule);
    const Rule* rule_ptr = rule_copy.get();

    {
        std::lock_guard<std::mutex> lock(rules_mutex_);
        rules_storage_.push_back(std::move(rule_copy));
    }

    // 插入到 Trie
    trie_.insert(domain, domain_len, rule_ptr);
}

FilterEngine::Stats FilterEngine::getStats() const {
    return Stats{
        total_checks_.load(std::memory_order_relaxed),
        allowed_.load(std::memory_order_relaxed),
        blocked_.load(std::memory_order_relaxed),
        redirected_.load(std::memory_order_relaxed),
        logged_.load(std::memory_order_relaxed)
    };
}

void FilterEngine::resetStats() {
    total_checks_.store(0, std::memory_order_relaxed);
    allowed_.store(0, std::memory_order_relaxed);
    blocked_.store(0, std::memory_order_relaxed);
    redirected_.store(0, std::memory_order_relaxed);
    logged_.store(0, std::memory_order_relaxed);
}

} // namespace xdp_dns

