#include "xdp_dns/domain_trie.hpp"
#include <algorithm>
#include <sstream>

namespace xdp_dns {

// ==================== DomainTrie ====================

DomainTrie::DomainTrie() 
    : root_(std::make_unique<TrieNode>()), rule_count_(0) {}

void DomainTrie::insert(const char* domain, size_t domain_len, const Rule* rule) {
    if (!domain || domain_len == 0 || !rule) return;
    
    std::unique_lock lock(mutex_);
    
    std::string dom(domain, domain_len);
    
    // 检查是否是通配符规则
    bool is_wildcard = false;
    if (domain_len > 2 && domain[0] == '*' && domain[1] == '.') {
        is_wildcard = true;
        dom = dom.substr(2);
    }
    
    // 转小写
    std::transform(dom.begin(), dom.end(), dom.begin(), ::tolower);
    
    auto labels = splitAndReverse(dom.c_str(), dom.size());
    insertImpl(root_.get(), labels, is_wildcard, rule);
    rule_count_++;
}

void DomainTrie::insert(const std::string& domain, const Rule* rule) {
    insert(domain.c_str(), domain.size(), rule);
}

const Rule* DomainTrie::match(const char* domain, size_t domain_len) const {
    if (!domain || domain_len == 0) return nullptr;
    
    std::shared_lock lock(mutex_);
    
    std::string dom(domain, domain_len);
    std::transform(dom.begin(), dom.end(), dom.begin(), ::tolower);
    
    auto labels = splitAndReverse(dom.c_str(), dom.size());
    return matchImpl(root_.get(), labels);
}

const Rule* DomainTrie::match(const std::string& domain) const {
    return match(domain.c_str(), domain.size());
}

bool DomainTrie::remove(const char* domain, size_t domain_len) {
    if (!domain || domain_len == 0) return false;
    
    std::unique_lock lock(mutex_);
    
    std::string dom(domain, domain_len);
    bool is_wildcard = false;
    if (domain_len > 2 && domain[0] == '*' && domain[1] == '.') {
        is_wildcard = true;
        dom = dom.substr(2);
    }
    
    std::transform(dom.begin(), dom.end(), dom.begin(), ::tolower);
    auto labels = splitAndReverse(dom.c_str(), dom.size());
    
    TrieNode* node = root_.get();
    for (const auto& label : labels) {
        auto it = node->children.find(label);
        if (it == node->children.end()) {
            return false;
        }
        node = it->second.get();
    }
    
    if (is_wildcard) {
        if (node->wildcard_rule) {
            node->wildcard_rule = nullptr;
            rule_count_--;
            return true;
        }
    } else {
        if (node->exact_rule) {
            node->exact_rule = nullptr;
            rule_count_--;
            return true;
        }
    }
    
    return false;
}

bool DomainTrie::remove(const std::string& domain) {
    return remove(domain.c_str(), domain.size());
}

void DomainTrie::clear() {
    std::unique_lock lock(mutex_);
    root_ = std::make_unique<TrieNode>();
    rule_count_ = 0;
    rules_storage_.clear();
}

size_t DomainTrie::size() const {
    std::shared_lock lock(mutex_);
    return rule_count_;
}

std::vector<std::string> DomainTrie::splitAndReverse(const char* domain, size_t len) {
    std::vector<std::string> labels;
    std::string current;
    
    for (size_t i = 0; i < len; i++) {
        if (domain[i] == '.') {
            if (!current.empty()) {
                labels.push_back(std::move(current));
                current.clear();
            }
        } else {
            current += domain[i];
        }
    }
    
    if (!current.empty()) {
        labels.push_back(std::move(current));
    }
    
    // 反转
    std::reverse(labels.begin(), labels.end());
    return labels;
}

const Rule* DomainTrie::matchImpl(
    const TrieNode* node,
    const std::vector<std::string>& labels
) const {
    const Rule* matched_wildcard = nullptr;
    
    for (const auto& label : labels) {
        // 检查当前节点的通配符规则
        if (node->wildcard_rule) {
            matched_wildcard = node->wildcard_rule;
        }
        
        auto it = node->children.find(label);
        if (it == node->children.end()) {
            return matched_wildcard;
        }
        node = it->second.get();
    }
    
    // 检查最终节点
    if (node->exact_rule) {
        return node->exact_rule;
    }
    if (node->wildcard_rule) {
        return node->wildcard_rule;
    }
    
    return matched_wildcard;
}

void DomainTrie::insertImpl(
    TrieNode* node,
    const std::vector<std::string>& labels,
    bool is_wildcard,
    const Rule* rule
) {
    for (const auto& label : labels) {
        auto& child = node->children[label];
        if (!child) {
            child = std::make_unique<TrieNode>();
        }
        node = child.get();
    }
    
    if (is_wildcard) {
        node->wildcard_rule = rule;
    } else {
        node->exact_rule = rule;
    }
}

} // namespace xdp_dns
