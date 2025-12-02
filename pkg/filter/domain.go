package filter

import (
	"strings"
	"sync"
)

// DomainTrie 域名前缀树 (反向存储域名)
type DomainTrie struct {
	mu       sync.RWMutex
	root     *trieNode
	size     int
}

type trieNode struct {
	children map[string]*trieNode
	rule     *Rule // 如果这是一个完整域名，存储对应规则
	wildcard *Rule // 通配符规则
}

// NewDomainTrie 创建新的域名Trie
func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		root: &trieNode{
			children: make(map[string]*trieNode),
		},
	}
}

// Insert 插入域名规则
func (t *DomainTrie) Insert(domain string, rule *Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}

	// 处理通配符
	isWildcard := strings.HasPrefix(domain, "*.")
	if isWildcard {
		domain = domain[2:] // 移除 "*."
	}

	// 将域名分割为标签并反转 (example.com -> [com, example])
	labels := reverseDomainLabels(domain)
	
	node := t.root
	for _, label := range labels {
		if node.children == nil {
			node.children = make(map[string]*trieNode)
		}
		child, exists := node.children[label]
		if !exists {
			child = &trieNode{
				children: make(map[string]*trieNode),
			}
			node.children[label] = child
		}
		node = child
	}

	if isWildcard {
		node.wildcard = rule
	} else {
		node.rule = rule
	}
	t.size++
}

// Match 匹配域名
func (t *DomainTrie) Match(domain string) *Rule {
	t.mu.RLock()
	defer t.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	labels := reverseDomainLabels(domain)
	
	node := t.root
	var matchedWildcard *Rule

	for _, label := range labels {
		// 检查当前节点的通配符规则
		if node.wildcard != nil {
			matchedWildcard = node.wildcard
		}

		child, exists := node.children[label]
		if !exists {
			// 如果没有找到精确匹配，返回最近匹配的通配符规则
			return matchedWildcard
		}
		node = child
	}

	// 检查最终节点的规则
	if node.rule != nil {
		return node.rule
	}

	// 检查最终节点的通配符
	if node.wildcard != nil {
		return node.wildcard
	}

	return matchedWildcard
}

// Remove 删除域名规则
func (t *DomainTrie) Remove(domain string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	isWildcard := strings.HasPrefix(domain, "*.")
	if isWildcard {
		domain = domain[2:]
	}

	labels := reverseDomainLabels(domain)
	
	node := t.root
	for _, label := range labels {
		child, exists := node.children[label]
		if !exists {
			return false
		}
		node = child
	}

	if isWildcard {
		if node.wildcard != nil {
			node.wildcard = nil
			t.size--
			return true
		}
	} else {
		if node.rule != nil {
			node.rule = nil
			t.size--
			return true
		}
	}

	return false
}

// Size 返回规则数量
func (t *DomainTrie) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.size
}

// reverseDomainLabels 反转域名标签
func reverseDomainLabels(domain string) []string {
	labels := strings.Split(domain, ".")
	// 反转
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels
}

