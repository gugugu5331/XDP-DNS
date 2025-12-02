package filter

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"

	"xdp-dns/pkg/dns"
)

// Engine 过滤引擎
type Engine struct {
	rules      []Rule
	domainTrie *DomainTrie
	mu         sync.RWMutex
	stats      EngineStats
}

// NewEngine 创建新的过滤引擎
func NewEngine(rulesPath string) (*Engine, error) {
	e := &Engine{
		domainTrie: NewDomainTrie(),
		rules:      make([]Rule, 0),
	}

	if rulesPath != "" {
		if err := e.LoadRules(rulesPath); err != nil {
			return nil, err
		}
	}

	return e, nil
}

// LoadRules 从文件加载规则
func (e *Engine) LoadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %w", err)
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// 清空现有规则
	e.rules = make([]Rule, 0, len(ruleSet.Rules))
	e.domainTrie = NewDomainTrie()

	// 加载规则
	for _, rc := range ruleSet.Rules {
		rule := e.convertRuleConfig(rc)
		e.addRuleInternal(rule)
	}

	// 按优先级排序 (高优先级在前)
	sort.Slice(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})

	return nil
}

// convertRuleConfig 转换规则配置
func (e *Engine) convertRuleConfig(rc RuleConfig) Rule {
	rule := Rule{
		ID:          rc.ID,
		Priority:    rc.Priority,
		Enabled:     rc.Enabled,
		Domains:     rc.Domains,
		RedirectTTL: rc.RedirectTTL,
		Description: rc.Description,
	}

	// 转换动作
	switch strings.ToLower(rc.Action) {
	case "block":
		rule.Action = ActionBlock
	case "redirect":
		rule.Action = ActionRedirect
	case "log":
		rule.Action = ActionLog
	default:
		rule.Action = ActionAllow
	}

	// 转换重定向IP
	if rc.RedirectIP != "" {
		rule.RedirectIP = net.ParseIP(rc.RedirectIP)
	}

	// 转换查询类型
	for _, qt := range rc.QueryTypes {
		switch strings.ToUpper(qt) {
		case "A":
			rule.QueryTypes = append(rule.QueryTypes, dns.TypeA)
		case "AAAA":
			rule.QueryTypes = append(rule.QueryTypes, dns.TypeAAAA)
		case "CNAME":
			rule.QueryTypes = append(rule.QueryTypes, dns.TypeCNAME)
		case "MX":
			rule.QueryTypes = append(rule.QueryTypes, dns.TypeMX)
		case "TXT":
			rule.QueryTypes = append(rule.QueryTypes, dns.TypeTXT)
		case "NS":
			rule.QueryTypes = append(rule.QueryTypes, dns.TypeNS)
		case "ANY":
			rule.QueryTypes = append(rule.QueryTypes, dns.TypeANY)
		}
	}

	if rule.RedirectTTL == 0 {
		rule.RedirectTTL = 300 // 默认 5 分钟
	}

	return rule
}

// addRuleInternal 内部添加规则 (无锁)
func (e *Engine) addRuleInternal(rule Rule) {
	e.rules = append(e.rules, rule)

	// 将精确域名添加到 Trie
	for _, domain := range rule.Domains {
		if !strings.HasPrefix(domain, "*") {
			e.domainTrie.Insert(domain, &rule)
		}
	}
}

// Check 检查 DNS 消息
func (e *Engine) Check(msg *dns.Message, srcIP string) (Action, *Rule) {
	atomic.AddUint64(&e.stats.TotalChecks, 1)

	domain := msg.GetQueryDomain()
	qtype := msg.GetQueryType()

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. 精确域名匹配 (Trie 查找)
	if rule := e.domainTrie.Match(domain); rule != nil && rule.Enabled {
		if e.matchQueryType(rule, qtype) {
			e.updateStats(rule.Action)
			return rule.Action, rule
		}
	}

	// 2. 通配符匹配
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if e.matchDomainPatterns(domain, rule.Domains) {
			if e.matchQueryType(rule, qtype) {
				e.updateStats(rule.Action)
				return rule.Action, rule
			}
		}
	}

	atomic.AddUint64(&e.stats.Allowed, 1)
	return ActionAllow, nil
}

// CheckDomain 检查域名 - 用于混合架构
// 接收已解析的域名和查询类型，返回匹配结果
func (e *Engine) CheckDomain(domain string, qtype uint16) (*CheckResult, error) {
	atomic.AddUint64(&e.stats.TotalChecks, 1)

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. 精确域名匹配 (Trie 查找)
	if rule := e.domainTrie.Match(domain); rule != nil && rule.Enabled {
		if e.matchQueryType(rule, qtype) {
			e.updateStats(rule.Action)
			return &CheckResult{
				Action:     rule.Action,
				Rule:       rule,
				RuleID:     rule.ID,
				RedirectIP: rule.RedirectIP,
				TTL:        rule.RedirectTTL,
			}, nil
		}
	}

	// 2. 通配符匹配
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if e.matchDomainPatterns(domain, rule.Domains) {
			if e.matchQueryType(rule, qtype) {
				e.updateStats(rule.Action)
				return &CheckResult{
					Action:     rule.Action,
					Rule:       rule,
					RuleID:     rule.ID,
					RedirectIP: rule.RedirectIP,
					TTL:        rule.RedirectTTL,
				}, nil
			}
		}
	}

	atomic.AddUint64(&e.stats.Allowed, 1)
	return &CheckResult{Action: ActionAllow}, nil
}

// matchDomainPatterns 匹配域名模式列表
func (e *Engine) matchDomainPatterns(domain string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchDomainPattern(domain, pattern) {
			return true
		}
	}
	return false
}

// matchDomainPattern 匹配单个域名模式
func matchDomainPattern(domain, pattern string) bool {
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	// 完全通配符
	if pattern == "*" {
		return true
	}

	// 通配符前缀匹配 (*.example.com)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
	}

	// 精确匹配
	return domain == pattern
}

// matchQueryType 匹配查询类型
func (e *Engine) matchQueryType(rule *Rule, qtype uint16) bool {
	if len(rule.QueryTypes) == 0 {
		return true // 未指定类型则匹配所有
	}

	for _, t := range rule.QueryTypes {
		if t == qtype || t == dns.TypeANY {
			return true
		}
	}
	return false
}

// updateStats 更新统计
func (e *Engine) updateStats(action Action) {
	switch action {
	case ActionBlock:
		atomic.AddUint64(&e.stats.Blocked, 1)
	case ActionRedirect:
		atomic.AddUint64(&e.stats.Redirected, 1)
	case ActionLog:
		atomic.AddUint64(&e.stats.Logged, 1)
	default:
		atomic.AddUint64(&e.stats.Allowed, 1)
	}
}

// AddRule 动态添加规则
func (e *Engine) AddRule(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.addRuleInternal(rule)

	// 重新排序
	sort.Slice(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})
}

// RemoveRule 移除规则
func (e *Engine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, rule := range e.rules {
		if rule.ID == id {
			// 从 Trie 中移除域名
			for _, domain := range rule.Domains {
				e.domainTrie.Remove(domain)
			}
			// 从规则列表中移除
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// GetStats 获取统计信息
func (e *Engine) GetStats() EngineStats {
	return EngineStats{
		TotalChecks: atomic.LoadUint64(&e.stats.TotalChecks),
		Allowed:     atomic.LoadUint64(&e.stats.Allowed),
		Blocked:     atomic.LoadUint64(&e.stats.Blocked),
		Redirected:  atomic.LoadUint64(&e.stats.Redirected),
		Logged:      atomic.LoadUint64(&e.stats.Logged),
	}
}

// GetRules 获取所有规则
func (e *Engine) GetRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, len(e.rules))
	copy(rules, e.rules)
	return rules
}

// GetRule 获取指定规则
func (e *Engine) GetRule(id string) (*Rule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range e.rules {
		if e.rules[i].ID == id {
			rule := e.rules[i]
			return &rule, true
		}
	}
	return nil, false
}

// EnableRule 启用规则
func (e *Engine) EnableRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.rules {
		if e.rules[i].ID == id {
			e.rules[i].Enabled = true
			return true
		}
	}
	return false
}

// DisableRule 禁用规则
func (e *Engine) DisableRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.rules {
		if e.rules[i].ID == id {
			e.rules[i].Enabled = false
			return true
		}
	}
	return false
}
