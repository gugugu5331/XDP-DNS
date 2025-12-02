// Package filter 提供 DNS 威胁域名过滤引擎
// 核心功能: 基于规则匹配 DNS 查询，判断是否为威胁流量
package filter

// Action 检测动作
type Action int

const (
	ActionAllow Action = iota // 允许通过 (正常流量)
	ActionBlock               // 阻止 (威胁流量)
	ActionLog                 // 仅记录日志 (可疑流量)
)

// String 返回动作名称
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionLog:
		return "log"
	default:
		return "unknown"
	}
}

// Rule 过滤规则
type Rule struct {
	ID          string   `yaml:"id"`          // 规则ID
	Priority    int      `yaml:"priority"`    // 优先级 (越大越优先)
	Enabled     bool     `yaml:"enabled"`     // 是否启用
	Action      Action   `yaml:"action"`      // 动作
	Domains     []string `yaml:"domains"`     // 域名匹配列表 (支持通配符)
	QueryTypes  []uint16 `yaml:"query_types"` // 查询类型过滤
	Description string   `yaml:"description"` // 规则描述
}

// RuleSet 规则集配置
type RuleSet struct {
	Rules       []RuleConfig `yaml:"rules"`        // 规则列表
	IPBlacklist []string     `yaml:"ip_blacklist"` // IP黑名单 (在XDP层实现)
}

// RuleConfig YAML规则配置
type RuleConfig struct {
	ID          string   `yaml:"id"`
	Priority    int      `yaml:"priority"`
	Enabled     bool     `yaml:"enabled"`
	Action      string   `yaml:"action"`
	Domains     []string `yaml:"domains"`
	QueryTypes  []string `yaml:"query_types"`
	Description string   `yaml:"description"`
}

// EngineStats 引擎统计信息
type EngineStats struct {
	TotalChecks uint64 // 总检查次数
	Allowed     uint64 // 允许次数
	Blocked     uint64 // 阻止次数
	Logged      uint64 // 日志记录次数
}

// CheckResult 检查结果
type CheckResult struct {
	Action      Action
	Rule        *Rule
	RuleID      string
	MatchedName string
}
