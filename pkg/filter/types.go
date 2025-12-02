package filter

import "net"

// Action 过滤动作
type Action int

const (
	ActionAllow    Action = iota // 允许通过
	ActionBlock                  // 阻止
	ActionRedirect               // 重定向
	ActionLog                    // 仅记录日志
)

// String 返回动作名称
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionRedirect:
		return "redirect"
	case ActionLog:
		return "log"
	default:
		return "unknown"
	}
}

// Rule 过滤规则
type Rule struct {
	ID          string   `yaml:"id"`           // 规则ID
	Priority    int      `yaml:"priority"`     // 优先级 (越大越优先)
	Enabled     bool     `yaml:"enabled"`      // 是否启用
	Action      Action   `yaml:"action"`       // 动作
	Domains     []string `yaml:"domains"`      // 域名匹配列表 (支持通配符)
	QueryTypes  []uint16 `yaml:"query_types"`  // 查询类型过滤
	RedirectIP  net.IP   `yaml:"redirect_ip"`  // 重定向IP
	RedirectTTL uint32   `yaml:"redirect_ttl"` // 重定向TTL
	Description string   `yaml:"description"`  // 规则描述
}

// RuleSet 规则集配置
type RuleSet struct {
	Rules       []RuleConfig      `yaml:"rules"`        // 规则列表
	IPBlacklist []string          `yaml:"ip_blacklist"` // IP黑名单
	RateLimits  []RateLimitConfig `yaml:"rate_limits"`  // 速率限制
}

// RuleConfig YAML规则配置
type RuleConfig struct {
	ID          string   `yaml:"id"`
	Priority    int      `yaml:"priority"`
	Enabled     bool     `yaml:"enabled"`
	Action      string   `yaml:"action"`
	Domains     []string `yaml:"domains"`
	QueryTypes  []string `yaml:"query_types"`
	RedirectIP  string   `yaml:"redirect_ip"`
	RedirectTTL uint32   `yaml:"redirect_ttl"`
	Description string   `yaml:"description"`
}

// RateLimitConfig 速率限制配置
type RateLimitConfig struct {
	Source           string `yaml:"source"`             // 来源IP/CIDR
	QueriesPerSecond int    `yaml:"queries_per_second"` // 每秒查询数
	Burst            int    `yaml:"burst"`              // 突发容量
}

// EngineStats 引擎统计信息
type EngineStats struct {
	TotalChecks uint64 // 总检查次数
	Allowed     uint64 // 允许次数
	Blocked     uint64 // 阻止次数
	Redirected  uint64 // 重定向次数
	Logged      uint64 // 日志记录次数
}

// CheckResult 检查结果
type CheckResult struct {
	Action      Action
	Rule        *Rule
	RuleID      string
	MatchedName string
	RedirectIP  []byte // IPv4 或 IPv6
	TTL         uint32
}
