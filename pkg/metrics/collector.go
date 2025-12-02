// Package metrics 提供威胁流量分析的指标收集
package metrics

import (
	"sync/atomic"
)

// Collector 指标收集器
type Collector struct {
	received    uint64 // 接收的DNS包数
	allowed     uint64 // 正常流量数量
	blocked     uint64 // 威胁流量数量
	logged      uint64 // 可疑流量数量
	dropped     uint64 // 丢弃的数量
	parseErrors uint64 // 解析错误数量
}

// NewCollector 创建新的指标收集器
func NewCollector() *Collector {
	return &Collector{}
}

// IncReceived 增加接收计数
func (c *Collector) IncReceived() {
	atomic.AddUint64(&c.received, 1)
}

// IncAllowed 增加正常流量计数
func (c *Collector) IncAllowed() {
	atomic.AddUint64(&c.allowed, 1)
}

// IncBlocked 增加威胁流量计数
func (c *Collector) IncBlocked() {
	atomic.AddUint64(&c.blocked, 1)
}

// IncLogged 增加可疑流量计数
func (c *Collector) IncLogged() {
	atomic.AddUint64(&c.logged, 1)
}

// IncDropped 增加丢弃计数
func (c *Collector) IncDropped() {
	atomic.AddUint64(&c.dropped, 1)
}

// IncParseError 增加解析错误计数
func (c *Collector) IncParseError() {
	atomic.AddUint64(&c.parseErrors, 1)
}

// Stats 统计信息
type Stats struct {
	Received    uint64 `json:"received"`     // 总接收
	Allowed     uint64 `json:"allowed"`      // 正常流量
	Blocked     uint64 `json:"blocked"`      // 威胁流量
	Logged      uint64 `json:"logged"`       // 可疑流量
	Dropped     uint64 `json:"dropped"`      // 丢弃
	ParseErrors uint64 `json:"parse_errors"` // 解析错误
}

// GetStats 获取当前统计
func (c *Collector) GetStats() Stats {
	return Stats{
		Received:    atomic.LoadUint64(&c.received),
		Allowed:     atomic.LoadUint64(&c.allowed),
		Blocked:     atomic.LoadUint64(&c.blocked),
		Logged:      atomic.LoadUint64(&c.logged),
		Dropped:     atomic.LoadUint64(&c.dropped),
		ParseErrors: atomic.LoadUint64(&c.parseErrors),
	}
}

// Reset 重置所有计数器
func (c *Collector) Reset() {
	atomic.StoreUint64(&c.received, 0)
	atomic.StoreUint64(&c.allowed, 0)
	atomic.StoreUint64(&c.blocked, 0)
	atomic.StoreUint64(&c.logged, 0)
	atomic.StoreUint64(&c.dropped, 0)
	atomic.StoreUint64(&c.parseErrors, 0)
}
