package metrics

import (
	"sync/atomic"
)

// Collector 指标收集器
type Collector struct {
	received    uint64 // 接收的DNS包数
	allowed     uint64 // 允许通过的数量
	blocked     uint64 // 阻止的数量
	redirected  uint64 // 重定向的数量
	logged      uint64 // 记录日志的数量
	dropped     uint64 // 丢弃的数量
	parseErrors uint64 // 解析错误数量
	panics      uint64 // panic 次数
}

// NewCollector 创建新的指标收集器
func NewCollector() *Collector {
	return &Collector{}
}

// IncReceived 增加接收计数
func (c *Collector) IncReceived() {
	atomic.AddUint64(&c.received, 1)
}

// IncAllowed 增加允许计数
func (c *Collector) IncAllowed() {
	atomic.AddUint64(&c.allowed, 1)
}

// IncBlocked 增加阻止计数
func (c *Collector) IncBlocked() {
	atomic.AddUint64(&c.blocked, 1)
}

// IncRedirected 增加重定向计数
func (c *Collector) IncRedirected() {
	atomic.AddUint64(&c.redirected, 1)
}

// IncLogged 增加日志记录计数
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

// IncPanics 增加 panic 计数
func (c *Collector) IncPanics() {
	atomic.AddUint64(&c.panics, 1)
}

// Stats 返回统计信息
type Stats struct {
	Received    uint64 `json:"received"`
	Allowed     uint64 `json:"allowed"`
	Blocked     uint64 `json:"blocked"`
	Redirected  uint64 `json:"redirected"`
	Logged      uint64 `json:"logged"`
	Dropped     uint64 `json:"dropped"`
	ParseErrors uint64 `json:"parse_errors"`
	Panics      uint64 `json:"panics"`
}

// GetStats 获取当前统计
func (c *Collector) GetStats() Stats {
	return Stats{
		Received:    atomic.LoadUint64(&c.received),
		Allowed:     atomic.LoadUint64(&c.allowed),
		Blocked:     atomic.LoadUint64(&c.blocked),
		Redirected:  atomic.LoadUint64(&c.redirected),
		Logged:      atomic.LoadUint64(&c.logged),
		Dropped:     atomic.LoadUint64(&c.dropped),
		ParseErrors: atomic.LoadUint64(&c.parseErrors),
		Panics:      atomic.LoadUint64(&c.panics),
	}
}

// Reset 重置所有计数器
func (c *Collector) Reset() {
	atomic.StoreUint64(&c.received, 0)
	atomic.StoreUint64(&c.allowed, 0)
	atomic.StoreUint64(&c.blocked, 0)
	atomic.StoreUint64(&c.redirected, 0)
	atomic.StoreUint64(&c.logged, 0)
	atomic.StoreUint64(&c.dropped, 0)
	atomic.StoreUint64(&c.parseErrors, 0)
	atomic.StoreUint64(&c.panics, 0)
}

