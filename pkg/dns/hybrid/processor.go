// Package hybrid 实现混合架构 DNS 威胁流量分析处理器
//
// 架构:
// ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
// │ DNS Packet  │────▶│  C++ Parse  │────▶│  Go Match   │
// └─────────────┘     │   (12ns)    │     │  (187ns)    │
//
//	└─────────────┘     └──────┬──────┘
//	                           │
//	                    ┌──────▼──────┐
//	                    │   Threat    │
//	                    │  Detection  │
//	                    └─────────────┘
//
// 威胁分析系统只检测，不构建响应
// 总延迟: ~200ns, 吞吐量: ~5M PPS
package hybrid

import (
	"sync"

	"xdp-dns/pkg/dns/cppbridge"
	"xdp-dns/pkg/filter"
)

// Processor 混合架构威胁分析处理器
type Processor struct {
	engine *filter.Engine
	mu     sync.RWMutex

	// 统计
	processed   uint64
	allowed     uint64 // 正常流量
	blocked     uint64 // 威胁流量
	logged      uint64 // 可疑流量
	parseErrors uint64
}

// NewProcessor 创建新的混合处理器
func NewProcessor(engine *filter.Engine) (*Processor, error) {
	// 初始化 C++ 库
	if err := cppbridge.Init(); err != nil {
		return nil, err
	}

	return &Processor{
		engine: engine,
	}, nil
}

// Close 关闭处理器
func (p *Processor) Close() {
	cppbridge.Cleanup()
}

// ProcessResult 处理结果
type ProcessResult struct {
	Action   filter.Action
	Response []byte
	Domain   string
	RuleID   string
}

// Process 处理 DNS 数据包进行威胁分析
// 返回检测结果 (威胁分析系统不构建响应)
func (p *Processor) Process(packet []byte) (*ProcessResult, error) {
	// Step 1: C++ 高性能解析 (12ns)
	parsed, err := cppbridge.Parse(packet)
	if err != nil {
		p.parseErrors++
		return nil, err
	}

	// Step 2: Go Trie 匹配 (187ns) - Go 比 C++ 快 2-3x
	result, err := p.engine.CheckDomain(parsed.Domain, parsed.QType)
	if err != nil {
		return &ProcessResult{
			Action: filter.ActionAllow,
			Domain: parsed.Domain,
		}, nil
	}

	p.processed++
	pr := &ProcessResult{
		Action: result.Action,
		Domain: parsed.Domain,
		RuleID: result.RuleID,
	}

	// 威胁检测统计 (不构建响应)
	switch result.Action {
	case filter.ActionAllow:
		p.allowed++ // 正常流量

	case filter.ActionBlock:
		p.blocked++ // 威胁流量

	case filter.ActionLog:
		p.logged++ // 可疑流量
	}

	return pr, nil
}

// Stats 获取处理器统计
func (p *Processor) Stats() ProcessorStats {
	cppStats := cppbridge.GetStats()

	return ProcessorStats{
		Processed:     p.processed,
		Allowed:       p.allowed,
		Blocked:       p.blocked,
		Logged:        p.logged,
		ParseErrors:   p.parseErrors,
		CPPParseCount: cppStats.PacketsParsed,
	}
}

// ProcessorStats 威胁分析处理器统计
type ProcessorStats struct {
	Processed     uint64 // 总处理数
	Allowed       uint64 // 正常流量
	Blocked       uint64 // 威胁流量
	Logged        uint64 // 可疑流量
	ParseErrors   uint64 // 解析错误
	CPPParseCount uint64 // C++ 解析计数
}
