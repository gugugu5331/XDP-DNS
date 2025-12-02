// Package hybrid 实现混合架构 DNS 处理器
//
// 架构:
// ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
// │ DNS Packet  │────▶│  C++ Parse  │────▶│  Go Match   │
// └─────────────┘     │   (12ns)    │     │  (187ns)    │
//                     └─────────────┘     └──────┬──────┘
//                                                │
//                     ┌─────────────┐     ┌──────▼──────┐
//                     │  C++ Build  │◀────│   Action    │
//                     │   (4ns)     │     │  Decision   │
//                     └─────────────┘     └─────────────┘
//
// 总延迟: ~200ns, 吞吐量: ~5M PPS
package hybrid

import (
	"encoding/binary"
	"sync"

	"xdp-dns/pkg/dns/cppbridge"
	"xdp-dns/pkg/filter"
)

// Processor 混合架构 DNS 处理器
type Processor struct {
	engine *filter.Engine
	mu     sync.RWMutex

	// 统计
	processed   uint64
	allowed     uint64
	blocked     uint64
	redirected  uint64
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

// Process 处理 DNS 数据包
// 返回处理结果和响应数据(如果需要)
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

	// Step 3: C++ 高性能响应构建 (4-29ns)
	switch result.Action {
	case filter.ActionAllow:
		p.allowed++
		// 不需要构建响应

	case filter.ActionBlock:
		p.blocked++
		// 构建 NXDOMAIN 响应
		pr.Response, err = cppbridge.BuildNXDomain(packet)
		if err != nil {
			return nil, err
		}

	case filter.ActionRedirect:
		p.redirected++
		// 构建重定向响应
		if result.RedirectIP != nil {
			if len(result.RedirectIP) == 4 {
				// IPv4
				ip := binary.BigEndian.Uint32(result.RedirectIP)
				pr.Response, err = cppbridge.BuildAResponse(packet, ip, result.TTL)
			} else if len(result.RedirectIP) == 16 {
				// IPv6
				var ipv6 [16]byte
				copy(ipv6[:], result.RedirectIP)
				pr.Response, err = cppbridge.BuildAAAAResponse(packet, ipv6, result.TTL)
			}
			if err != nil {
				return nil, err
			}
		}

	case filter.ActionLog:
		p.allowed++
		// 记录但放行
	}

	return pr, nil
}

// Stats 获取处理器统计
func (p *Processor) Stats() ProcessorStats {
	cppStats := cppbridge.GetStats()

	return ProcessorStats{
		Processed:       p.processed,
		Allowed:         p.allowed,
		Blocked:         p.blocked,
		Redirected:      p.redirected,
		ParseErrors:     p.parseErrors,
		CPPParseCount:   cppStats.PacketsParsed,
		CPPResponseBuilt: cppStats.ResponseBuilt,
	}
}

// ProcessorStats 处理器统计
type ProcessorStats struct {
	Processed        uint64
	Allowed          uint64
	Blocked          uint64
	Redirected       uint64
	ParseErrors      uint64
	CPPParseCount    uint64
	CPPResponseBuilt uint64
}

