package benchmark

import (
	"fmt"
	"testing"

	"xdp-dns/pkg/dns"
	"xdp-dns/pkg/filter"
)

// 构建测试 DNS 查询包
func buildE2ETestQuery(domain string) []byte {
	packet := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags (standard query)
		0x00, 0x01, // QDCount = 1
		0x00, 0x00, // ANCount = 0
		0x00, 0x00, // NSCount = 0
		0x00, 0x00, // ARCount = 0
	}

	// 编码域名
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			length := i - start
			packet = append(packet, byte(length))
			packet = append(packet, []byte(domain[start:i])...)
			start = i + 1
		}
	}
	packet = append(packet, 0)          // 结束符
	packet = append(packet, 0x00, 0x01) // Type A
	packet = append(packet, 0x00, 0x01) // Class IN

	return packet
}

// BenchmarkGoE2E_Allow 纯 Go 端到端 - 放行
func BenchmarkGoE2E_Allow(b *testing.B) {
	engine, _ := filter.NewEngine("")
	parser := dns.NewParser()
	packet := buildE2ETestQuery("allowed.example.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := parser.Parse(packet)
		_, _ = engine.Check(msg, "192.168.1.1")
	}
}

// BenchmarkGoE2E_Block 纯 Go 端到端 - 阻止 + 响应构建
func BenchmarkGoE2E_Block(b *testing.B) {
	engine, _ := filter.NewEngine("")
	engine.AddRule(filter.Rule{
		ID:       "block",
		Priority: 100,
		Enabled:  true,
		Action:   filter.ActionBlock,
		Domains:  []string{"*.block.com"},
	})

	parser := dns.NewParser()
	packet := buildE2ETestQuery("test.block.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := parser.Parse(packet)
		action, _ := engine.Check(msg, "192.168.1.1")
		if action == filter.ActionBlock {
			_ = dns.BuildNXDomainResponse(msg)
		}
	}
}

// BenchmarkGoE2E_Redirect 纯 Go 端到端 - 重定向 + 响应构建
func BenchmarkGoE2E_Redirect(b *testing.B) {
	engine, _ := filter.NewEngine("")
	engine.AddRule(filter.Rule{
		ID:         "redirect",
		Priority:   100,
		Enabled:    true,
		Action:     filter.ActionRedirect,
		Domains:    []string{"*.redirect.com"},
		RedirectIP: []byte{192, 168, 1, 100},
	})

	parser := dns.NewParser()
	packet := buildE2ETestQuery("test.redirect.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := parser.Parse(packet)
		action, rule := engine.Check(msg, "192.168.1.1")
		if action == filter.ActionRedirect && rule != nil {
			_ = dns.BuildAResponse(msg, rule.RedirectIP, rule.RedirectTTL)
		}
	}
}

// BenchmarkGoE2E_MatchManyRules 纯 Go 端到端 - 大规则集匹配
func BenchmarkGoE2E_MatchManyRules(b *testing.B) {
	engine, _ := filter.NewEngine("")

	// 添加 1000 条规则
	for i := 0; i < 1000; i++ {
		engine.AddRule(filter.Rule{
			ID:       fmt.Sprintf("rule%d", i),
			Priority: i,
			Enabled:  true,
			Action:   filter.ActionBlock,
			Domains:  []string{fmt.Sprintf("domain%d.example.com", i)},
		})
	}

	parser := dns.NewParser()
	// 匹配中间的规则
	packet := buildE2ETestQuery("domain500.example.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := parser.Parse(packet)
		_, _ = engine.Check(msg, "192.168.1.1")
	}
}
