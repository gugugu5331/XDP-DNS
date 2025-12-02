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

// BenchmarkGoE2E_ThreatDetect 威胁检测 - 检测到威胁
func BenchmarkGoE2E_ThreatDetect(b *testing.B) {
	engine, _ := filter.NewEngine("")
	engine.AddRule(filter.Rule{
		ID:       "threat-malware",
		Priority: 100,
		Enabled:  true,
		Action:   filter.ActionBlock,
		Domains:  []string{"*.malware.com"},
	})

	parser := dns.NewParser()
	packet := buildE2ETestQuery("c2.malware.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := parser.Parse(packet)
		action, _ := engine.Check(msg, "192.168.1.1")
		// 威胁分析系统只检测，不构建响应
		_ = action
	}
}

// BenchmarkGoE2E_SuspiciousLog 可疑流量检测 - 记录日志
func BenchmarkGoE2E_SuspiciousLog(b *testing.B) {
	engine, _ := filter.NewEngine("")
	engine.AddRule(filter.Rule{
		ID:       "suspicious-dyndns",
		Priority: 100,
		Enabled:  true,
		Action:   filter.ActionLog,
		Domains:  []string{"*.dyndns.org"},
	})

	parser := dns.NewParser()
	packet := buildE2ETestQuery("host.dyndns.org")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := parser.Parse(packet)
		action, _ := engine.Check(msg, "192.168.1.1")
		_ = action
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
