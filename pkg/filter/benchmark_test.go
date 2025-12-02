package filter

import (
	"fmt"
	"testing"

	"xdp-dns/pkg/dns"
)

// BenchmarkTrieMatch Trie匹配基准测试
func BenchmarkTrieMatch(b *testing.B) {
	trie := NewDomainTrie()

	// 插入1000条规则
	for i := 0; i < 1000; i++ {
		domain := fmt.Sprintf("domain%d.example.com", i)
		rule := &Rule{
			ID:      fmt.Sprintf("rule%d", i),
			Action:  ActionBlock,
			Enabled: true,
		}
		trie.Insert(domain, rule)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = trie.Match("domain500.example.com")
	}
}

// BenchmarkTrieMatchWildcard 通配符匹配
func BenchmarkTrieMatchWildcard(b *testing.B) {
	trie := NewDomainTrie()

	rule := &Rule{
		ID:      "wildcard",
		Action:  ActionBlock,
		Enabled: true,
	}
	trie.Insert("*.example.com", rule)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = trie.Match("sub.domain.example.com")
	}
}

// BenchmarkEngineCheck 引擎检查
func BenchmarkEngineCheck(b *testing.B) {
	engine, _ := NewEngine("")

	// 添加规则
	for i := 0; i < 100; i++ {
		engine.AddRule(Rule{
			ID:       fmt.Sprintf("rule%d", i),
			Priority: i,
			Enabled:  true,
			Action:   ActionBlock,
			Domains:  []string{fmt.Sprintf("domain%d.example.com", i)},
		})
	}

	// 添加通配符规则
	engine.AddRule(Rule{
		ID:       "wildcard",
		Priority: 1000,
		Enabled:  true,
		Action:   ActionLog,
		Domains:  []string{"*.test.com"},
	})

	msg := &dns.Message{
		Header: dns.Header{
			ID:      0x1234,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []dns.Question{
			{
				Name:   "domain50.example.com",
				QType:  dns.TypeA,
				QClass: dns.ClassIN,
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = engine.Check(msg, "192.168.1.1")
	}
}

// BenchmarkEngineCheckWildcard 通配符检查
func BenchmarkEngineCheckWildcard(b *testing.B) {
	engine, _ := NewEngine("")

	engine.AddRule(Rule{
		ID:       "wildcard",
		Priority: 100,
		Enabled:  true,
		Action:   ActionBlock,
		Domains:  []string{"*.example.com"},
	})

	msg := &dns.Message{
		Header: dns.Header{
			ID:      0x1234,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []dns.Question{
			{
				Name:   "sub.domain.example.com",
				QType:  dns.TypeA,
				QClass: dns.ClassIN,
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = engine.Check(msg, "192.168.1.1")
	}
}

