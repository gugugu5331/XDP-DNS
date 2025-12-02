package filter

import (
	"testing"

	"xdp-dns/pkg/dns"
)

func TestEngine_Check(t *testing.T) {
	engine, _ := NewEngine("")

	// 添加测试规则
	engine.AddRule(Rule{
		ID:       "block-ads",
		Priority: 100,
		Enabled:  true,
		Action:   ActionBlock,
		Domains:  []string{"*.ads.com", "ads.example.com"},
	})

	engine.AddRule(Rule{
		ID:       "allow-all",
		Priority: 10,
		Enabled:  true,
		Action:   ActionAllow,
		Domains:  []string{"*"},
	})

	tests := []struct {
		name       string
		domain     string
		wantAction Action
	}{
		{"blocked wildcard", "test.ads.com", ActionBlock},
		{"blocked exact", "ads.example.com", ActionBlock},
		{"allowed domain", "google.com", ActionAllow},
		{"allowed subdomain", "www.google.com", ActionAllow},
	}

	parser := dns.NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 构建测试 DNS 消息
			msg := createTestDNSMessage(tt.domain)

			action, _ := engine.Check(msg, "192.168.1.1")
			if action != tt.wantAction {
				t.Errorf("Check() action = %v, want %v", action, tt.wantAction)
			}
		})
	}

	_ = parser // 避免未使用警告
}

func TestDomainTrie(t *testing.T) {
	trie := NewDomainTrie()

	rule1 := &Rule{ID: "rule1", Action: ActionBlock}
	rule2 := &Rule{ID: "rule2", Action: ActionRedirect}

	trie.Insert("example.com", rule1)
	trie.Insert("*.test.com", rule2)

	tests := []struct {
		domain string
		wantID string
	}{
		{"example.com", "rule1"},
		{"www.test.com", "rule2"},
		{"sub.test.com", "rule2"},
		{"unknown.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			rule := trie.Match(tt.domain)
			if tt.wantID == "" {
				if rule != nil {
					t.Errorf("Match(%s) = %v, want nil", tt.domain, rule.ID)
				}
			} else {
				if rule == nil || rule.ID != tt.wantID {
					var gotID string
					if rule != nil {
						gotID = rule.ID
					}
					t.Errorf("Match(%s) = %v, want %v", tt.domain, gotID, tt.wantID)
				}
			}
		})
	}
}

func TestMatchDomainPattern(t *testing.T) {
	tests := []struct {
		domain  string
		pattern string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "*.com", true}, // *.com 匹配所有 .com 域名
		{"sub.example.com", "*.example.com", true},
		{"example.com", "*.example.com", true}, // 也匹配根域名
		{"test.com", "*", true},
		{"any.thing.com", "*", true},
		{"example.org", "*.com", false}, // 不同 TLD 不匹配
	}

	for _, tt := range tests {
		t.Run(tt.domain+"_"+tt.pattern, func(t *testing.T) {
			got := matchDomainPattern(tt.domain, tt.pattern)
			if got != tt.want {
				t.Errorf("matchDomainPattern(%s, %s) = %v, want %v",
					tt.domain, tt.pattern, got, tt.want)
			}
		})
	}
}

// createTestDNSMessage 创建测试用 DNS 消息
func createTestDNSMessage(domain string) *dns.Message {
	return &dns.Message{
		Header: dns.Header{
			ID:      0x1234,
			Flags:   0x0100, // Query
			QDCount: 1,
		},
		Questions: []dns.Question{
			{
				Name:   domain,
				QType:  dns.TypeA,
				QClass: dns.ClassIN,
			},
		},
	}
}

func BenchmarkEngine_Check(b *testing.B) {
	engine, _ := NewEngine("")
	engine.AddRule(Rule{
		ID:      "block",
		Enabled: true,
		Action:  ActionBlock,
		Domains: []string{"*.blocked.com"},
	})

	msg := createTestDNSMessage("test.blocked.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Check(msg, "192.168.1.1")
	}
}
