package dns

import (
	"testing"
)

// 构建测试 DNS 查询包
func buildTestQuery(domain string) []byte {
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
	packet = append(packet, 0) // 结束符

	// 类型和类别
	packet = append(packet, 0x00, 0x01) // Type A
	packet = append(packet, 0x00, 0x01) // Class IN

	return packet
}

// BenchmarkDNSParse DNS解析基准测试
func BenchmarkDNSParse(b *testing.B) {
	packet := buildTestQuery("www.example.com")
	parser := NewParser()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(packet)
	}
}

// BenchmarkDNSParseLongDomain 长域名解析
func BenchmarkDNSParseLongDomain(b *testing.B) {
	packet := buildTestQuery("subdomain.sub.example.com")
	parser := NewParser()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(packet)
	}
}

// BenchmarkDNSParseAndExtract 解析并提取域名
func BenchmarkDNSParseAndExtract(b *testing.B) {
	packet := buildTestQuery("malware.threat.example.com")
	parser := NewParser()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := parser.Parse(packet)
		_ = msg.GetQueryDomain()
		_ = msg.GetQueryType()
	}
}
