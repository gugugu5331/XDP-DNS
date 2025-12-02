package hybrid

import (
	"fmt"
	"testing"

	"xdp-dns/pkg/dns/cppbridge"
	"xdp-dns/pkg/filter"
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
	packet = append(packet, 0x00, 0x01) // Type A
	packet = append(packet, 0x00, 0x01) // Class IN

	return packet
}

func init() {
	cppbridge.Init()
}

// BenchmarkCPPParse C++ DNS 解析
func BenchmarkCPPParse(b *testing.B) {
	packet := buildTestQuery("www.example.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = cppbridge.Parse(packet)
	}
}

// BenchmarkCPPBuildNXDomain C++ NXDOMAIN 响应构建
func BenchmarkCPPBuildNXDomain(b *testing.B) {
	packet := buildTestQuery("blocked.example.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = cppbridge.BuildNXDomain(packet)
	}
}

// BenchmarkCPPBuildAResponse C++ A 记录响应构建
func BenchmarkCPPBuildAResponse(b *testing.B) {
	packet := buildTestQuery("redirect.example.com")
	ip := uint32(0xC0A80164) // 192.168.1.100

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = cppbridge.BuildAResponse(packet, ip, 300)
	}
}

// BenchmarkHybridProcess 混合架构端到端测试
func BenchmarkHybridProcess(b *testing.B) {
	engine, _ := filter.NewEngine("")

	// 添加规则
	for i := 0; i < 100; i++ {
		engine.AddRule(filter.Rule{
			ID:       fmt.Sprintf("rule%d", i),
			Priority: i,
			Enabled:  true,
			Action:   filter.ActionBlock,
			Domains:  []string{fmt.Sprintf("domain%d.example.com", i)},
		})
	}

	processor, err := NewProcessor(engine)
	if err != nil {
		b.Fatal(err)
	}
	defer processor.Close()

	packet := buildTestQuery("domain50.example.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = processor.Process(packet)
	}
}

// BenchmarkHybridProcessAllow 混合架构 - 放行
func BenchmarkHybridProcessAllow(b *testing.B) {
	engine, _ := filter.NewEngine("")
	processor, err := NewProcessor(engine)
	if err != nil {
		b.Fatal(err)
	}
	defer processor.Close()

	packet := buildTestQuery("allowed.example.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = processor.Process(packet)
	}
}

// BenchmarkHybridProcessBlock 混合架构 - 阻止
func BenchmarkHybridProcessBlock(b *testing.B) {
	engine, _ := filter.NewEngine("")
	engine.AddRule(filter.Rule{
		ID:       "block",
		Priority: 100,
		Enabled:  true,
		Action:   filter.ActionBlock,
		Domains:  []string{"*.block.com"},
	})

	processor, err := NewProcessor(engine)
	if err != nil {
		b.Fatal(err)
	}
	defer processor.Close()

	packet := buildTestQuery("test.block.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = processor.Process(packet)
	}
}

