// DNS 流量分析性能测试
package tests

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"xdp-dns/pkg/dns"
	"xdp-dns/pkg/filter"
)

// 构建模拟的完整网络数据包 (ETH + IP + UDP + DNS)
func buildFullDNSPacket(domain string) []byte {
	// 1. 构建 DNS 负载
	dnsPayload := buildDNSPayload(domain)

	// 2. 构建 UDP 头 (8 字节)
	udpLen := uint16(8 + len(dnsPayload))
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 12345)  // 源端口
	binary.BigEndian.PutUint16(udpHeader[2:4], 53)     // 目标端口 (DNS)
	binary.BigEndian.PutUint16(udpHeader[4:6], udpLen) // UDP 长度
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)      // 校验和

	// 3. 构建 IP 头 (20 字节)
	ipLen := uint16(20 + len(udpHeader) + len(dnsPayload))
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // 版本 (4) + IHL (5)
	ipHeader[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(ipHeader[2:4], ipLen)
	binary.BigEndian.PutUint16(ipHeader[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000) // Flags + Fragment
	ipHeader[8] = 64                                  // TTL
	ipHeader[9] = 17                                  // Protocol (UDP)
	// ipHeader[10:12] 校验和 (简化为0)
	copy(ipHeader[12:16], []byte{192, 168, 1, 100}) // 源 IP
	copy(ipHeader[16:20], []byte{8, 8, 8, 8})       // 目标 IP

	// 4. 构建以太网头 (14 字节)
	ethHeader := make([]byte, 14)
	copy(ethHeader[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})  // 目标 MAC
	copy(ethHeader[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // 源 MAC
	binary.BigEndian.PutUint16(ethHeader[12:14], 0x0800)              // EtherType (IPv4)

	// 5. 组装完整数据包
	packet := make([]byte, 0, len(ethHeader)+len(ipHeader)+len(udpHeader)+len(dnsPayload))
	packet = append(packet, ethHeader...)
	packet = append(packet, ipHeader...)
	packet = append(packet, udpHeader...)
	packet = append(packet, dnsPayload...)

	return packet
}

// 构建 DNS 负载
func buildDNSPayload(domain string) []byte {
	payload := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}
	// 编码域名
	for _, part := range strings.Split(domain, ".") {
		payload = append(payload, byte(len(part)))
		payload = append(payload, []byte(part)...)
	}
	payload = append(payload, 0x00)       // 域名结束
	payload = append(payload, 0x00, 0x01) // Type: A
	payload = append(payload, 0x00, 0x01) // Class: IN
	return payload
}

// 从完整数据包中提取 DNS 负载
func extractDNSPayload(packet []byte) []byte {
	// ETH(14) + IP(20) + UDP(8) = 42
	if len(packet) < 42 {
		return nil
	}
	return packet[42:]
}

// BenchmarkFullPipelineParsing 完整流水线解析测试
func BenchmarkFullPipelineParsing(b *testing.B) {
	packet := buildFullDNSPacket("www.example.com")
	parser := dns.NewParser()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dnsPayload := extractDNSPayload(packet)
		_, _ = parser.Parse(dnsPayload)
	}
}

// BenchmarkFullPipelineWithFilter 完整流水线 + 过滤测试
func BenchmarkFullPipelineWithFilter(b *testing.B) {
	packet := buildFullDNSPacket("ads.doubleclick.net")
	parser := dns.NewParser()

	engine, _ := filter.NewEngine("")
	engine.AddRule(filter.Rule{
		ID:       "block_ads",
		Priority: 100,
		Enabled:  true,
		Action:   filter.ActionBlock,
		Domains:  []string{"*.doubleclick.net", "*.ads.com"},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dnsPayload := extractDNSPayload(packet)
		msg, err := parser.Parse(dnsPayload)
		if err != nil {
			continue
		}
		_, _ = engine.Check(msg, "192.168.1.100")
	}
}

// BenchmarkBatchProcessing 批量处理测试
func BenchmarkBatchProcessing(b *testing.B) {
	// 准备不同域名的数据包
	domains := []string{
		"www.google.com",
		"ads.example.com",
		"mail.yahoo.com",
		"tracker.analytics.com",
		"cdn.cloudflare.com",
	}

	packets := make([][]byte, len(domains))
	for i, domain := range domains {
		packets[i] = buildFullDNSPacket(domain)
	}

	parser := dns.NewParser()
	engine, _ := filter.NewEngine("")
	engine.AddRule(filter.Rule{
		ID: "block", Priority: 100, Enabled: true,
		Action: filter.ActionBlock, Domains: []string{"*.ads.com", "*.analytics.com"},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := packets[i%len(packets)]
		dnsPayload := extractDNSPayload(pkt)
		msg, _ := parser.Parse(dnsPayload)
		if msg != nil {
			_, _ = engine.Check(msg, "192.168.1.100")
		}
	}
}

// BenchmarkResponseBuilding 响应构建测试
func BenchmarkResponseBuilding(b *testing.B) {
	packet := buildFullDNSPacket("blocked.example.com")
	parser := dns.NewParser()
	dnsPayload := extractDNSPayload(packet)
	msg, _ := parser.Parse(dnsPayload)

	b.Run("NXDOMAIN", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dns.BuildNXDomainResponse(msg)
		}
	})

	b.Run("ARecord", func(b *testing.B) {
		ip := []byte{127, 0, 0, 1}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dns.BuildAResponse(msg, ip, 300)
		}
	})
}

// TestDNSPerformanceSummary 性能总结测试
func TestDNSPerformanceSummary(t *testing.T) {
	iterations := 100000
	packet := buildFullDNSPacket("test.example.com")
	parser := dns.NewParser()

	engine, _ := filter.NewEngine("")
	for i := 0; i < 1000; i++ {
		engine.AddRule(filter.Rule{
			ID:       fmt.Sprintf("rule_%d", i),
			Priority: i,
			Enabled:  true,
			Action:   filter.ActionBlock,
			Domains:  []string{fmt.Sprintf("domain%d.example.com", i)},
		})
	}

	// 测试 1: 纯 DNS 解析
	start := time.Now()
	for i := 0; i < iterations; i++ {
		dnsPayload := extractDNSPayload(packet)
		_, _ = parser.Parse(dnsPayload)
	}
	parseTime := time.Since(start)
	parseNsPerOp := float64(parseTime.Nanoseconds()) / float64(iterations)

	// 测试 2: 解析 + 过滤
	dnsPayload := extractDNSPayload(packet)
	msg, _ := parser.Parse(dnsPayload)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		_, _ = engine.Check(msg, "192.168.1.100")
	}
	filterTime := time.Since(start)
	filterNsPerOp := float64(filterTime.Nanoseconds()) / float64(iterations)

	// 测试 3: 响应构建
	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = dns.BuildNXDomainResponse(msg)
	}
	buildTime := time.Since(start)
	buildNsPerOp := float64(buildTime.Nanoseconds()) / float64(iterations)

	// 计算吞吐量
	totalNsPerOp := parseNsPerOp + filterNsPerOp + buildNsPerOp
	pps := 1e9 / totalNsPerOp

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              DNS 流量分析性能测试结果                         ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  测试迭代次数: %d                                       ║\n", iterations)
	fmt.Printf("║  规则数量: 1000                                              ║\n")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  DNS 解析:      %8.1f ns/op  (%7.2f M/s)                ║\n", parseNsPerOp, 1e3/parseNsPerOp)
	fmt.Printf("║  规则匹配:      %8.1f ns/op  (%7.2f M/s)                ║\n", filterNsPerOp, 1e3/filterNsPerOp)
	fmt.Printf("║  响应构建:      %8.1f ns/op  (%7.2f M/s)                ║\n", buildNsPerOp, 1e3/buildNsPerOp)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  端到端总计:    %8.1f ns/op                              ║\n", totalNsPerOp)
	fmt.Printf("║  预估吞吐量:    %8.0f PPS (单核)                         ║\n", pps)
	fmt.Printf("║  预估吞吐量:    %8.0f PPS (8核)                          ║\n", pps*8*0.7)
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}
