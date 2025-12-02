package benchmark

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"xdp-dns/pkg/dns"
	"xdp-dns/pkg/filter"
)

// TestThreatDetectionWithDnsperfQueries 使用 dnsperf 查询文件测试威胁检测
func TestThreatDetectionWithDnsperfQueries(t *testing.T) {
	// 加载规则
	engine, err := filter.NewEngine("../../configs/rules.yaml")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// 读取 dnsperf 查询文件
	queries, err := loadDnsperfQueries("dnsperf_queries.txt")
	if err != nil {
		t.Fatalf("Failed to load queries: %v", err)
	}

	parser := dns.NewParser()

	// 统计
	var allowed, blocked, logged int
	results := make(map[string][]string)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           DNS 威胁检测测试 (使用 dnsperf 查询)               ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	for _, q := range queries {
		// 构建 DNS 查询包
		packet := buildDNSQuery(q.domain, q.qtype)
		msg, err := parser.Parse(packet)
		if err != nil {
			continue
		}

		// 执行威胁检测
		action, rule := engine.Check(msg, "192.168.1.100")

		var ruleID string
		if rule != nil {
			ruleID = rule.ID
		}

		switch action {
		case filter.ActionAllow:
			allowed++
			results["ALLOW"] = append(results["ALLOW"], q.domain)
		case filter.ActionBlock:
			blocked++
			results["BLOCK"] = append(results["BLOCK"], fmt.Sprintf("%s (rule: %s)", q.domain, ruleID))
		case filter.ActionLog:
			logged++
			results["LOG"] = append(results["LOG"], fmt.Sprintf("%s [%s] (rule: %s)", q.domain, q.qtype, ruleID))
		}
	}

	// 打印结果
	fmt.Printf("查询总数: %d\n", len(queries))
	fmt.Println()

	fmt.Printf("✅ 正常流量 (ALLOW): %d\n", allowed)
	fmt.Printf("🚫 威胁流量 (BLOCK): %d\n", blocked)
	fmt.Printf("⚠️  可疑流量 (LOG):   %d\n", logged)
	fmt.Println()

	if len(results["BLOCK"]) > 0 {
		fmt.Println("被阻止的威胁域名:")
		for _, d := range results["BLOCK"] {
			fmt.Printf("  - %s\n", d)
		}
		fmt.Println()
	}

	if len(results["LOG"]) > 0 {
		fmt.Println("被记录的可疑查询:")
		for _, d := range results["LOG"] {
			fmt.Printf("  - %s\n", d)
		}
		fmt.Println()
	}
}

// BenchmarkThreatDetectionDnsperfQueries 威胁检测性能基准测试
func BenchmarkThreatDetectionDnsperfQueries(b *testing.B) {
	engine, _ := filter.NewEngine("../../configs/rules.yaml")
	queries, _ := loadDnsperfQueries("dnsperf_queries.txt")
	parser := dns.NewParser()

	// 预构建查询包
	packets := make([][]byte, len(queries))
	for i, q := range queries {
		packets[i] = buildDNSQuery(q.domain, q.qtype)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx := i % len(packets)
		msg, _ := parser.Parse(packets[idx])
		engine.Check(msg, "192.168.1.100")
	}
}

// BenchmarkThreatDetectionThroughput 吞吐量测试
func BenchmarkThreatDetectionThroughput(b *testing.B) {
	engine, _ := filter.NewEngine("../../configs/rules.yaml")
	queries, _ := loadDnsperfQueries("dnsperf_queries.txt")
	parser := dns.NewParser()

	packets := make([][]byte, len(queries))
	for i, q := range queries {
		packets[i] = buildDNSQuery(q.domain, q.qtype)
	}

	start := time.Now()
	count := 0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % len(packets)
		msg, _ := parser.Parse(packets[idx])
		engine.Check(msg, "192.168.1.100")
		count++
	}

	elapsed := time.Since(start)
	qps := float64(count) / elapsed.Seconds()
	b.ReportMetric(qps, "qps")
}

type dnsQuery struct {
	domain string
	qtype  string
}

func loadDnsperfQueries(filename string) ([]dnsQuery, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var queries []dnsQuery
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			queries = append(queries, dnsQuery{domain: parts[0], qtype: parts[1]})
		}
	}
	return queries, scanner.Err()
}

func buildDNSQuery(domain, qtype string) []byte {
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

	// 查询类型
	var qtypeCode uint16
	switch strings.ToUpper(qtype) {
	case "A":
		qtypeCode = 1
	case "AAAA":
		qtypeCode = 28
	case "TXT":
		qtypeCode = 16
	case "ANY":
		qtypeCode = 255
	case "MX":
		qtypeCode = 15
	case "NS":
		qtypeCode = 2
	default:
		qtypeCode = 1
	}
	packet = append(packet, byte(qtypeCode>>8), byte(qtypeCode&0xFF))
	packet = append(packet, 0x00, 0x01) // Class IN

	return packet
}
