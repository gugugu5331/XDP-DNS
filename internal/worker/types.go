package worker

import (
	"xdp-dns/pkg/dns"
	"xdp-dns/pkg/filter"
	"xdp-dns/pkg/metrics"
	"xdp-dns/xdp"
)

// Packet 表示接收到的数据包
type Packet struct {
	Desc xdp.Desc // XDP 描述符
	Data []byte   // 数据包内容
}

// PoolOptions Worker池配置选项
type PoolOptions struct {
	NumWorkers   int               // Worker数量
	BatchSize    int               // 批处理大小
	Socket       *xdp.Socket       // XDP Socket
	FilterEngine *filter.Engine    // 过滤引擎
	DNSParser    *dns.Parser       // DNS解析器
	Metrics      *metrics.Collector // 指标收集器
}

// PacketInfo 数据包信息
type PacketInfo struct {
	SrcMAC  [6]byte
	DstMAC  [6]byte
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	IsIPv6  bool
}

