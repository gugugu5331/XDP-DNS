package worker

import (
	"xdp-dns/pkg/config"
	"xdp-dns/pkg/dns"
	"xdp-dns/pkg/filter"
	"xdp-dns/pkg/metrics"
	"xdp-dns/xdp"
)

// Packet 表示接收到的数据包
type Packet struct {
	QueueID  int         // 来源队列 ID
	Desc     xdp.Desc    // XDP 描述符
	Data     []byte      // 数据包内容
	Socket   *xdp.Socket // 所属 Socket (用于发送响应)
	OrigData []byte      // 原始数据包的副本 (用于构建响应)
}

// PoolOptions Worker池配置选项
type PoolOptions struct {
	NumWorkers      int                    // 总 Worker 数量
	WorkersPerQueue int                    // 每个队列的 Worker 数量
	BatchSize       int                    // 批处理大小
	QueueManager    *xdp.QueueManager      // 多队列管理器
	FilterEngine    *filter.Engine         // 过滤引擎
	DNSParser       *dns.Parser            // DNS解析器
	Metrics         *metrics.Collector     // 指标收集器
	ResponseConfig  *config.ResponseConfig // 响应配置

	// 响应处理回调 (可选)
	// 返回 nil 表示不发送响应
	// 返回 DNS 响应数据则发送响应
	ResponseHandler ResponseHandler
}

// ResponseHandler DNS 响应处理函数
// 参数:
//   - query: 原始 DNS 查询消息
//   - action: 过滤动作
//   - rule: 匹配的规则 (可能为 nil)
//   - pktInfo: 数据包信息
//
// 返回:
//   - []byte: DNS 响应数据 (nil 表示不发送响应)
//   - bool: 是否发送响应
type ResponseHandler func(query *dns.Message, action filter.Action, rule *filter.Rule, pktInfo *PacketInfo) ([]byte, bool)

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

// ProcessResult 处理结果
type ProcessResult struct {
	Action       filter.Action // 执行的动作
	Rule         *filter.Rule  // 匹配的规则
	Domain       string        // 查询的域名
	QueryType    uint16        // 查询类型
	SrcIP        string        // 源 IP
	ResponseSent bool          // 是否发送了响应
}
