package worker

import (
	"context"
	"log"
	"runtime"
	"sync"

	"xdp-dns/pkg/dns"
	"xdp-dns/pkg/filter"
	"xdp-dns/pkg/metrics"
)

// Pool 多队列 Worker 处理池
type Pool struct {
	options PoolOptions
	packets chan Packet
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// NewPool 创建新的 Worker 池
func NewPool(opts PoolOptions) *Pool {
	numWorkers := opts.NumWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 64
	}
	if opts.WorkersPerQueue <= 0 {
		opts.WorkersPerQueue = 2
	}

	// 如果有队列管理器，根据队列数量调整 worker 数
	if opts.QueueManager != nil {
		queueCount := opts.QueueManager.QueueCount()
		if numWorkers < queueCount*opts.WorkersPerQueue {
			numWorkers = queueCount * opts.WorkersPerQueue
		}
	}

	opts.NumWorkers = numWorkers

	return &Pool{
		options: opts,
		packets: make(chan Packet, numWorkers*1024),
	}
}

// Start 启动 Worker 池
func (p *Pool) Start(ctx context.Context) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.mu.Unlock()

	// 启动 workers
	for i := 0; i < p.options.NumWorkers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	// 启动 receiver (从队列管理器接收)
	if p.options.QueueManager != nil {
		p.wg.Add(1)
		go p.multiQueueReceiver(ctx)
		log.Printf("Worker pool started: %d workers for %d queues",
			p.options.NumWorkers, p.options.QueueManager.QueueCount())
	} else {
		log.Printf("Worker pool started: %d workers (no queue manager)", p.options.NumWorkers)
	}
}

// multiQueueReceiver 从多队列管理器接收数据包
func (p *Pool) multiQueueReceiver(ctx context.Context) {
	defer p.wg.Done()

	qm := p.options.QueueManager
	if qm == nil {
		log.Println("Worker pool: queue manager is nil")
		return
	}

	// 启动队列管理器的接收器
	rxPackets := qm.StartReceiver(ctx, p.options.BatchSize)

	for {
		select {
		case <-ctx.Done():
			return
		case rxPkt, ok := <-rxPackets:
			if !ok {
				return
			}

			// 转换为 worker Packet
			pkt := Packet{
				QueueID:  rxPkt.QueueID,
				Desc:     rxPkt.Desc,
				Data:     rxPkt.Data,
				Socket:   rxPkt.Socket,
				OrigData: make([]byte, len(rxPkt.Data)),
			}
			// 复制原始数据用于构建响应
			copy(pkt.OrigData, rxPkt.Data)

			select {
			case p.packets <- pkt:
			default:
				// 队列满，丢弃
				if p.options.Metrics != nil {
					p.options.Metrics.IncDropped()
				}
			}
		}
	}
}

// worker 处理数据包
func (p *Pool) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	parser := p.options.DNSParser
	engine := p.options.FilterEngine
	metricsCollector := p.options.Metrics

	if parser == nil {
		parser = dns.NewParser()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-p.packets:
			p.processPacket(pkt, parser, engine, metricsCollector)
		}
	}
}

// processPacket 处理单个数据包
func (p *Pool) processPacket(pkt Packet, parser *dns.Parser,
	engine *filter.Engine, metricsCollector *metrics.Collector) {

	// 提取 DNS payload
	dnsData, pktInfo, err := extractDNSPayload(pkt.Data)
	if err != nil || dnsData == nil {
		return
	}

	// 解析 DNS 消息
	msg, err := parser.Parse(dnsData)
	if err != nil {
		if metricsCollector != nil {
			metricsCollector.IncParseError()
		}
		return
	}

	if metricsCollector != nil {
		metricsCollector.IncReceived()
	}

	// 只处理查询
	if !msg.IsQuery() {
		return
	}

	// 过滤检查
	var action filter.Action = filter.ActionAllow
	var rule *filter.Rule
	if engine != nil {
		action, rule = engine.Check(msg, pktInfo.SrcIP)
	}

	// 处理动作并可能发送响应
	p.handleActionWithResponse(pkt, msg, action, rule, pktInfo, metricsCollector)
}

// Wait 等待所有 worker 完成
func (p *Pool) Wait() {
	p.wg.Wait()
}

// Stop 停止 Worker 池
func (p *Pool) Stop() {
	p.mu.Lock()
	p.running = false
	p.mu.Unlock()
}
