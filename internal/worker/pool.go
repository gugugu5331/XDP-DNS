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

// Pool Worker 处理池
type Pool struct {
	options PoolOptions
	packets chan Packet
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// NewPool 创建新的 Worker 池
func NewPool(opts PoolOptions) *Pool {
	if opts.NumWorkers <= 0 {
		opts.NumWorkers = runtime.NumCPU()
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 64
	}

	return &Pool{
		options: opts,
		packets: make(chan Packet, opts.NumWorkers*1024),
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

	// 启动 receiver
	p.wg.Add(1)
	go p.receiver(ctx)
}

// receiver 接收数据包
func (p *Pool) receiver(ctx context.Context) {
	defer p.wg.Done()

	socket := p.options.Socket
	if socket == nil {
		log.Println("Worker pool: socket is nil")
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 填充 Fill Ring
		descs := socket.GetDescs(socket.NumFreeFillSlots(), true)
		if len(descs) > 0 {
			socket.Fill(descs)
		}

		// 轮询接收
		numRx, _, err := socket.Poll(100) // 100ms 超时
		if err != nil {
			log.Printf("Poll error: %v", err)
			continue
		}

		if numRx == 0 {
			continue
		}

		// 分发到 workers
		rxDescs := socket.Receive(numRx)
		for _, desc := range rxDescs {
			pkt := Packet{
				Desc: desc,
				Data: socket.GetFrame(desc),
			}

			select {
			case p.packets <- pkt:
			default:
				// 队列满，丢弃包
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
	if engine == nil {
		return
	}

	action, rule := engine.Check(msg, pktInfo.SrcIP)

	// 处理检测结果 (威胁分析只记录，不响应)
	p.handleAction(msg, action, rule, pktInfo, metricsCollector)
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
