package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"xdp-dns/internal/worker"
	"xdp-dns/pkg/config"
	"xdp-dns/pkg/dns"
	"xdp-dns/pkg/filter"
	"xdp-dns/pkg/metrics"
	"xdp-dns/xdp"
)

var (
	configPath   = flag.String("config", "configs/config.yaml", "Path to config file")
	bpfPath      = flag.String("bpf", "", "Path to BPF program (use DNS filter if specified)")
	version      = flag.Bool("version", false, "Show version")
	buildVersion = "dev"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("xdp-dns-filter version %s\n", buildVersion)
		os.Exit(0)
	}

	log.Printf("Starting XDP DNS Filter...")

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化指标收集器
	metricsCollector := metrics.NewCollector()

	// 获取网络接口
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", cfg.Interface, err)
	}
	ifindex := link.Attrs().Index

	log.Printf("Using interface: %s (index: %d)", cfg.Interface, ifindex)

	// 确定 BPF 程序路径
	bpfProgPath := *bpfPath
	if bpfProgPath == "" {
		bpfProgPath = cfg.BPFPath
	}
	if bpfProgPath == "" {
		log.Fatalf("BPF program path is required. Set bpf_path in config or use -bpf flag")
	}

	// 加载 XDP DNS 过滤程序
	log.Printf("Loading XDP DNS filter program from: %s", bpfProgPath)
	program, err := xdp.LoadProgram(bpfProgPath)
	if err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}
	defer program.Close()

	// 设置 DNS 端口
	dnsPorts := []uint16{53} // 默认只监听端口 53
	if len(cfg.DNS.ListenPorts) > 0 {
		dnsPorts = cfg.DNS.ListenPorts
	}
	if err := program.SetDNSPorts(dnsPorts); err != nil {
		log.Fatalf("Failed to set DNS ports: %v", err)
	}
	log.Printf("DNS ports configured: %v", dnsPorts)

	// 附加 XDP 程序到接口
	if err := program.Attach(ifindex); err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer program.Detach(ifindex)

	log.Printf("XDP program attached to %s", cfg.Interface)

	// 创建 Socket 配置
	socketOpts := &xdp.SocketOptions{
		NumFrames:              cfg.XDP.NumFrames,
		FrameSize:              cfg.XDP.FrameSize,
		FillRingNumDescs:       cfg.XDP.FillRingNumDescs,
		CompletionRingNumDescs: cfg.XDP.CompletionRingNumDescs,
		RxRingNumDescs:         cfg.XDP.RxRingNumDescs,
		TxRingNumDescs:         cfg.XDP.TxRingNumDescs,
	}

	// 创建多队列管理器
	queueManager, err := xdp.NewQueueManager(xdp.QueueManagerConfig{
		Ifindex:    ifindex,
		QueueStart: cfg.QueueStart,
		QueueCount: cfg.QueueCount,
		SocketOpts: socketOpts,
	}, program)
	if err != nil {
		log.Fatalf("Failed to create queue manager: %v", err)
	}
	defer queueManager.Close()

	log.Printf("Multi-queue XDP sockets created: queues %d-%d (%d total)",
		cfg.QueueStart, cfg.QueueStart+cfg.QueueCount-1, cfg.QueueCount)

	// 初始化过滤引擎
	filterEngine, err := filter.NewEngine(cfg.RulesPath)
	if err != nil {
		log.Fatalf("Failed to init filter engine: %v", err)
	}
	log.Printf("Filter engine initialized with %d rules", len(filterEngine.GetRules()))

	// 创建 Worker 池
	workerPool := worker.NewPool(worker.PoolOptions{
		NumWorkers:      cfg.Workers.NumWorkers,
		WorkersPerQueue: cfg.Workers.WorkersPerQueue,
		BatchSize:       cfg.Workers.BatchSize,
		QueueManager:    queueManager,
		FilterEngine:    filterEngine,
		DNSParser:       dns.NewParser(),
		Metrics:         metricsCollector,
		ResponseConfig:  &cfg.Response,
	})

	// 启动上下文
	ctx, cancel := context.WithCancel(context.Background())

	// 启动 metrics 服务器
	if cfg.Metrics.Enabled {
		exporter := metrics.NewExporter(metricsCollector, cfg.Metrics.Listen, cfg.Metrics.Path)
		go func() {
			if err := exporter.Start(); err != nil {
				log.Printf("Metrics server error: %v", err)
			}
		}()
		go exporter.StartUpdateLoop(ctx, 10*time.Second)
		log.Printf("Metrics server started on %s%s", cfg.Metrics.Listen, cfg.Metrics.Path)
	}

	// 启动 Worker 池
	go workerPool.Start(ctx)
	log.Printf("Worker pool started with %d workers for %d queues",
		cfg.Workers.NumWorkers, cfg.QueueCount)

	// 打印配置摘要
	log.Printf("=== Configuration Summary ===")
	log.Printf("  Interface: %s", cfg.Interface)
	log.Printf("  Queues: %d-%d (%d total)", cfg.QueueStart, cfg.QueueStart+cfg.QueueCount-1, cfg.QueueCount)
	log.Printf("  DNS Ports: %v", dnsPorts)
	log.Printf("  Response enabled: %v", cfg.Response.Enabled)
	log.Printf("  Block response: %v (NXDOMAIN: %v)", cfg.Response.BlockResponse, cfg.Response.NXDomain)
	log.Printf("=============================")

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("XDP DNS Filter is running. Press Ctrl+C to stop.")

	<-sigCh
	log.Println("Shutting down...")

	cancel()
	workerPool.Wait()

	// 打印统计信息
	stats := metricsCollector.GetStats()
	log.Printf("Final stats: received=%d, allowed=%d (normal), blocked=%d (threat), logged=%d (suspicious), dropped=%d",
		stats.Received, stats.Allowed, stats.Blocked, stats.Logged, stats.Dropped)

	log.Println("XDP DNS Filter stopped.")
}
