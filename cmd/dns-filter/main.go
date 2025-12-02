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
	configPath = flag.String("config", "configs/config.yaml", "Path to config file")
	version    = flag.Bool("version", false, "Show version")
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

	// 创建 XDP 程序
	program, err := xdp.NewProgram(cfg.QueueCount)
	if err != nil {
		log.Fatalf("Failed to create XDP program: %v", err)
	}
	defer program.Close()

	// 附加 XDP 程序到接口
	if err := program.Attach(ifindex); err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer program.Detach(ifindex)

	log.Printf("XDP program attached to %s", cfg.Interface)

	// 创建 AF_XDP Socket
	socketOpts := &xdp.SocketOptions{
		NumFrames:              cfg.XDP.NumFrames,
		FrameSize:              cfg.XDP.FrameSize,
		FillRingNumDescs:       cfg.XDP.FillRingNumDescs,
		CompletionRingNumDescs: cfg.XDP.CompletionRingNumDescs,
		RxRingNumDescs:         cfg.XDP.RxRingNumDescs,
		TxRingNumDescs:         cfg.XDP.TxRingNumDescs,
	}

	socket, err := xdp.NewSocket(ifindex, cfg.QueueID, socketOpts)
	if err != nil {
		log.Fatalf("Failed to create XDP socket: %v", err)
	}
	defer socket.Close()

	// 注册 socket 到 XDP 程序
	if err := program.Register(cfg.QueueID, socket.FD()); err != nil {
		log.Fatalf("Failed to register socket: %v", err)
	}

	log.Printf("XDP socket created and registered")

	// 初始化过滤引擎
	filterEngine, err := filter.NewEngine(cfg.RulesPath)
	if err != nil {
		log.Fatalf("Failed to init filter engine: %v", err)
	}
	log.Printf("Filter engine initialized with %d rules", len(filterEngine.GetRules()))

	// 创建 Worker 池
	workerPool := worker.NewPool(worker.PoolOptions{
		NumWorkers:   cfg.Workers.NumWorkers,
		BatchSize:    cfg.Workers.BatchSize,
		Socket:       socket,
		FilterEngine: filterEngine,
		DNSParser:    dns.NewParser(),
		Metrics:      metricsCollector,
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
	log.Printf("Worker pool started with %d workers", cfg.Workers.NumWorkers)

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
	log.Printf("Final stats: received=%d, allowed=%d, blocked=%d, redirected=%d, dropped=%d",
		stats.Received, stats.Allowed, stats.Blocked, stats.Redirected, stats.Dropped)

	log.Println("XDP DNS Filter stopped.")
}

