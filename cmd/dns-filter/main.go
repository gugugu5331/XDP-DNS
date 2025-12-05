package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

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

// 日志控制
var (
	logEnabled = true
)

func logPrintf(format string, v ...interface{}) {
	if logEnabled {
		log.Printf(format, v...)
	}
}

// setCPUAffinity 设置 CPU 亲和性
func setCPUAffinity(cpu int) error {
	var mask unix.CPUSet
	mask.Zero()
	mask.Set(cpu)
	return unix.SchedSetaffinity(0, &mask)
}

// applyPerformanceConfig 应用性能配置
func applyPerformanceConfig(cfg *config.Config) {
	// 禁用日志
	if cfg.Performance.DisableLog || !cfg.Logging.Enabled {
		logEnabled = false
		log.SetOutput(io.Discard)
		log.Printf("Logging disabled for maximum performance")
	}

	// 单核模式
	if cfg.Performance.SingleCore {
		runtime.GOMAXPROCS(1)
		if logEnabled {
			log.Printf("Single-core mode: GOMAXPROCS set to 1")
		}
	}

	// CPU 亲和性
	if cfg.Performance.CPUAffinity >= 0 {
		if err := setCPUAffinity(cfg.Performance.CPUAffinity); err != nil {
			log.Printf("Warning: failed to set CPU affinity to %d: %v", cfg.Performance.CPUAffinity, err)
		} else if logEnabled {
			log.Printf("CPU affinity set to core %d", cfg.Performance.CPUAffinity)
		}
	}
}

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

	// 应用性能配置
	applyPerformanceConfig(cfg)

	// 初始化指标收集器
	metricsCollector := metrics.NewCollector()

	// 获取网络接口
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", cfg.Interface, err)
	}
	ifindex := link.Attrs().Index

	logPrintf("Using interface: %s (index: %d)", cfg.Interface, ifindex)

	// 确定 BPF 程序路径
	bpfProgPath := *bpfPath
	if bpfProgPath == "" {
		bpfProgPath = cfg.BPFPath
	}
	if bpfProgPath == "" {
		log.Fatalf("BPF program path is required. Set bpf_path in config or use -bpf flag")
	}

	// 加载 XDP DNS 过滤程序
	logPrintf("Loading XDP DNS filter program from: %s", bpfProgPath)
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
	logPrintf("DNS ports configured: %v", dnsPorts)

	// 附加 XDP 程序到接口
	if err := program.Attach(ifindex); err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer program.Detach(ifindex)

	logPrintf("XDP program attached to %s", cfg.Interface)

	// 创建 Socket 配置
	socketOpts := &xdp.SocketOptions{
		NumFrames:              cfg.XDP.NumFrames,
		FrameSize:              cfg.XDP.FrameSize,
		FillRingNumDescs:       cfg.XDP.FillRingNumDescs,
		CompletionRingNumDescs: cfg.XDP.CompletionRingNumDescs,
		RxRingNumDescs:         cfg.XDP.RxRingNumDescs,
		TxRingNumDescs:         cfg.XDP.TxRingNumDescs,
	}

	// 应用单核模式
	queueCount := cfg.QueueCount
	if cfg.Performance.SingleCore {
		queueCount = 1
		logPrintf("Single-core mode enabled, using 1 queue")
	}

	// 创建多队列管理器
	queueManager, err := xdp.NewQueueManager(xdp.QueueManagerConfig{
		Ifindex:    ifindex,
		QueueStart: cfg.QueueStart,
		QueueCount: queueCount,
		SocketOpts: socketOpts,
	}, program)
	if err != nil {
		log.Fatalf("Failed to create queue manager: %v", err)
	}
	defer queueManager.Close()

	logPrintf("Multi-queue XDP sockets created: queues %d-%d (%d total)",
		cfg.QueueStart, cfg.QueueStart+queueCount-1, queueCount)

	// 初始化过滤引擎
	filterEngine, err := filter.NewEngine(cfg.RulesPath)
	if err != nil {
		log.Fatalf("Failed to init filter engine: %v", err)
	}
	logPrintf("Filter engine initialized with %d rules", len(filterEngine.GetRules()))

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
		DisableLog:      cfg.Performance.DisableLog,
	})

	// 启动上下文
	ctx, cancel := context.WithCancel(context.Background())

	// 启动 metrics 服务器
	if cfg.Metrics.Enabled {
		exporter := metrics.NewExporter(metricsCollector, cfg.Metrics.Listen, cfg.Metrics.Path)
		go func() {
			if err := exporter.Start(); err != nil {
				logPrintf("Metrics server error: %v", err)
			}
		}()
		go exporter.StartUpdateLoop(ctx, 10*time.Second)
		logPrintf("Metrics server started on %s%s", cfg.Metrics.Listen, cfg.Metrics.Path)
	}

	// 启动 Worker 池
	go workerPool.Start(ctx)
	logPrintf("Worker pool started with %d workers for %d queues",
		cfg.Workers.NumWorkers, queueCount)

	// 打印配置摘要
	logPrintf("=== Configuration Summary ===")
	logPrintf("  Interface: %s", cfg.Interface)
	logPrintf("  Queues: %d-%d (%d total)", cfg.QueueStart, cfg.QueueStart+queueCount-1, queueCount)
	logPrintf("  DNS Ports: %v", dnsPorts)
	logPrintf("  Response mode: %s", cfg.Response.Mode)
	logPrintf("  Block response: %v (NXDOMAIN: %v)", cfg.Response.BlockResponse, cfg.Response.NXDomain)
	logPrintf("  Performance: single_core=%v, cpu_affinity=%d, disable_log=%v",
		cfg.Performance.SingleCore, cfg.Performance.CPUAffinity, cfg.Performance.DisableLog)
	logPrintf("=============================")

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	logPrintf("XDP DNS Filter is running. Press Ctrl+C to stop.")

	<-sigCh
	log.Println("Shutting down...")

	cancel()
	workerPool.Wait()

	// 打印统计信息 (始终输出)
	stats := metricsCollector.GetStats()
	log.Printf("Final stats: received=%d, allowed=%d (normal), blocked=%d (threat), logged=%d (suspicious), dropped=%d",
		stats.Received, stats.Allowed, stats.Blocked, stats.Logged, stats.Dropped)

	log.Println("XDP DNS Filter stopped.")
}
