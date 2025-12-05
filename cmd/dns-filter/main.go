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

func logPrintf(format string, v ...any) {
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
	// 单核模式
	if cfg.Performance.SingleCore {
		runtime.GOMAXPROCS(1)
		fmt.Println("[PERF] Single-core mode: GOMAXPROCS set to 1")
	}

	// CPU 亲和性
	if cfg.Performance.CPUAffinity >= 0 {
		if err := setCPUAffinity(cfg.Performance.CPUAffinity); err != nil {
			fmt.Printf("[PERF] Warning: failed to set CPU affinity to %d: %v\n", cfg.Performance.CPUAffinity, err)
		} else {
			fmt.Printf("[PERF] CPU affinity set to core %d\n", cfg.Performance.CPUAffinity)
		}
	}

	// 禁用日志 (最后执行，让启动信息能输出)
	if cfg.Performance.DisableLog || !cfg.Logging.Enabled {
		logEnabled = false
		fmt.Println("[PERF] Logging disabled for maximum performance")
		log.SetOutput(io.Discard)
	}
}

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("xdp-dns-filter version %s\n", buildVersion)
		os.Exit(0)
	}

	fmt.Println("Starting XDP DNS Filter...")

	// 加载配置
	fmt.Println("[1/7] Loading configuration...")
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 应用性能配置
	applyPerformanceConfig(cfg)

	// 初始化指标收集器
	metricsCollector := metrics.NewCollector()

	// 获取网络接口
	fmt.Printf("[2/7] Getting interface %s...\n", cfg.Interface)
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", cfg.Interface, err)
	}
	ifindex := link.Attrs().Index
	fmt.Printf("      Interface %s (index: %d) ready\n", cfg.Interface, ifindex)

	// 确定 BPF 程序路径
	bpfProgPath := *bpfPath
	if bpfProgPath == "" {
		bpfProgPath = cfg.BPFPath
	}
	if bpfProgPath == "" {
		log.Fatalf("BPF program path is required. Set bpf_path in config or use -bpf flag")
	}

	// 加载 XDP DNS 过滤程序
	fmt.Printf("[3/7] Loading BPF program from: %s...\n", bpfProgPath)
	program, err := xdp.LoadProgram(bpfProgPath)
	if err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}
	defer program.Close()
	fmt.Println("      BPF program loaded")

	// 设置 DNS 端口
	dnsPorts := []uint16{53} // 默认只监听端口 53
	if len(cfg.DNS.ListenPorts) > 0 {
		dnsPorts = cfg.DNS.ListenPorts
	}
	if err := program.SetDNSPorts(dnsPorts); err != nil {
		log.Fatalf("Failed to set DNS ports: %v", err)
	}
	fmt.Printf("      DNS ports: %v\n", dnsPorts)

	// 附加 XDP 程序到接口
	fmt.Printf("[4/7] Attaching XDP program to %s...\n", cfg.Interface)
	if err := program.Attach(ifindex); err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer program.Detach(ifindex)
	fmt.Println("      XDP program attached")

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
	}

	// 创建多队列管理器
	fmt.Printf("[5/7] Creating AF_XDP sockets (queues: %d)...\n", queueCount)
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
	fmt.Printf("      Queues %d-%d created\n", cfg.QueueStart, cfg.QueueStart+queueCount-1)

	// 初始化过滤引擎
	fmt.Println("[6/7] Loading filter rules...")
	filterEngine, err := filter.NewEngine(cfg.RulesPath)
	if err != nil {
		log.Fatalf("Failed to init filter engine: %v", err)
	}
	fmt.Printf("      Loaded %d rules\n", len(filterEngine.GetRules()))

	// 创建 Worker 池
	fmt.Println("[7/7] Starting worker pool...")
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
		fmt.Printf("      Metrics: %s%s\n", cfg.Metrics.Listen, cfg.Metrics.Path)
	}

	// 启动 Worker 池
	go workerPool.Start(ctx)
	fmt.Printf("      Workers: %d\n", cfg.Workers.NumWorkers)

	// 打印配置摘要
	fmt.Println("")
	fmt.Println("=== XDP DNS Filter Ready ===")
	fmt.Printf("  Interface:    %s\n", cfg.Interface)
	fmt.Printf("  Queues:       %d-%d (%d total)\n", cfg.QueueStart, cfg.QueueStart+queueCount-1, queueCount)
	fmt.Printf("  DNS Ports:    %v\n", dnsPorts)
	fmt.Printf("  Response:     mode=%s, block=%v\n", cfg.Response.Mode, cfg.Response.BlockResponse)
	fmt.Printf("  Performance:  single_core=%v, cpu=%d, no_log=%v\n",
		cfg.Performance.SingleCore, cfg.Performance.CPUAffinity, cfg.Performance.DisableLog)
	fmt.Println("=============================")

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("")
	fmt.Println("XDP DNS Filter is running. Press Ctrl+C to stop.")

	<-sigCh
	fmt.Println("")
	fmt.Println("Shutting down...")

	cancel()
	workerPool.Wait()

	// 打印统计信息 (始终输出)
	stats := metricsCollector.GetStats()
	fmt.Printf("Final stats: received=%d, allowed=%d, blocked=%d, logged=%d, dropped=%d\n",
		stats.Received, stats.Allowed, stats.Blocked, stats.Logged, stats.Dropped)

	fmt.Println("XDP DNS Filter stopped.")
}
