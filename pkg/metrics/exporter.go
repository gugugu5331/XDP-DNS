package metrics

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// DNS 数据包指标
	packetsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "xdp_dns_packets_received_total",
		Help: "Total DNS packets received",
	})

	packetsAllowed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "xdp_dns_packets_allowed_total",
		Help: "Total DNS packets allowed",
	})

	packetsBlocked = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "xdp_dns_packets_blocked_total",
		Help: "Total DNS packets blocked",
	})

	packetsRedirected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "xdp_dns_packets_redirected_total",
		Help: "Total DNS packets redirected",
	})

	packetsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "xdp_dns_packets_dropped_total",
		Help: "Total DNS packets dropped due to queue full",
	})

	parseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "xdp_dns_parse_errors_total",
		Help: "Total DNS parse errors",
	})

	// 处理延迟指标
	packetLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "xdp_dns_packet_latency_seconds",
		Help:    "Packet processing latency in seconds",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
	})

	// XDP 统计指标
	xdpKernelDrops = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "xdp_kernel_drops",
		Help: "Number of packets dropped by kernel XDP",
	})

	// 规则统计
	rulesTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "xdp_dns_rules_total",
		Help: "Total number of filter rules",
	})
)

func init() {
	// 注册所有指标
	prometheus.MustRegister(
		packetsReceived,
		packetsAllowed,
		packetsBlocked,
		packetsRedirected,
		packetsDropped,
		parseErrors,
		packetLatency,
		xdpKernelDrops,
		rulesTotal,
	)
}

// Exporter Prometheus 指标导出器
type Exporter struct {
	collector *Collector
	server    *http.Server
	addr      string
	path      string
}

// NewExporter 创建新的导出器
func NewExporter(collector *Collector, addr, path string) *Exporter {
	return &Exporter{
		collector: collector,
		addr:      addr,
		path:      path,
	}
}

// Start 启动 HTTP 服务器
func (e *Exporter) Start() error {
	mux := http.NewServeMux()
	mux.Handle(e.path, promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if e.collector != nil {
			stats := e.collector.GetStats()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"received":%d,"allowed":%d,"blocked":%d,"redirected":%d,"dropped":%d}`,
				stats.Received, stats.Allowed, stats.Blocked, stats.Redirected, stats.Dropped)
		}
	})

	e.server = &http.Server{
		Addr:    e.addr,
		Handler: mux,
	}

	log.Printf("Starting metrics server on %s", e.addr)
	return e.server.ListenAndServe()
}

// Stop 停止服务器
func (e *Exporter) Stop(ctx context.Context) error {
	if e.server != nil {
		return e.server.Shutdown(ctx)
	}
	return nil
}

// UpdateMetrics 更新 Prometheus 指标
func (e *Exporter) UpdateMetrics() {
	if e.collector == nil {
		return
	}

	stats := e.collector.GetStats()
	packetsReceived.Add(float64(stats.Received))
	packetsAllowed.Add(float64(stats.Allowed))
	packetsBlocked.Add(float64(stats.Blocked))
	packetsRedirected.Add(float64(stats.Redirected))
	packetsDropped.Add(float64(stats.Dropped))
	parseErrors.Add(float64(stats.ParseErrors))
}

// StartUpdateLoop 启动指标更新循环
func (e *Exporter) StartUpdateLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.UpdateMetrics()
		}
	}
}

// SetRulesTotal 设置规则总数
func SetRulesTotal(count int) {
	rulesTotal.Set(float64(count))
}

// ObserveLatency 记录延迟
func ObserveLatency(duration time.Duration) {
	packetLatency.Observe(duration.Seconds())
}

