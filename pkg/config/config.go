package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 主配置结构
type Config struct {
	Interface  string        `yaml:"interface"`   // 网络接口名
	QueueID    int           `yaml:"queue_id"`    // 队列ID
	QueueCount int           `yaml:"queue_count"` // 队列数量
	BPFPath    string        `yaml:"bpf_path"`    // BPF程序路径
	XDP        XDPConfig     `yaml:"xdp"`         // XDP配置
	Workers    WorkerConfig  `yaml:"workers"`     // Worker配置
	DNS        DNSConfig     `yaml:"dns"`         // DNS配置
	RulesPath  string        `yaml:"rules_path"`  // 过滤规则路径
	Metrics    MetricsConfig `yaml:"metrics"`     // 监控配置
	Logging    LoggingConfig `yaml:"logging"`     // 日志配置
}

// XDPConfig AF_XDP Socket配置
type XDPConfig struct {
	NumFrames          int `yaml:"num_frames"`           // 帧数量
	FrameSize          int `yaml:"frame_size"`           // 帧大小
	FillRingNumDescs   int `yaml:"fill_ring_size"`       // Fill Ring大小
	CompletionRingNumDescs int `yaml:"comp_ring_size"`   // Completion Ring大小
	RxRingNumDescs     int `yaml:"rx_ring_size"`         // RX Ring大小
	TxRingNumDescs     int `yaml:"tx_ring_size"`         // TX Ring大小
}

// WorkerConfig Worker配置
type WorkerConfig struct {
	NumWorkers int `yaml:"num_workers"` // Worker数量, 0表示使用CPU核心数
	BatchSize  int `yaml:"batch_size"`  // 批处理大小
}

// DNSConfig DNS配置
type DNSConfig struct {
	ListenPorts     []uint16      `yaml:"listen_ports"`     // 监听端口
	UpstreamServers []string      `yaml:"upstream_servers"` // 上游DNS服务器
	CacheSize       int           `yaml:"cache_size"`       // 缓存大小
	CacheTTL        time.Duration `yaml:"cache_ttl"`        // 缓存TTL
}

// MetricsConfig 监控配置
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"` // 是否启用
	Listen  string `yaml:"listen"`  // 监听地址
	Path    string `yaml:"path"`    // 路径
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level  string `yaml:"level"`  // 日志级别
	Format string `yaml:"format"` // 日志格式
	Output string `yaml:"output"` // 输出路径
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Interface:  "eth0",
		QueueID:    0,
		QueueCount: 1,
		BPFPath:    "bpf/xdp_dns_filter_bpfel.o",
		XDP: XDPConfig{
			NumFrames:          4096,
			FrameSize:          2048,
			FillRingNumDescs:   2048,
			CompletionRingNumDescs: 2048,
			RxRingNumDescs:     2048,
			TxRingNumDescs:     2048,
		},
		Workers: WorkerConfig{
			NumWorkers: 0, // 使用CPU核心数
			BatchSize:  64,
		},
		DNS: DNSConfig{
			ListenPorts:     []uint16{53},
			UpstreamServers: []string{"8.8.8.8:53", "8.8.4.4:53"},
			CacheSize:       10000,
			CacheTTL:        5 * time.Minute,
		},
		RulesPath: "configs/rules.yaml",
		Metrics: MetricsConfig{
			Enabled: true,
			Listen:  ":9090",
			Path:    "/metrics",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}
}

// Load 从文件加载配置
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	if c.XDP.NumFrames < 64 {
		return fmt.Errorf("num_frames must be at least 64")
	}

	if c.XDP.FrameSize < 1024 {
		return fmt.Errorf("frame_size must be at least 1024")
	}

	if len(c.DNS.ListenPorts) == 0 {
		return fmt.Errorf("at least one listen port is required")
	}

	return nil
}

// Save 保存配置到文件
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

