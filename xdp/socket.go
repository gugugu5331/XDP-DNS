// Package xdp provides AF_XDP socket utilities for high-performance packet processing.
//
// 文件: xdp/socket.go
// 功能: 提供 AF_XDP Socket 的高级封装，简化 DNS 数据包的接收和处理
//
// 使用示例:
//
//	link, _ := netlink.LinkByName("eth0")
//	xsk, _ := NewXDPSocket(link.Attrs().Index, 0, nil)
//	defer xsk.Close()
//
//	for {
//	    packets, _ := xsk.ReceivePackets(100)
//	    for _, pkt := range packets {
//	        // 处理数据包
//	        dnsData, _ := pkt.GetDNSPayload()
//	    }
//	}
package xdp

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Packet 表示从 AF_XDP 接收到的数据包
type Packet struct {
	Desc      Desc   // XDP 描述符 (包含 addr 和 len)
	Data      []byte // 原始数据包数据 (指向 UMEM)
	Timestamp int64  // 接收时间戳 (纳秒)
}

// PacketInfo 提供解析后的数据包信息
type PacketInfo struct {
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	EtherType uint16
	SrcIP     net.IP
	DstIP     net.IP
	Protocol  uint8
	SrcPort   uint16
	DstPort   uint16
	Payload   []byte
	IsDNS     bool
	IsQuery   bool
}

// XDPSocket 是 Socket 的高级封装，提供更便捷的 API
type XDPSocket struct {
	socket  *Socket
	program *Program
	ifindex int
	queueID int

	// 统计信息
	stats XDPStats

	// 配置
	config XDPSocketConfig

	// 同步
	mu     sync.RWMutex
	closed bool
}

// XDPStats 统计信息
type XDPStats struct {
	PacketsReceived uint64 // 接收的数据包数
	PacketsSent     uint64 // 发送的数据包数
	BytesReceived   uint64 // 接收的字节数
	BytesSent       uint64 // 发送的字节数
	DNSPackets      uint64 // DNS 数据包数
	DroppedPackets  uint64 // 丢弃的数据包数
	ParseErrors     uint64 // 解析错误数
	PollTimeouts    uint64 // Poll 超时次数
	LastReceiveTime int64  // 最后接收时间
	LastSendTime    int64  // 最后发送时间
}

// XDPSocketConfig 配置选项
type XDPSocketConfig struct {
	NumFrames              int           // UMEM 帧数量
	FrameSize              int           // 每帧大小
	FillRingNumDescs       int           // Fill Ring 大小
	CompletionRingNumDescs int           // Completion Ring 大小
	RxRingNumDescs         int           // RX Ring 大小
	TxRingNumDescs         int           // TX Ring 大小
	PollTimeout            time.Duration // Poll 超时时间
	BatchSize              int           // 批量处理大小
	ZeroCopy               bool          // 是否使用零拷贝模式
}

// DefaultXDPSocketConfig 默认配置
var DefaultXDPSocketConfig = XDPSocketConfig{
	NumFrames:              4096,
	FrameSize:              2048,
	FillRingNumDescs:       2048,
	CompletionRingNumDescs: 2048,
	RxRingNumDescs:         2048,
	TxRingNumDescs:         2048,
	PollTimeout:            100 * time.Millisecond,
	BatchSize:              64,
	ZeroCopy:               true,
}

// DNS 相关常量
const (
	DNSPort    = 53
	DNSOverTLS = 853
	MDNSPort   = 5353
	DNSMinLen  = 12 // DNS 头部最小长度
	EthHdrLen  = 14
	IPv4HdrLen = 20
	IPv6HdrLen = 40
	UDPHdrLen  = 8
	TCPHdrLen  = 20
)

// 协议常量
const (
	EthTypeIPv4 = 0x0800
	EthTypeIPv6 = 0x86DD
	EthTypeARP  = 0x0806

	IPProtoICMP = 1
	IPProtoTCP  = 6
	IPProtoUDP  = 17
)

// 错误定义
var (
	ErrSocketClosed    = errors.New("xdp socket is closed")
	ErrInvalidPacket   = errors.New("invalid packet data")
	ErrNotDNSPacket    = errors.New("not a DNS packet")
	ErrPacketTooShort  = errors.New("packet too short")
	ErrUnsupportedType = errors.New("unsupported protocol type")
	ErrNoSocket        = errors.New("socket not initialized")
	ErrNoProgram       = errors.New("program not attached")
)

// NewXDPSocket 创建新的 XDP Socket
//
// 参数:
//   - ifindex: 网卡索引
//   - queueID: 队列 ID
//   - config: 配置选项 (可为 nil，使用默认配置)
//
// 返回:
//   - *XDPSocket: XDP Socket 实例
//   - error: 错误信息
func NewXDPSocket(ifindex int, queueID int, config *XDPSocketConfig) (*XDPSocket, error) {
	if config == nil {
		config = &DefaultXDPSocketConfig
	}

	// 创建底层 Socket
	socketOpts := &SocketOptions{
		NumFrames:              config.NumFrames,
		FrameSize:              config.FrameSize,
		FillRingNumDescs:       config.FillRingNumDescs,
		CompletionRingNumDescs: config.CompletionRingNumDescs,
		RxRingNumDescs:         config.RxRingNumDescs,
		TxRingNumDescs:         config.TxRingNumDescs,
	}

	socket, err := NewSocket(ifindex, queueID, socketOpts)
	if err != nil {
		return nil, fmt.Errorf("创建底层 socket 失败: %w", err)
	}

	xsk := &XDPSocket{
		socket:  socket,
		ifindex: ifindex,
		queueID: queueID,
		config:  *config,
	}

	return xsk, nil
}

// NewXDPSocketWithProgram 创建带有 XDP DNS 过滤程序的 Socket
//
// 参数:
//   - ifindex: 网卡索引
//   - queueID: 队列 ID
//   - bpfPath: BPF 程序文件路径
//   - dnsPorts: 要拦截的 DNS 端口列表
//   - config: Socket 配置 (可为 nil 使用默认配置)
func NewXDPSocketWithProgram(ifindex int, queueID int, bpfPath string, dnsPorts []uint16, config *XDPSocketConfig) (*XDPSocket, error) {
	xsk, err := NewXDPSocket(ifindex, queueID, config)
	if err != nil {
		return nil, err
	}

	// 加载 XDP DNS 过滤程序
	program, err := LoadProgram(bpfPath)
	if err != nil {
		xsk.Close()
		return nil, fmt.Errorf("加载 XDP 程序失败: %w", err)
	}
	xsk.program = program

	// 设置 DNS 端口
	if len(dnsPorts) == 0 {
		dnsPorts = []uint16{53} // 默认端口 53
	}
	if err := program.SetDNSPorts(dnsPorts); err != nil {
		xsk.Close()
		return nil, fmt.Errorf("设置 DNS 端口失败: %w", err)
	}

	// 附加程序到网卡
	if err := program.Attach(ifindex); err != nil {
		xsk.Close()
		return nil, fmt.Errorf("附加 XDP 程序失败: %w", err)
	}

	// 注册 socket
	if err := program.Register(queueID, xsk.socket.FD()); err != nil {
		xsk.Close()
		return nil, fmt.Errorf("注册 socket 失败: %w", err)
	}

	return xsk, nil
}

// AttachProgram 附加外部 XDP 程序
func (x *XDPSocket) AttachProgram(program *Program) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.closed {
		return ErrSocketClosed
	}

	x.program = program

	// 注册 socket 到程序
	if err := program.Register(x.queueID, x.socket.FD()); err != nil {
		return fmt.Errorf("注册 socket 失败: %w", err)
	}

	return nil
}

// FillRing 填充 Fill Ring，准备接收数据包
//
// 这个方法应该在开始接收前调用，以及在处理完数据包后调用以归还帧
func (x *XDPSocket) FillRing() int {
	x.mu.RLock()
	defer x.mu.RUnlock()

	if x.closed || x.socket == nil {
		return 0
	}

	numFreeSlots := x.socket.NumFreeFillSlots()
	if numFreeSlots == 0 {
		return 0
	}

	descs := x.socket.GetDescs(numFreeSlots, true)
	return x.socket.Fill(descs)
}

// Poll 等待数据包到达
//
// 返回:
//   - numRx: 接收到的数据包数
//   - numCompleted: 完成发送的数据包数
//   - error: 错误信息
func (x *XDPSocket) Poll(timeout time.Duration) (numRx int, numCompleted int, err error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	if x.closed || x.socket == nil {
		return 0, 0, ErrSocketClosed
	}

	timeoutMs := int(timeout.Milliseconds())
	numRx, numCompleted, err = x.socket.Poll(timeoutMs)

	if err != nil {
		return 0, 0, err
	}

	if numRx == 0 && numCompleted == 0 {
		atomic.AddUint64(&x.stats.PollTimeouts, 1)
	}

	return numRx, numCompleted, nil
}

// ReceivePackets 接收数据包
//
// 参数:
//   - maxPackets: 最大接收数量
//
// 返回:
//   - []Packet: 接收到的数据包列表
//   - error: 错误信息
func (x *XDPSocket) ReceivePackets(maxPackets int) ([]Packet, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	if x.closed || x.socket == nil {
		return nil, ErrSocketClosed
	}

	// 填充 Fill Ring
	x.socket.Fill(x.socket.GetDescs(x.socket.NumFreeFillSlots(), true))

	// Poll 等待数据
	numRx, _, err := x.socket.Poll(int(x.config.PollTimeout.Milliseconds()))
	if err != nil {
		return nil, fmt.Errorf("poll 失败: %w", err)
	}

	if numRx == 0 {
		return nil, nil
	}

	if numRx > maxPackets {
		numRx = maxPackets
	}

	// 接收数据包
	descs := x.socket.Receive(numRx)
	now := time.Now().UnixNano()

	packets := make([]Packet, len(descs))
	for i, desc := range descs {
		packets[i] = Packet{
			Desc:      desc,
			Data:      x.socket.GetFrame(desc),
			Timestamp: now,
		}

		// 更新统计
		atomic.AddUint64(&x.stats.PacketsReceived, 1)
		atomic.AddUint64(&x.stats.BytesReceived, uint64(desc.Len))
	}

	atomic.StoreInt64(&x.stats.LastReceiveTime, now)

	return packets, nil
}

// Close 关闭 XDP Socket 并释放资源
func (x *XDPSocket) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.closed {
		return nil
	}
	x.closed = true

	var errs []error

	// 先分离 XDP 程序
	if x.program != nil {
		if err := x.program.Detach(x.ifindex); err != nil {
			errs = append(errs, fmt.Errorf("分离 XDP 程序失败: %w", err))
		}
		if err := x.program.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭 XDP 程序失败: %w", err))
		}
		x.program = nil
	}

	// 关闭底层 socket
	if x.socket != nil {
		if err := x.socket.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭 socket 失败: %w", err))
		}
		x.socket = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// GetStats 获取统计信息
func (x *XDPSocket) GetStats() XDPStats {
	return XDPStats{
		PacketsReceived: atomic.LoadUint64(&x.stats.PacketsReceived),
		PacketsSent:     atomic.LoadUint64(&x.stats.PacketsSent),
		BytesReceived:   atomic.LoadUint64(&x.stats.BytesReceived),
		BytesSent:       atomic.LoadUint64(&x.stats.BytesSent),
		DNSPackets:      atomic.LoadUint64(&x.stats.DNSPackets),
		DroppedPackets:  atomic.LoadUint64(&x.stats.DroppedPackets),
		ParseErrors:     atomic.LoadUint64(&x.stats.ParseErrors),
		PollTimeouts:    atomic.LoadUint64(&x.stats.PollTimeouts),
		LastReceiveTime: atomic.LoadInt64(&x.stats.LastReceiveTime),
		LastSendTime:    atomic.LoadInt64(&x.stats.LastSendTime),
	}
}

// FD 返回底层 socket 的文件描述符
func (x *XDPSocket) FD() int {
	if x.socket == nil {
		return -1
	}
	return x.socket.FD()
}
