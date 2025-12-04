package xdp

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// Program 表示 XDP DNS 过滤程序及其关联的 BPF maps
// 该程序只拦截指定端口的 DNS (UDP) 流量，其他流量直接放行
type Program struct {
	Program  *ebpf.Program
	Queues   *ebpf.Map // qidconf_map - 队列配置
	Sockets  *ebpf.Map // xsks_map - AF_XDP socket 映射
	DNSPorts *ebpf.Map // dns_ports_map - DNS 端口过滤
	Metrics  *ebpf.Map // metrics_map - 统计指标 (可选)
}

// Attach 将 XDP 程序附加到网络接口
func (p *Program) Attach(ifindex int) error {
	if err := removeProgram(ifindex); err != nil {
		return err
	}
	return attachProgram(ifindex, p.Program)
}

// Detach 从网络接口分离 XDP 程序
func (p *Program) Detach(ifindex int) error {
	return removeProgram(ifindex)
}

// Register 注册 AF_XDP socket 到指定队列
// queueID: 网卡队列 ID
// fd: socket 文件描述符
func (p *Program) Register(queueID int, fd int) error {
	if err := p.Sockets.Put(uint32(queueID), uint32(fd)); err != nil {
		return fmt.Errorf("failed to update xsks_map: %v", err)
	}

	if err := p.Queues.Put(uint32(queueID), uint32(1)); err != nil {
		return fmt.Errorf("failed to update qidconf_map: %v", err)
	}
	return nil
}

// Unregister 取消注册指定队列的 socket
func (p *Program) Unregister(queueID int) error {
	if err := p.Queues.Put(uint32(queueID), uint32(0)); err != nil {
		return err
	}
	if err := p.Sockets.Delete(uint32(queueID)); err != nil {
		return err
	}
	return nil
}

// Close 关闭并释放程序资源
func (p *Program) Close() error {
	var firstErr error

	if p.DNSPorts != nil {
		if err := p.DNSPorts.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close dns_ports_map: %v", err)
		}
		p.DNSPorts = nil
	}

	if p.Metrics != nil {
		if err := p.Metrics.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close metrics_map: %v", err)
		}
		p.Metrics = nil
	}

	if p.Sockets != nil {
		if err := p.Sockets.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close xsks_map: %v", err)
		}
		p.Sockets = nil
	}

	if p.Queues != nil {
		if err := p.Queues.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close qidconf_map: %v", err)
		}
		p.Queues = nil
	}

	if p.Program != nil {
		if err := p.Program.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close XDP program: %v", err)
		}
		p.Program = nil
	}

	return firstErr
}

// LoadProgram 从 BPF 目标文件加载 XDP DNS 过滤程序
//
// 该程序只拦截指定 DNS 端口的 UDP 流量，其他所有流量（包括 SSH、HTTP 等）直接放行，
// 确保不会影响正常网络通信。
//
// 参数:
//   - bpfPath: BPF 程序文件路径 (如 "bpf/xdp_dns_filter_bpfel.o")
//
// 返回:
//   - *Program: 加载的程序实例
//   - error: 错误信息
//
// 使用示例:
//
//	program, err := xdp.LoadProgram("bpf/xdp_dns_filter_bpfel.o")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer program.Close()
//
//	// 设置要拦截的 DNS 端口
//	program.SetDNSPorts([]uint16{53})
//
//	// 附加到网卡
//	program.Attach(ifindex)
func LoadProgram(bpfPath string) (*Program, error) {
	// 加载 BPF collection
	col, err := ebpf.LoadCollection(bpfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF collection from %s: %v", bpfPath, err)
	}

	prog := &Program{}

	// 获取 XDP 程序
	var ok bool
	if prog.Program, ok = col.Programs["xdp_dns_filter"]; !ok {
		col.Close()
		return nil, fmt.Errorf("BPF program 'xdp_dns_filter' not found in %s", bpfPath)
	}

	// 获取必需的 maps
	if prog.Queues, ok = col.Maps["qidconf_map"]; !ok {
		col.Close()
		return nil, fmt.Errorf("map 'qidconf_map' not found in %s", bpfPath)
	}

	if prog.Sockets, ok = col.Maps["xsks_map"]; !ok {
		col.Close()
		return nil, fmt.Errorf("map 'xsks_map' not found in %s", bpfPath)
	}

	if prog.DNSPorts, ok = col.Maps["dns_ports_map"]; !ok {
		col.Close()
		return nil, fmt.Errorf("map 'dns_ports_map' not found in %s", bpfPath)
	}

	// 获取可选的 metrics map
	prog.Metrics = col.Maps["metrics_map"]

	return prog, nil
}

// removeProgram removes an existing XDP program from the given network interface.
func removeProgram(Ifindex int) error {
	var link netlink.Link
	var err error
	link, err = netlink.LinkByIndex(Ifindex)
	if err != nil {
		return err
	}
	if !isXdpAttached(link) {
		return nil
	}
	if err = netlink.LinkSetXdpFd(link, -1); err != nil {
		return fmt.Errorf("netlink.LinkSetXdpFd(link, -1) failed: %v", err)
	}
	for {
		link, err = netlink.LinkByIndex(Ifindex)
		if err != nil {
			return err
		}
		if !isXdpAttached(link) {
			break
		}
		time.Sleep(time.Second)
	}
	return nil
}

func isXdpAttached(link netlink.Link) bool {
	if link.Attrs() != nil && link.Attrs().Xdp != nil && link.Attrs().Xdp.Attached {
		return true
	}
	return false
}

// attachProgram attaches the given XDP program to the network interface.
func attachProgram(Ifindex int, program *ebpf.Program) error {
	link, err := netlink.LinkByIndex(Ifindex)
	if err != nil {
		return err
	}
	return netlink.LinkSetXdpFdWithFlags(link, program.FD(), int(DefaultXdpFlags))
}

// SetDNSPorts 设置需要拦截的 DNS 端口
func (p *Program) SetDNSPorts(ports []uint16) error {
	if p.DNSPorts == nil {
		return fmt.Errorf("dns_ports_map not initialized")
	}

	value := uint8(1)
	for _, port := range ports {
		if err := p.DNSPorts.Put(port, value); err != nil {
			return fmt.Errorf("failed to add DNS port %d: %v", port, err)
		}
	}

	return nil
}

// AddDNSPort 添加单个 DNS 端口
func (p *Program) AddDNSPort(port uint16) error {
	if p.DNSPorts == nil {
		return fmt.Errorf("dns_ports_map not initialized")
	}
	value := uint8(1)
	return p.DNSPorts.Put(port, value)
}

// RemoveDNSPort 移除 DNS 端口
func (p *Program) RemoveDNSPort(port uint16) error {
	if p.DNSPorts == nil {
		return fmt.Errorf("dns_ports_map not initialized")
	}
	return p.DNSPorts.Delete(port)
}

// GetMetrics 获取 XDP 程序统计指标
type XDPMetrics struct {
	TotalPackets uint64
	DNSPackets   uint64
	Redirected   uint64
	Blocked      uint64
	Passed       uint64
}

func (p *Program) GetMetrics() (*XDPMetrics, error) {
	if p.Metrics == nil {
		return nil, fmt.Errorf("metrics_map not initialized")
	}

	var key uint32 = 0
	var values []byte

	// Per-CPU map，需要读取所有 CPU 的值并汇总
	if err := p.Metrics.Lookup(key, &values); err != nil {
		return nil, fmt.Errorf("failed to read metrics: %v", err)
	}

	// 汇总所有 CPU 的指标
	metrics := &XDPMetrics{}
	// 每个 metrics 结构体 40 字节 (5 * uint64)
	structSize := 40
	numCPUs := len(values) / structSize

	for i := 0; i < numCPUs; i++ {
		offset := i * structSize
		if offset+structSize <= len(values) {
			metrics.TotalPackets += readUint64(values[offset:])
			metrics.DNSPackets += readUint64(values[offset+8:])
			metrics.Redirected += readUint64(values[offset+16:])
			metrics.Blocked += readUint64(values[offset+24:])
			metrics.Passed += readUint64(values[offset+32:])
		}
	}

	return metrics, nil
}

func readUint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
