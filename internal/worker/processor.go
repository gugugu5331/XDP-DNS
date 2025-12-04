// Package worker 提供数据包处理工作池
// 用于 DNS 威胁流量分析系统
package worker

import (
	"encoding/binary"
	"errors"
	"log"
	"net"

	"xdp-dns/pkg/dns"
	"xdp-dns/pkg/filter"
	"xdp-dns/pkg/metrics"
)

const (
	EthernetHeaderLen = 14
	IPv4HeaderLen     = 20
	IPv6HeaderLen     = 40
	UDPHeaderLen      = 8

	EthTypeIPv4 = 0x0800
	EthTypeIPv6 = 0x86DD
)

var (
	ErrPacketTooShort = errors.New("packet too short")
	ErrNotUDP         = errors.New("not a UDP packet")
	ErrNotDNS         = errors.New("not a DNS packet")
)

// extractDNSPayload 从数据包中提取 DNS 负载
func extractDNSPayload(data []byte) ([]byte, *PacketInfo, error) {
	if len(data) < EthernetHeaderLen {
		return nil, nil, ErrPacketTooShort
	}

	info := &PacketInfo{}

	// 解析以太网头
	copy(info.DstMAC[:], data[0:6])
	copy(info.SrcMAC[:], data[6:12])
	ethType := binary.BigEndian.Uint16(data[12:14])

	var ipHeaderLen int
	var protocol uint8
	var l4Offset int

	switch ethType {
	case EthTypeIPv4:
		if len(data) < EthernetHeaderLen+IPv4HeaderLen {
			return nil, nil, ErrPacketTooShort
		}
		info.IsIPv6 = false
		ihl := int(data[EthernetHeaderLen]&0x0F) * 4
		ipHeaderLen = ihl
		protocol = data[EthernetHeaderLen+9]
		info.SrcIP = net.IP(data[EthernetHeaderLen+12 : EthernetHeaderLen+16]).String()
		info.DstIP = net.IP(data[EthernetHeaderLen+16 : EthernetHeaderLen+20]).String()
		l4Offset = EthernetHeaderLen + ipHeaderLen

	case EthTypeIPv6:
		if len(data) < EthernetHeaderLen+IPv6HeaderLen {
			return nil, nil, ErrPacketTooShort
		}
		info.IsIPv6 = true
		ipHeaderLen = IPv6HeaderLen
		protocol = data[EthernetHeaderLen+6] // Next Header
		info.SrcIP = net.IP(data[EthernetHeaderLen+8 : EthernetHeaderLen+24]).String()
		info.DstIP = net.IP(data[EthernetHeaderLen+24 : EthernetHeaderLen+40]).String()
		l4Offset = EthernetHeaderLen + ipHeaderLen

	default:
		return nil, nil, ErrNotUDP
	}

	// 检查是否为 UDP
	if protocol != 17 { // IPPROTO_UDP
		return nil, nil, ErrNotUDP
	}

	// 解析 UDP 头
	if len(data) < l4Offset+UDPHeaderLen {
		return nil, nil, ErrPacketTooShort
	}

	info.SrcPort = binary.BigEndian.Uint16(data[l4Offset : l4Offset+2])
	info.DstPort = binary.BigEndian.Uint16(data[l4Offset+2 : l4Offset+4])
	udpLen := binary.BigEndian.Uint16(data[l4Offset+4 : l4Offset+6])

	// 提取 DNS payload
	dnsOffset := l4Offset + UDPHeaderLen
	dnsEnd := l4Offset + int(udpLen)
	if dnsEnd > len(data) {
		dnsEnd = len(data)
	}

	if dnsEnd <= dnsOffset {
		return nil, nil, ErrNotDNS
	}

	return data[dnsOffset:dnsEnd], info, nil
}

// handleActionWithResponse 处理检测动作并可选发送响应
func (p *Pool) handleActionWithResponse(pkt Packet, msg *dns.Message, action filter.Action,
	rule *filter.Rule, pktInfo *PacketInfo, metricsCollector *metrics.Collector) {

	// 先尝试使用自定义响应处理器
	if p.options.ResponseHandler != nil {
		if dnsResp, shouldSend := p.options.ResponseHandler(msg, action, rule, pktInfo); shouldSend && dnsResp != nil {
			p.sendResponse(pkt, dnsResp, pktInfo)
			return
		}
	}

	// 默认处理逻辑
	switch action {
	case filter.ActionAllow:
		// 正常流量 - 仅统计
		if metricsCollector != nil {
			metricsCollector.IncAllowed()
		}

	case filter.ActionBlock:
		// 威胁流量 - 记录并可选发送拒绝响应
		if metricsCollector != nil {
			metricsCollector.IncBlocked()
		}
		if rule != nil {
			log.Printf("THREAT DETECTED: domain=%s rule=%s src=%s type=%s",
				msg.GetQueryDomain(), rule.ID, pktInfo.SrcIP,
				dns.TypeName(msg.GetQueryType()))
		}

		// 如果配置了发送阻止响应
		if p.options.ResponseConfig != nil && p.options.ResponseConfig.BlockResponse {
			dnsResp := buildBlockResponse(msg, p.options.ResponseConfig.NXDomain)
			if dnsResp != nil {
				p.sendResponse(pkt, dnsResp, pktInfo)
			}
		}

	case filter.ActionLog:
		// 可疑流量 - 记录详细信息
		log.Printf("SUSPICIOUS: domain=%s src=%s:%d dst=%s:%d type=%s",
			msg.GetQueryDomain(),
			pktInfo.SrcIP, pktInfo.SrcPort,
			pktInfo.DstIP, pktInfo.DstPort,
			dns.TypeName(msg.GetQueryType()))
		if metricsCollector != nil {
			metricsCollector.IncLogged()
		}
	}
}
