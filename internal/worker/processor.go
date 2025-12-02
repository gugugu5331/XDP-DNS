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

// handleAction 处理过滤动作
func (p *Pool) handleAction(pkt Packet, msg *dns.Message, action filter.Action,
	rule *filter.Rule, pktInfo *PacketInfo, metricsCollector *metrics.Collector) {

	switch action {
	case filter.ActionAllow:
		if metricsCollector != nil {
			metricsCollector.IncAllowed()
		}

	case filter.ActionBlock:
		// 生成 NXDOMAIN 响应
		response := dns.BuildNXDomainResponse(msg)
		if response != nil {
			p.sendResponse(pkt, response, pktInfo)
		}
		if metricsCollector != nil {
			metricsCollector.IncBlocked()
		}
		if rule != nil {
			log.Printf("Blocked: %s (rule: %s)", msg.GetQueryDomain(), rule.ID)
		}

	case filter.ActionRedirect:
		// 生成重定向响应
		if rule != nil && rule.RedirectIP != nil {
			var response []byte
			if msg.GetQueryType() == dns.TypeAAAA {
				response = dns.BuildAAAAResponse(msg, rule.RedirectIP, rule.RedirectTTL)
			} else {
				response = dns.BuildAResponse(msg, rule.RedirectIP, rule.RedirectTTL)
			}
			if response != nil {
				p.sendResponse(pkt, response, pktInfo)
			}
		}
		if metricsCollector != nil {
			metricsCollector.IncRedirected()
		}

	case filter.ActionLog:
		log.Printf("Logged: %s type=%s from=%s",
			msg.GetQueryDomain(),
			dns.TypeName(msg.GetQueryType()),
			pktInfo.SrcIP)
		if metricsCollector != nil {
			metricsCollector.IncLogged()
		}
	}
}

// sendResponse 发送响应
func (p *Pool) sendResponse(pkt Packet, dnsResponse []byte, pktInfo *PacketInfo) {
	responsePkt, err := buildResponsePacket(pkt.Data, dnsResponse, pktInfo)
	if err != nil {
		log.Printf("Failed to build response: %v", err)
		return
	}

	// 获取 TX 描述符
	txDescs := p.options.Socket.GetDescs(1, false)
	if len(txDescs) == 0 {
		return
	}

	// 复制响应数据到 TX 缓冲区
	frame := p.options.Socket.GetFrame(txDescs[0])
	copy(frame, responsePkt)
	txDescs[0].Len = uint32(len(responsePkt))

	// 发送
	p.options.Socket.Transmit(txDescs)
}
