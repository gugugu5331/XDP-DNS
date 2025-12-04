package worker

import (
	"encoding/binary"
	"errors"
	"log"

	"xdp-dns/pkg/dns"
)

// buildResponsePacket 构建响应数据包
func buildResponsePacket(origPkt []byte, dnsResponse []byte, pktInfo *PacketInfo) ([]byte, error) {
	if len(origPkt) < EthernetHeaderLen+IPv4HeaderLen+UDPHeaderLen {
		return nil, errors.New("original packet too short")
	}

	// 计算各层头部偏移
	var ipHeaderLen int
	ethType := binary.BigEndian.Uint16(origPkt[12:14])

	switch ethType {
	case EthTypeIPv4:
		ipHeaderLen = int(origPkt[EthernetHeaderLen]&0x0F) * 4
	case EthTypeIPv6:
		ipHeaderLen = IPv6HeaderLen
	default:
		return nil, errors.New("unsupported ethernet type")
	}

	// 计算响应包总长度
	totalLen := EthernetHeaderLen + ipHeaderLen + UDPHeaderLen + len(dnsResponse)
	response := make([]byte, totalLen)

	// 复制以太网头并交换 MAC 地址
	copy(response[0:6], origPkt[6:12])    // Dst MAC = 原 Src MAC
	copy(response[6:12], origPkt[0:6])    // Src MAC = 原 Dst MAC
	copy(response[12:14], origPkt[12:14]) // EtherType

	// 处理 IP 头
	ipStart := EthernetHeaderLen
	if ethType == EthTypeIPv4 {
		// 复制 IP 头
		copy(response[ipStart:ipStart+ipHeaderLen], origPkt[ipStart:ipStart+ipHeaderLen])

		// 交换源/目的 IP
		copy(response[ipStart+12:ipStart+16], origPkt[ipStart+16:ipStart+20]) // Src = 原 Dst
		copy(response[ipStart+16:ipStart+20], origPkt[ipStart+12:ipStart+16]) // Dst = 原 Src

		// 更新总长度
		binary.BigEndian.PutUint16(response[ipStart+2:ipStart+4], uint16(ipHeaderLen+UDPHeaderLen+len(dnsResponse)))

		// 清除校验和 (让内核或网卡计算)
		binary.BigEndian.PutUint16(response[ipStart+10:ipStart+12], 0)

		// 重新计算 IP 校验和
		checksum := ipv4Checksum(response[ipStart : ipStart+ipHeaderLen])
		binary.BigEndian.PutUint16(response[ipStart+10:ipStart+12], checksum)

	} else {
		// IPv6
		copy(response[ipStart:ipStart+ipHeaderLen], origPkt[ipStart:ipStart+ipHeaderLen])

		// 交换源/目的 IP
		copy(response[ipStart+8:ipStart+24], origPkt[ipStart+24:ipStart+40]) // Src = 原 Dst
		copy(response[ipStart+24:ipStart+40], origPkt[ipStart+8:ipStart+24]) // Dst = 原 Src

		// 更新 Payload Length
		binary.BigEndian.PutUint16(response[ipStart+4:ipStart+6], uint16(UDPHeaderLen+len(dnsResponse)))
	}

	// 处理 UDP 头
	udpStart := ipStart + ipHeaderLen
	origUDPStart := EthernetHeaderLen + ipHeaderLen

	// 交换源/目的端口
	binary.BigEndian.PutUint16(response[udpStart:udpStart+2], binary.BigEndian.Uint16(origPkt[origUDPStart+2:origUDPStart+4])) // Src = 原 Dst
	binary.BigEndian.PutUint16(response[udpStart+2:udpStart+4], binary.BigEndian.Uint16(origPkt[origUDPStart:origUDPStart+2])) // Dst = 原 Src
	binary.BigEndian.PutUint16(response[udpStart+4:udpStart+6], uint16(UDPHeaderLen+len(dnsResponse)))                         // UDP Length
	binary.BigEndian.PutUint16(response[udpStart+6:udpStart+8], 0)                                                             // Checksum (可选)

	// 复制 DNS 响应
	copy(response[udpStart+UDPHeaderLen:], dnsResponse)

	// 计算 UDP 校验和 (对于 IPv6 是必须的)
	if ethType == EthTypeIPv6 {
		udpChecksum := calculateUDPChecksum(response, ipStart, udpStart, len(dnsResponse), true)
		binary.BigEndian.PutUint16(response[udpStart+6:udpStart+8], udpChecksum)
	}

	return response, nil
}

// sendResponse 发送 DNS 响应
func (p *Pool) sendResponse(pkt Packet, dnsResp []byte, pktInfo *PacketInfo) {
	if pkt.Socket == nil || pkt.OrigData == nil {
		return
	}

	// 构建响应数据包
	respPkt, err := buildResponsePacket(pkt.OrigData, dnsResp, pktInfo)
	if err != nil {
		log.Printf("Failed to build response packet: %v", err)
		return
	}

	// 获取 TX 描述符
	txDescs := pkt.Socket.GetDescs(1, false)
	if len(txDescs) == 0 {
		log.Printf("No TX descriptors available")
		return
	}

	// 复制响应到 UMEM
	frame := pkt.Socket.GetFrame(txDescs[0])
	if len(frame) < len(respPkt) {
		log.Printf("Frame too small for response")
		return
	}

	copy(frame, respPkt)
	txDescs[0].Len = uint32(len(respPkt))

	// 发送
	numSent := pkt.Socket.Transmit(txDescs)
	if numSent == 0 {
		log.Printf("Failed to transmit response: no descriptors sent")
		return
	}

	// 完成发送
	pkt.Socket.Complete(pkt.Socket.NumCompleted())
}

// buildBlockResponse 构建阻止响应 (NXDOMAIN 或 REFUSED)
func buildBlockResponse(query *dns.Message, nxdomain bool) []byte {
	if query == nil || len(query.RawData) < 12 {
		return nil
	}

	// 复制原始查询
	resp := make([]byte, len(query.RawData))
	copy(resp, query.RawData)

	// 修改标志位
	// 设置 QR=1 (响应), OPCODE=0 (标准查询), AA=1 (权威), TC=0, RD=原值
	// RA=1 (递归可用), Z=0, AD=0, CD=0, RCODE
	flags := uint16(0x8180) // QR=1, AA=1, RA=1
	if nxdomain {
		flags |= 0x0003 // RCODE = NXDOMAIN (3)
	} else {
		flags |= 0x0005 // RCODE = REFUSED (5)
	}
	resp[2] = byte(flags >> 8)
	resp[3] = byte(flags)

	// QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
	resp[4] = 0
	resp[5] = 1
	resp[6] = 0
	resp[7] = 0
	resp[8] = 0
	resp[9] = 0
	resp[10] = 0
	resp[11] = 0

	return resp
}

// ipv4Checksum 计算 IPv4 头部校验和
func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i+1 < len(header) {
			sum += uint32(header[i])<<8 | uint32(header[i+1])
		} else {
			sum += uint32(header[i]) << 8
		}
	}
	// 折叠到 16 位
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// calculateUDPChecksum 计算 UDP 校验和
func calculateUDPChecksum(packet []byte, ipStart, udpStart, dnsLen int, isIPv6 bool) uint16 {
	var sum uint32

	if isIPv6 {
		// 伪首部: 源IP(16) + 目的IP(16) + UDP长度(4) + 协议(4)
		for i := ipStart + 8; i < ipStart+40; i += 2 {
			sum += uint32(packet[i])<<8 | uint32(packet[i+1])
		}
		udpLen := UDPHeaderLen + dnsLen
		sum += uint32(udpLen) // UDP 长度
		sum += 17             // 协议号 (UDP)
	} else {
		// IPv4 伪首部: 源IP(4) + 目的IP(4) + 协议(1) + UDP长度(2)
		for i := ipStart + 12; i < ipStart+20; i += 2 {
			sum += uint32(packet[i])<<8 | uint32(packet[i+1])
		}
		udpLen := UDPHeaderLen + dnsLen
		sum += 17             // 协议号
		sum += uint32(udpLen) // UDP 长度
	}

	// UDP 头和数据
	udpEnd := udpStart + UDPHeaderLen + dnsLen
	for i := udpStart; i < udpEnd; i += 2 {
		if i+1 < udpEnd {
			// 跳过校验和字段
			if i == udpStart+6 {
				continue
			}
			sum += uint32(packet[i])<<8 | uint32(packet[i+1])
		} else {
			sum += uint32(packet[i]) << 8
		}
	}

	// 折叠
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	checksum := ^uint16(sum)
	if checksum == 0 {
		checksum = 0xFFFF
	}
	return checksum
}
