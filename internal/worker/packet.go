package worker

import (
	"encoding/binary"
	"errors"
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
		copy(response[ipStart+8:ipStart+24], origPkt[ipStart+24:ipStart+40])  // Src = 原 Dst
		copy(response[ipStart+24:ipStart+40], origPkt[ipStart+8:ipStart+24])  // Dst = 原 Src

		// 更新 Payload Length
		binary.BigEndian.PutUint16(response[ipStart+4:ipStart+6], uint16(UDPHeaderLen+len(dnsResponse)))
	}

	// 处理 UDP 头
	udpStart := ipStart + ipHeaderLen
	origUDPStart := EthernetHeaderLen + ipHeaderLen

	// 交换源/目的端口
	binary.BigEndian.PutUint16(response[udpStart:udpStart+2], binary.BigEndian.Uint16(origPkt[origUDPStart+2:origUDPStart+4]))   // Src = 原 Dst
	binary.BigEndian.PutUint16(response[udpStart+2:udpStart+4], binary.BigEndian.Uint16(origPkt[origUDPStart:origUDPStart+2]))   // Dst = 原 Src
	binary.BigEndian.PutUint16(response[udpStart+4:udpStart+6], uint16(UDPHeaderLen+len(dnsResponse))) // UDP Length
	binary.BigEndian.PutUint16(response[udpStart+6:udpStart+8], 0) // Checksum (可选)

	// 复制 DNS 响应
	copy(response[udpStart+UDPHeaderLen:], dnsResponse)

	// 计算 UDP 校验和 (对于 IPv6 是必须的)
	if ethType == EthTypeIPv6 {
		udpChecksum := calculateUDPChecksum(response, ipStart, udpStart, len(dnsResponse), true)
		binary.BigEndian.PutUint16(response[udpStart+6:udpStart+8], udpChecksum)
	}

	return response, nil
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
		sum += 17                  // 协议号
		sum += uint32(udpLen)      // UDP 长度
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

