package xdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

const (
	EthernetHeaderLen = 14
	IPv4HeaderLen     = 20
	IPv6HeaderLen     = 40
	UOAHeaderLen      = 12
	UDPHeaderLen      = 8

	IPv4ProtocolIndex = 23

	UDPMinimumSize  = 8
	IPv4MinimumSize = 20

	UOAProtocol = 248
	UDPProtocol = 17
)

var options = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// EthernetHeader1 represents the Ethernet frame header.
type EthernetHeader1 struct {
	DestMAC [6]byte // 目的MAC地址
	SrcMAC  [6]byte // 源MAC地址
	EthType uint16  // 类型字段，例如0x0800表示IPv4，0x86DD表示IPv6
}

// IPv4Header1 represents the IPv4 header.
type IPv4Header1 struct {
	Version        uint8  // 4 bits
	IHL            uint8  // 4 bits - Internet Header Length
	TOS            uint8  // Type of Service
	TotalLength    uint16 // Total Length
	ID             uint16 // Identification
	Flags          uint16 // Flags (3 bits) and Fragment Offset (13 bits)
	TTL            uint8  // Time to Live
	Protocol       uint8  // Protocol
	HeaderChecksum uint16 // Header Checksum
	SrcIP          net.IP // Source IP Address
	DstIP          net.IP // Destination IP Address
}

// IPv6Header represents the IPv6 header.
type IPv6Header struct {
	Version      uint8  // 4 bits
	TrafficClass uint8  // 8 bits
	FlowLabel    uint32 // 20 bits
	PayloadLen   uint16 // Payload Length
	NextHeader   uint8  // Next Header
	HopLimit     uint8  // Hop Limit
	SrcIP        net.IP // Source IP Address
	DstIP        net.IP // Destination IP Address
}

// UDPHeader represents the UDP header.
type UDPHeader struct {
	SrcPort  uint16 // 源端口
	DstPort  uint16 // 目的端口
	Length   uint16 // 长度
	Checksum uint16 // 校验和
}

// ParseEthernetHeader parses the given data as an Ethernet header.
func ParseEthernetHeader(data []byte) (*EthernetHeader1, error) {
	if len(data) < EthernetHeaderLen {
		return nil, fmt.Errorf("data is too short to be an Ethernet header")
	}

	header := &EthernetHeader1{
		DestMAC: [6]byte{data[0], data[1], data[2], data[3], data[4], data[5]},
		SrcMAC:  [6]byte{data[6], data[7], data[8], data[9], data[10], data[11]},
		EthType: binary.BigEndian.Uint16(data[12:14]),
	}

	return header, nil
}

// ParseIPv4Header parses the given data as an IPv4 header.
func ParseIPv4Header(data []byte) (*IPv4Header1, error) {
	if len(data) < IPv4HeaderLen {
		return nil, fmt.Errorf("data is too short to be an IPv4 header")
	}

	header := &IPv4Header1{
		Version:        data[0] >> 4,
		IHL:            data[0] & 0x0F,
		TOS:            data[1],
		TotalLength:    binary.BigEndian.Uint16(data[2:4]),
		ID:             binary.BigEndian.Uint16(data[4:6]),
		Flags:          binary.BigEndian.Uint16(data[6:8]) & 0xE000,
		TTL:            data[8],
		Protocol:       data[9],
		HeaderChecksum: binary.BigEndian.Uint16(data[10:12]),
		SrcIP:          net.IPv4(data[12], data[13], data[14], data[15]),
		DstIP:          net.IPv4(data[16], data[17], data[18], data[19]),
	}

	return header, nil
}

// ParseIPv6Header parses the given data as an IPv6 header.
func ParseIPv6Header(data []byte) (*IPv6Header, error) {
	if len(data) < IPv6HeaderLen {
		return nil, fmt.Errorf("data is too short to be an IPv6 header")
	}

	header := &IPv6Header{
		Version:      data[0] >> 4,
		TrafficClass: (data[0]&0x0F)<<4 | (data[1] >> 4),
		FlowLabel:    (uint32(data[1]&0x0F) << 16) | (uint32(data[2]) << 8) | uint32(data[3]),
		PayloadLen:   binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   data[6],
		HopLimit:     data[7],
		SrcIP:        net.IP(data[8:24]),
		DstIP:        net.IP(data[24:40]),
	}

	return header, nil
}

// ParseUDPHeader parses the given data as a UDP header.
func ParseUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < UDPHeaderLen {
		return nil, fmt.Errorf("data is too short to be a UDP header")
	}

	header := &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}

	return header, nil
}

func ParseUDPPacket(data []byte) ([]byte, bool, error) {
	isUoa := false
	ethHeader, err := ParseEthernetHeader(data)
	if err != nil {
		return nil, isUoa, err
	}

	var ipHeader interface{}
	var parseErr error

	switch ethHeader.EthType {
	case 0x0800: // IPv4
		ipHeader, parseErr = ParseIPv4Header(data[EthernetHeaderLen:])
	case 0x86DD: // IPv6
		ipHeader, parseErr = ParseIPv6Header(data[EthernetHeaderLen:])
	default:
		return nil, isUoa, fmt.Errorf("Unsupported Ethernet type: %v\n", ethHeader.EthType)
	}

	if parseErr != nil {
		return nil, isUoa, parseErr
	}

	var udpHeader *UDPHeader
	var ipHeaderLen int

	if iph, ok := ipHeader.(*IPv4Header1); ok {
		ipHeaderLen = IPv4HeaderLen
		if iph.Protocol == UOAProtocol {
			isUoa = true
			udpHeader, parseErr = ParseUDPHeader(data[EthernetHeaderLen+ipHeaderLen+UOAHeaderLen:])
		} else {
			udpHeader, parseErr = ParseUDPHeader(data[EthernetHeaderLen+ipHeaderLen:])
		}
	} else if _, ok = ipHeader.(*IPv6Header); ok {
		ipHeaderLen = IPv6HeaderLen
		udpHeader, parseErr = ParseUDPHeader(data[EthernetHeaderLen+ipHeaderLen:])
	}

	if parseErr != nil {
		return nil, isUoa, parseErr
	}

	//if ipv4, ok := ipHeader.(*IPv4Header1); ok {
	//	// get src IP & dst IP
	//	fmt.Println(ipv4.SrcIP.String(), ipv4.DstIP.String())
	//} else if _, ok = ipHeader.(*IPv6Header); ok {
	//	// get src IP & dst IP
	//}

	if udpHeader != nil {
		if isUoa {
			return data[EthernetHeaderLen+ipHeaderLen+UDPHeaderLen+UOAHeaderLen : EthernetHeaderLen+ipHeaderLen+UOAHeaderLen+int(udpHeader.Length)], isUoa, nil
		} else {
			return data[EthernetHeaderLen+ipHeaderLen+UDPHeaderLen : EthernetHeaderLen+ipHeaderLen+int(udpHeader.Length)], false, nil
		}
	}
	return nil, isUoa, fmt.Errorf("udpHeader is nil\n")
}

func ParseUDPPacketUseGP(pktData []byte) ([]byte, bool) {
	packet := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udpBuffer, _ := udpLayer.(*layers.UDP)
		return udpBuffer.Payload, true
	}

	return nil, false
}

func GenResponsePacket(isUoa bool, pktData []byte, responseData []byte, dMac net.HardwareAddr) ([]byte, error) {
	// uoa must be ipv4
	if isUoa {
		pktData[IPv4ProtocolIndex] = UDPProtocol
		pktData = append(pktData[:EthernetHeaderLen+IPv4HeaderLen], pktData[EthernetHeaderLen+IPv4HeaderLen+UOAHeaderLen:]...)
	}

	packet := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
	// 解析以太网头部
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, errors.New("No Ethernet layer found\n")
	}

	eth, _ := ethLayer.(*layers.Ethernet)

	// 解析IP头部
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var ip *layers.IPv4
	var isIPv4 bool
	if ipLayer != nil {
		ip, _ = ipLayer.(*layers.IPv4)
		isIPv4 = true
	} else {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		if ipLayer == nil {
			return nil, errors.New("No IP layer found\n")
		}
	}

	// 解析UDP头部
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)

		// 构建UDP头部
		udpResponse := &layers.UDP{
			SrcPort: udp.DstPort,
			DstPort: udp.SrcPort,
			Length:  uint16(len(responseData) + UDPMinimumSize),
		}
		udpResponse.SetNetworkLayerForChecksum(ip)

		// 构建IP头部
		var ipResponse gopacket.SerializableLayer
		if isIPv4 {
			ipResponse = &layers.IPv4{
				Version:    4,
				IHL:        5,
				TOS:        0,
				Length:     uint16(len(responseData) + UDPMinimumSize + IPv4MinimumSize),
				Id:         0,
				Flags:      0,
				FragOffset: 0,
				TTL:        64,
				Protocol:   layers.IPProtocolUDP,
				SrcIP:      ip.DstIP,
				DstIP:      ip.SrcIP,
			}
		} else {
			ip6, _ := ipLayer.(*layers.IPv6)
			ipResponse = &layers.IPv6{
				Version:      6,
				TrafficClass: 0,
				FlowLabel:    0,
				Length:       uint16(len(responseData) + UDPMinimumSize),
				NextHeader:   layers.IPProtocolUDP,
				HopLimit:     64,
				SrcIP:        ip6.DstIP,
				DstIP:        ip6.SrcIP,
			}
		}

		// 构建以太网头部
		ethResponse := &layers.Ethernet{
			DstMAC:       eth.SrcMAC,
			SrcMAC:       eth.DstMAC,
			EthernetType: eth.EthernetType,
		}

		if dMac != nil {
			ethResponse.DstMAC = dMac
		}

		// 组合数据包
		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, options, ethResponse, ipResponse, udpResponse, gopacket.Payload(responseData))
		if err != nil {
			return nil, err
		}

		return buffer.Bytes(), nil
	} else {
		return nil, errors.New("No UDP layer found\n")
	}
}

func BuildResponse(pktData *[]byte, responseData []byte) {
	l := len(responseData) - len(*pktData)
	if l > 0 {
		*pktData = append(*pktData, make([]byte, l)...)
	}
	copy((*pktData)[:], responseData)
}
