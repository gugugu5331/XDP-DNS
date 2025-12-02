package dns

import (
	"encoding/binary"
	"net"
)

// ResponseBuilder DNS 响应构建器
type ResponseBuilder struct {
	buffer []byte
	offset int
}

// NewResponseBuilder 创建响应构建器
func NewResponseBuilder(capacity int) *ResponseBuilder {
	return &ResponseBuilder{
		buffer: make([]byte, 0, capacity),
	}
}

// BuildNXDomainResponse 构建 NXDOMAIN 响应
func BuildNXDomainResponse(query *Message) []byte {
	if query == nil || len(query.Questions) == 0 {
		return nil
	}

	rb := NewResponseBuilder(512)

	// 设置响应标志: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
	flags := uint16(0x8180 | uint16(RCodeNXDomain))

	rb.writeHeader(query.Header.ID, flags, 1, 0, 0, 0)
	rb.writeQuestion(query.Questions[0])

	return rb.buffer
}

// BuildRefusedResponse 构建 REFUSED 响应
func BuildRefusedResponse(query *Message) []byte {
	if query == nil || len(query.Questions) == 0 {
		return nil
	}

	rb := NewResponseBuilder(512)

	// 设置响应标志: QR=1, RD=1, RA=1, RCODE=5 (REFUSED)
	flags := uint16(0x8180 | uint16(RCodeRefused))

	rb.writeHeader(query.Header.ID, flags, 1, 0, 0, 0)
	rb.writeQuestion(query.Questions[0])

	return rb.buffer
}

// BuildAResponse 构建 A 记录响应
func BuildAResponse(query *Message, ip net.IP, ttl uint32) []byte {
	if query == nil || len(query.Questions) == 0 {
		return nil
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	rb := NewResponseBuilder(512)

	// 设置响应标志: QR=1, AA=1, RD=1, RA=1, RCODE=0
	flags := uint16(0x8580)

	rb.writeHeader(query.Header.ID, flags, 1, 1, 0, 0)
	rb.writeQuestion(query.Questions[0])
	rb.writeARecord(query.Questions[0].Name, ip4, ttl)

	return rb.buffer
}

// BuildAAAAResponse 构建 AAAA 记录响应
func BuildAAAAResponse(query *Message, ip net.IP, ttl uint32) []byte {
	if query == nil || len(query.Questions) == 0 {
		return nil
	}

	ip6 := ip.To16()
	if ip6 == nil || ip.To4() != nil {
		return nil
	}

	rb := NewResponseBuilder(512)
	flags := uint16(0x8580)

	rb.writeHeader(query.Header.ID, flags, 1, 1, 0, 0)
	rb.writeQuestion(query.Questions[0])
	rb.writeAAAARecord(query.Questions[0].Name, ip6, ttl)

	return rb.buffer
}

// writeHeader 写入 DNS 头部
func (rb *ResponseBuilder) writeHeader(id, flags uint16, qd, an, ns, ar uint16) {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], qd)
	binary.BigEndian.PutUint16(header[6:8], an)
	binary.BigEndian.PutUint16(header[8:10], ns)
	binary.BigEndian.PutUint16(header[10:12], ar)
	rb.buffer = append(rb.buffer, header...)
	rb.offset += 12
}

// writeQuestion 写入问题部分
func (rb *ResponseBuilder) writeQuestion(q Question) {
	rb.writeName(q.Name)
	qtype := make([]byte, 4)
	binary.BigEndian.PutUint16(qtype[0:2], q.QType)
	binary.BigEndian.PutUint16(qtype[2:4], q.QClass)
	rb.buffer = append(rb.buffer, qtype...)
	rb.offset += 4
}

// writeName 写入域名
func (rb *ResponseBuilder) writeName(name string) {
	if name == "" {
		rb.buffer = append(rb.buffer, 0)
		rb.offset++
		return
	}

	labels := splitDomainName(name)
	for _, label := range labels {
		if len(label) > 63 {
			label = label[:63]
		}
		rb.buffer = append(rb.buffer, byte(len(label)))
		rb.buffer = append(rb.buffer, []byte(label)...)
		rb.offset += 1 + len(label)
	}
	rb.buffer = append(rb.buffer, 0)
	rb.offset++
}

// writeARecord 写入 A 记录
func (rb *ResponseBuilder) writeARecord(name string, ip net.IP, ttl uint32) {
	rb.writeName(name)
	record := make([]byte, 10)
	binary.BigEndian.PutUint16(record[0:2], TypeA)
	binary.BigEndian.PutUint16(record[2:4], ClassIN)
	binary.BigEndian.PutUint32(record[4:8], ttl)
	binary.BigEndian.PutUint16(record[8:10], 4)
	rb.buffer = append(rb.buffer, record...)
	rb.buffer = append(rb.buffer, ip[:4]...)
	rb.offset += 14
}

// writeAAAARecord 写入 AAAA 记录
func (rb *ResponseBuilder) writeAAAARecord(name string, ip net.IP, ttl uint32) {
	rb.writeName(name)
	record := make([]byte, 10)
	binary.BigEndian.PutUint16(record[0:2], TypeAAAA)
	binary.BigEndian.PutUint16(record[2:4], ClassIN)
	binary.BigEndian.PutUint32(record[4:8], ttl)
	binary.BigEndian.PutUint16(record[8:10], 16)
	rb.buffer = append(rb.buffer, record...)
	rb.buffer = append(rb.buffer, ip[:16]...)
	rb.offset += 26
}

// splitDomainName 分割域名为标签
func splitDomainName(name string) []string {
	var labels []string
	var label string
	for _, c := range name {
		if c == '.' {
			if label != "" {
				labels = append(labels, label)
				label = ""
			}
		} else {
			label += string(c)
		}
	}
	if label != "" {
		labels = append(labels, label)
	}
	return labels
}
