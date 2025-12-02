package dns

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrTooShort      = errors.New("DNS message too short")
	ErrTruncated     = errors.New("DNS message truncated")
	ErrPointerLoop   = errors.New("DNS pointer loop detected")
	ErrInvalidLabel  = errors.New("DNS invalid label")
	ErrInvalidHeader = errors.New("DNS invalid header")
)

// Parser DNS 消息解析器
type Parser struct {
	maxNameLength int // 最大域名长度
	maxLabels     int // 最大标签数
}

// NewParser 创建新的 DNS 解析器
func NewParser() *Parser {
	return &Parser{
		maxNameLength: 255,
		maxLabels:     128,
	}
}

// Parse 解析 DNS 消息
func (p *Parser) Parse(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, ErrTooShort
	}

	msg := &Message{
		RawData:   data,
		Questions: make([]Question, 0, 1),
	}

	// 解析头部
	msg.Header = Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	// 解析问题部分
	offset := 12
	for i := uint16(0); i < msg.Header.QDCount; i++ {
		q, newOffset, err := p.parseQuestion(data, offset)
		if err != nil {
			return nil, err
		}
		msg.Questions = append(msg.Questions, q)
		offset = newOffset
	}

	// 解析回答部分 (可选)
	for i := uint16(0); i < msg.Header.ANCount && offset < len(data); i++ {
		rr, newOffset, err := p.parseResourceRecord(data, offset)
		if err != nil {
			break // 允许部分解析
		}
		msg.Answers = append(msg.Answers, rr)
		offset = newOffset
	}

	return msg, nil
}

// parseQuestion 解析问题部分
func (p *Parser) parseQuestion(data []byte, offset int) (Question, int, error) {
	name, newOffset, err := p.parseName(data, offset)
	if err != nil {
		return Question{}, 0, err
	}

	if newOffset+4 > len(data) {
		return Question{}, 0, ErrTruncated
	}

	return Question{
		Name:   strings.ToLower(name),
		QType:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
		QClass: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
	}, newOffset + 4, nil
}

// parseResourceRecord 解析资源记录
func (p *Parser) parseResourceRecord(data []byte, offset int) (ResourceRecord, int, error) {
	name, newOffset, err := p.parseName(data, offset)
	if err != nil {
		return ResourceRecord{}, 0, err
	}

	if newOffset+10 > len(data) {
		return ResourceRecord{}, 0, ErrTruncated
	}

	rr := ResourceRecord{
		Name:     strings.ToLower(name),
		Type:     binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
		Class:    binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
		TTL:      binary.BigEndian.Uint32(data[newOffset+4 : newOffset+8]),
		RDLength: binary.BigEndian.Uint16(data[newOffset+8 : newOffset+10]),
	}

	newOffset += 10
	rdataEnd := newOffset + int(rr.RDLength)
	if rdataEnd > len(data) {
		return ResourceRecord{}, 0, ErrTruncated
	}

	rr.RData = data[newOffset:rdataEnd]
	return rr, rdataEnd, nil
}

// parseName 解析域名
func (p *Parser) parseName(data []byte, offset int) (string, int, error) {
	var labels []string
	visited := make(map[int]bool)
	originalOffset := offset
	jumped := false

	for labelCount := 0; labelCount < p.maxLabels; labelCount++ {
		if offset >= len(data) {
			return "", 0, ErrTruncated
		}

		// 检测指针循环
		if visited[offset] {
			return "", 0, ErrPointerLoop
		}
		visited[offset] = true

		length := int(data[offset])

		if length == 0 {
			if !jumped {
				originalOffset = offset + 1
			}
			return strings.Join(labels, "."), originalOffset, nil
		}

		// 压缩指针 (高两位为 11)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, ErrTruncated
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				originalOffset = offset + 2
				jumped = true
			}
			offset = ptr
			continue
		}

		offset++
		if offset+length > len(data) {
			return "", 0, ErrTruncated
		}

		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	return "", 0, ErrInvalidLabel
}

