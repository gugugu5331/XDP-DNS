package dns

// DNS 消息类型
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeANY   uint16 = 255
)

// DNS 类别
const (
	ClassIN uint16 = 1 // Internet
	ClassCS uint16 = 2 // CSNET
	ClassCH uint16 = 3 // CHAOS
	ClassHS uint16 = 4 // Hesiod
)

// DNS 响应码
const (
	RCodeNoError        uint8 = 0 // No error
	RCodeFormatError    uint8 = 1 // Format error
	RCodeServerFailure  uint8 = 2 // Server failure
	RCodeNXDomain       uint8 = 3 // Non-existent domain
	RCodeNotImplemented uint8 = 4 // Not implemented
	RCodeRefused        uint8 = 5 // Query refused
)

// DNS 操作码
const (
	OpcodeQuery  uint8 = 0 // Standard query
	OpcodeIQuery uint8 = 1 // Inverse query
	OpcodeStatus uint8 = 2 // Server status request
)

// Header 表示 DNS 消息头部
type Header struct {
	ID      uint16 // 事务ID
	Flags   uint16 // 标志位
	QDCount uint16 // 问题数
	ANCount uint16 // 回答数
	NSCount uint16 // 授权数
	ARCount uint16 // 附加数
}

// Question 表示 DNS 问题部分
type Question struct {
	Name   string // 查询的域名
	QType  uint16 // 查询类型
	QClass uint16 // 查询类别
}

// ResourceRecord 表示 DNS 资源记录
type ResourceRecord struct {
	Name     string // 域名
	Type     uint16 // 类型
	Class    uint16 // 类别
	TTL      uint32 // 生存时间
	RDLength uint16 // 数据长度
	RData    []byte // 数据
}

// Message 表示完整的 DNS 消息
type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
	RawData     []byte
}

// DNS 标志位掩码
const (
	FlagQR     uint16 = 0x8000 // Query/Response
	FlagOpcode uint16 = 0x7800 // Operation code
	FlagAA     uint16 = 0x0400 // Authoritative answer
	FlagTC     uint16 = 0x0200 // Truncated
	FlagRD     uint16 = 0x0100 // Recursion desired
	FlagRA     uint16 = 0x0080 // Recursion available
	FlagZ      uint16 = 0x0070 // Reserved
	FlagRCode  uint16 = 0x000F // Response code
)

// IsQuery 检查是否为查询消息
func (m *Message) IsQuery() bool {
	return m.Header.Flags&FlagQR == 0
}

// IsResponse 检查是否为响应消息
func (m *Message) IsResponse() bool {
	return m.Header.Flags&FlagQR != 0
}

// GetRCode 获取响应码
func (m *Message) GetRCode() uint8 {
	return uint8(m.Header.Flags & FlagRCode)
}

// GetQueryDomain 获取查询域名
func (m *Message) GetQueryDomain() string {
	if len(m.Questions) > 0 {
		return m.Questions[0].Name
	}
	return ""
}

// GetQueryType 获取查询类型
func (m *Message) GetQueryType() uint16 {
	if len(m.Questions) > 0 {
		return m.Questions[0].QType
	}
	return 0
}

// TypeName 返回查询类型名称
func TypeName(qtype uint16) string {
	switch qtype {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeANY:
		return "ANY"
	default:
		return "UNKNOWN"
	}
}

