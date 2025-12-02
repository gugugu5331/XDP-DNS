package dns

import (
	"testing"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantDomain string
		wantQType  uint16
		wantErr    bool
	}{
		{
			name: "valid A query for example.com",
			data: []byte{
				0x12, 0x34, // ID
				0x01, 0x00, // Flags (standard query)
				0x00, 0x01, // QDCount = 1
				0x00, 0x00, // ANCount = 0
				0x00, 0x00, // NSCount = 0
				0x00, 0x00, // ARCount = 0
				// Question: example.com
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // null terminator
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
			},
			wantDomain: "example.com",
			wantQType:  TypeA,
			wantErr:    false,
		},
		{
			name: "valid AAAA query for test.org",
			data: []byte{
				0xAB, 0xCD, // ID
				0x01, 0x00, // Flags
				0x00, 0x01, // QDCount = 1
				0x00, 0x00, // ANCount = 0
				0x00, 0x00, // NSCount = 0
				0x00, 0x00, // ARCount = 0
				// Question: test.org
				0x04, 't', 'e', 's', 't',
				0x03, 'o', 'r', 'g',
				0x00,       // null terminator
				0x00, 0x1C, // Type AAAA
				0x00, 0x01, // Class IN
			},
			wantDomain: "test.org",
			wantQType:  TypeAAAA,
			wantErr:    false,
		},
		{
			name:    "too short message",
			data:    []byte{0x12, 0x34, 0x01},
			wantErr: true,
		},
		{
			name:    "empty message",
			data:    []byte{},
			wantErr: true,
		},
	}

	p := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := p.Parse(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if msg.GetQueryDomain() != tt.wantDomain {
				t.Errorf("Parse() domain = %v, want %v", msg.GetQueryDomain(), tt.wantDomain)
			}
			if msg.GetQueryType() != tt.wantQType {
				t.Errorf("Parse() qtype = %v, want %v", msg.GetQueryType(), tt.wantQType)
			}
		})
	}
}

func TestMessage_IsQuery(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
		want  bool
	}{
		{"query", 0x0100, true},
		{"response", 0x8180, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Message{Header: Header{Flags: tt.flags}}
			if got := m.IsQuery(); got != tt.want {
				t.Errorf("IsQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkParser_Parse(b *testing.B) {
	data := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCount
		0x00, 0x00, // ANCount
		0x00, 0x00, // NSCount
		0x00, 0x00, // ARCount
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01,
		0x00, 0x01,
	}

	p := NewParser()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = p.Parse(data)
	}
}

