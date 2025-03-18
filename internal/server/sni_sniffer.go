package server

type SNISniffer struct{}

func NewSNISniffer() *SNISniffer {
	return &SNISniffer{}
}

func (s *SNISniffer) Sniff(data []byte) string {
	return "example.com"
}
