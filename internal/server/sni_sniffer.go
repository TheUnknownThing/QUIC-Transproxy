package server

type SNISniffer struct{}

func NewSNISniffer() *SNISniffer {
	return &SNISniffer{}
}

func (s *SNISniffer) Sniff(data []byte) string {
	// PLACEHOLDER: Implement SNI sniffing logic here
	return "theunknown.site"
}
