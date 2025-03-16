package client

import (
	"quic-transproxy/internal/logger"
)

type SNISniffer struct {
	logger *logger.Logger
	sniMap map[string]string
}

func NewSNISniffer(logger *logger.Logger) *SNISniffer {
	return &SNISniffer{
		logger: logger,
		sniMap: make(map[string]string),
	}
}

func (s *SNISniffer) SniffSNI(packet []byte) (string, bool) {
	// PLACEHOLDER: SNI sniffing

	s.logger.Debug("SNI sniffing is currently a placeholder")

	// RETURN PLACEHOLDER: A website support http/3
	return "theunknown.site", true
}

func (s *SNISniffer) GetSNI(sourceAddr string) (string, bool) {
	sni, exists := s.sniMap[sourceAddr]
	return sni, exists
}

func (s *SNISniffer) SetSNI(sourceAddr string, sni string) {
	s.sniMap[sourceAddr] = sni
	s.logger.Debug("Set SNI %s for source address %s", sni, sourceAddr)
}
