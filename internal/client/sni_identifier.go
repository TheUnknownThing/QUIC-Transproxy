package client

import (
	"hash/fnv"
	"net"
	"quic-transproxy/internal/logger"
)

type SNIIdentifierGenerator struct {
	logger *logger.Logger
	cache  map[string]uint16
}

func NewSNIIdentifierGenerator(logger *logger.Logger) *SNIIdentifierGenerator {
	return &SNIIdentifierGenerator{
		logger: logger,
		cache:  make(map[string]uint16),
	}
}

func (g *SNIIdentifierGenerator) GenerateIdentifier(sourceIP net.IP, sourcePort int) uint16 {
	key := sourceIP.String() + ":" + string(sourcePort)

	// check if the identifier is already cached
	if id, exists := g.cache[key]; exists {
		g.logger.Debug("Using cached SNI identifier %d for %s", id, key)
		return id
	}

	h := fnv.New32a()
	h.Write(sourceIP)
	h.Write([]byte{byte(sourcePort >> 8), byte(sourcePort)})

	// use the lower 16 bits of the hash value as the identifier
	identifier := uint16(h.Sum32() & 0xFFFF)

	g.cache[key] = identifier

	g.logger.Debug("Generated new SNI identifier %d for %s", identifier, key)

	return identifier
}

// GenerateIdentifierFromAddr generates an identifier from a net.Addr
func (g *SNIIdentifierGenerator) GenerateIdentifierFromAddr(addr net.Addr) uint16 {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return g.GenerateIdentifier(udpAddr.IP, udpAddr.Port)
	}

	h := fnv.New32a()
	h.Write([]byte(addr.String()))

	identifier := uint16(h.Sum32() & 0xFFFF)
	g.logger.Debug("Generated new SNI identifier %d for address %s", identifier, addr.String())

	return identifier
}
