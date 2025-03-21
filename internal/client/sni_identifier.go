package client

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
)

type SNIIdentifierGenerator struct {
	cache      map[string][]byte
	ClientMark int
}

func NewSNIIdentifierGenerator(ClientMark int) *SNIIdentifierGenerator {
	return &SNIIdentifierGenerator{
		cache:      make(map[string][]byte),
		ClientMark: ClientMark,
	}
}

func (g *SNIIdentifierGenerator) Generate(srcIP net.IP, srcPort int) []byte {
	key := fmt.Sprintf("%s:%d:%d", srcIP.String(), srcPort, g.ClientMark)

	if id, exists := g.cache[key]; exists {
		return id
	}

	// FNV-1a hash
	h := fnv.New32a()
	h.Write(srcIP)
	binary.Write(h, binary.BigEndian, uint16(srcPort))
	binary.Write(h, binary.BigEndian, uint32(g.ClientMark)) // Include ClientMark in hash

	hash := h.Sum32()
	identifier := make([]byte, 2)
	// Lower 16 bits of the hash
	binary.BigEndian.PutUint16(identifier, uint16(hash))

	// cache result
	g.cache[key] = identifier

	return identifier
}

func (g *SNIIdentifierGenerator) GenerateFromAddr(addr net.Addr) []byte {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return []byte{0xFF, 0xFF} // invalid address
		}

		ip := net.ParseIP(host)
		if ip == nil {
			return []byte{0xFF, 0xFF}
		}

		var portNum int
		fmt.Sscanf(port, "%d", &portNum)

		return g.Generate(ip, portNum)
	}

	return g.Generate(udpAddr.IP, udpAddr.Port)
}
