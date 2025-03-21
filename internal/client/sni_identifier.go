package client

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
)

type SNIIdentifierGenerator struct {
	cache map[string][]byte
}

func NewSNIIdentifierGenerator() *SNIIdentifierGenerator {
	return &SNIIdentifierGenerator{
		cache: make(map[string][]byte),
	}
}

func (g *SNIIdentifierGenerator) SNIIdentifierToString(id []byte) string {
	return fmt.Sprintf("%X", id)
}

func (g *SNIIdentifierGenerator) SNIIdentifierFromString(s string) []byte {
	id := make([]byte, 2)
	fmt.Sscanf(s, "%X", &id)
	return id
}

func (g *SNIIdentifierGenerator) Generate(srcIP net.IP, srcPort int) []byte {
	key := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)

	if id, exists := g.cache[key]; exists {
		return id
	}

	// FNV-1a hash
	h := fnv.New32a()
	h.Write(srcIP)
	binary.Write(h, binary.BigEndian, uint16(srcPort))

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
