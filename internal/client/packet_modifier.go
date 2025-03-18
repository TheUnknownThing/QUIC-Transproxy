package client

import (
	"quic-transproxy/internal/shared/packet"
)

type PacketModifier struct{}

func NewPacketModifier() *PacketModifier {
	return &PacketModifier{}
}

func (m *PacketModifier) ModifyPacket(data []byte, sniIdentifier []byte) *packet.Packet {
	if len(sniIdentifier) != 2 {
		return packet.NewPacket(data)
	}
	p := packet.NewPacket(data)
	p.AppendSNIIdentifier(sniIdentifier)
	return p
}
