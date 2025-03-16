package client

import (
	"quic-transproxy/internal/connectionid"
	"quic-transproxy/internal/logger"
)

type ConnectionIDModifier struct {
	logger *logger.Logger
}

func NewConnectionIDModifier(logger *logger.Logger) *ConnectionIDModifier {
	return &ConnectionIDModifier{
		logger: logger,
	}
}

func (m *ConnectionIDModifier) ModifyPacket(packet []byte, sniIdentifier uint16) ([]byte, error) {
	// This simplify the first 20 bytes of the packet to be the Connection ID
	// TODO: Further implementation is needed to handle the actual packet
	if len(packet) < connectionid.ConnectionIDLength {
		m.logger.Error("Packet too short to contain Connection ID")
		return nil, connectionid.ErrInvalidConnectionIDLength
	}

	originalID := packet[:connectionid.ConnectionIDLength]

	modifiedID, err := connectionid.ModifyConnectionID(originalID, sniIdentifier)
	if err != nil {
		m.logger.Error("Failed to modify Connection ID: %v", err)
		return nil, err
	}

	modifiedPacket := make([]byte, len(packet)+connectionid.SNIIdentifierLength)
	copy(modifiedPacket, modifiedID)
	copy(modifiedPacket[connectionid.TotalLength:], packet[connectionid.ConnectionIDLength:])

	m.logger.Debug("Modified packet with SNI identifier %d", sniIdentifier)

	return modifiedPacket, nil
}
