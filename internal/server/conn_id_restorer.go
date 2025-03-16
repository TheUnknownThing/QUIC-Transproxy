package server

import (
	"quic-transproxy/internal/connectionid"
	"quic-transproxy/internal/logger"
)

type ConnectionIDRestorer struct {
	logger *logger.Logger
}

func NewConnectionIDRestorer(logger *logger.Logger) *ConnectionIDRestorer {
	return &ConnectionIDRestorer{
		logger: logger,
	}
}

func (r *ConnectionIDRestorer) RestorePacket(packet []byte) ([]byte, error) {
	if len(packet) < connectionid.TotalLength {
		r.logger.Error("Packet too short to restore Connection ID")
		return nil, connectionid.ErrInvalidConnectionIDLength
	}

	modifiedID := packet[:connectionid.TotalLength]

	originalID, err := connectionid.RestoreConnectionID(modifiedID)
	if err != nil {
		r.logger.Error("Failed to restore Connection ID: %v", err)
		return nil, err
	}

	restoredPacket := make([]byte, len(packet)-connectionid.SNIIdentifierLength)
	copy(restoredPacket, originalID)
	copy(restoredPacket[connectionid.ConnectionIDLength:], packet[connectionid.TotalLength:])

	r.logger.Debug("Restored original Connection ID")

	return restoredPacket, nil
}
