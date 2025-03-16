package server

import (
	"quic-transproxy/internal/connectionid"
	"quic-transproxy/internal/logger"
)

type SNIIdentifierExtractor struct {
	logger *logger.Logger
}

func NewSNIIdentifierExtractor(logger *logger.Logger) *SNIIdentifierExtractor {
	return &SNIIdentifierExtractor{
		logger: logger,
	}
}

func (e *SNIIdentifierExtractor) ExtractSNIIdentifier(packet []byte) (uint16, error) {
	if len(packet) < connectionid.TotalLength {
		e.logger.Error("Packet too short to contain Connection ID and SNI identifier")
		return 0, connectionid.ErrInvalidConnectionIDLength
	}

	modifiedID := packet[:connectionid.TotalLength]

	sniIdentifier, err := connectionid.ExtractSNIIdentifier(modifiedID)
	if err != nil {
		e.logger.Error("Failed to extract SNI identifier: %v", err)
		return 0, err
	}

	e.logger.Debug("Extracted SNI identifier %d", sniIdentifier)

	return sniIdentifier, nil
}
