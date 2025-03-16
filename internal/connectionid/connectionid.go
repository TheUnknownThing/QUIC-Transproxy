package connectionid

import (
	"encoding/binary"
	"errors"
)

const (
	// ConnectionIDLength is the length of connection ID
	ConnectionIDLength = 20
	// SNIIdentifierLength is the length of SNI identifier
	SNIIdentifierLength = 2
	TotalLength         = ConnectionIDLength + SNIIdentifierLength
)

var (
	ErrInvalidConnectionIDLength = errors.New("invalid connection ID length")
)

func ModifyConnectionID(originalID []byte, sniIdentifier uint16) ([]byte, error) {
	if len(originalID) != ConnectionIDLength {
		return nil, ErrInvalidConnectionIDLength
	}

	modifiedID := make([]byte, TotalLength)
	copy(modifiedID, originalID)

	binary.BigEndian.PutUint16(modifiedID[ConnectionIDLength:], sniIdentifier)

	return modifiedID, nil
}

func ExtractSNIIdentifier(modifiedID []byte) (uint16, error) {
	if len(modifiedID) != TotalLength {
		return 0, ErrInvalidConnectionIDLength
	}

	return binary.BigEndian.Uint16(modifiedID[ConnectionIDLength:]), nil
}

// RestoreConnectionID restores the original connection ID from the modified connection ID
func RestoreConnectionID(modifiedID []byte) ([]byte, error) {
	if len(modifiedID) != TotalLength {
		return nil, ErrInvalidConnectionIDLength
	}

	originalID := make([]byte, ConnectionIDLength)
	copy(originalID, modifiedID[:ConnectionIDLength])

	return originalID, nil
}
