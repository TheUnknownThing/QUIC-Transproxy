package server

import (
	"quic-transproxy/internal/logger"
	"sync"
)

type SNIMapper struct {
	logger   *logger.Logger
	mappings map[uint16]string
	mutex    sync.RWMutex
}

func NewSNIMapper(logger *logger.Logger) *SNIMapper {
	return &SNIMapper{
		logger:   logger,
		mappings: make(map[uint16]string),
	}
}

func (m *SNIMapper) AddMapping(sniIdentifier uint16, sni string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.mappings[sniIdentifier] = sni
	m.logger.Debug("Added mapping: SNI identifier %d -> %s", sniIdentifier, sni)
}

func (m *SNIMapper) GetSNI(sniIdentifier uint16) (string, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	sni, exists := m.mappings[sniIdentifier]
	return sni, exists
}

func (m *SNIMapper) DeleteMapping(sniIdentifier uint16) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.mappings[sniIdentifier]; exists {
		delete(m.mappings, sniIdentifier)
		m.logger.Debug("Deleted mapping for SNI identifier %d", sniIdentifier)
	}
}
