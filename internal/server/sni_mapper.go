package server

import (
	"encoding/hex"
	"sync"
)

type SNIMapper struct {
	mutex   sync.RWMutex
	mapping map[string]string
}

func NewSNIMapper() *SNIMapper {
	return &SNIMapper{
		mapping: make(map[string]string),
	}
}

func (m *SNIMapper) Update(identifier []byte, sni string) {
	if len(identifier) == 0 || sni == "" {
		return
	}

	key := hex.EncodeToString(identifier)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.mapping[key] = sni
}

func (m *SNIMapper) Lookup(identifier []byte) string {
	if len(identifier) == 0 {
		return ""
	}

	key := hex.EncodeToString(identifier)

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.mapping[key]
}
