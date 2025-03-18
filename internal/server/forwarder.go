package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"quic-transproxy/internal/shared/logger"
	"quic-transproxy/internal/shared/quic_lib"
	"sync"
	"time"
)

type QUICForwarder struct {
	log         logger.Logger
	mutex       sync.RWMutex
	connections map[string]*quic_lib.QUICConnection
	timeout     time.Duration
}

func NewQUICForwarder(log logger.Logger) *QUICForwarder {
	return &QUICForwarder{
		log:         log,
		connections: make(map[string]*quic_lib.QUICConnection),
		timeout:     5 * time.Second,
	}
}

func (f *QUICForwarder) Forward(ctx context.Context, targetSNI string, data []byte) ([]byte, error) {
	forwardCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	conn, err := f.getOrCreateConnection(forwardCtx, targetSNI)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection to %s: %w", targetSNI, err)
	}

	stream, err := conn.OpenStream()
	if err != nil {
		f.removeConnection(targetSNI)
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	_, err = stream.Write(data)
	if err != nil {
		f.removeConnection(targetSNI)
		return nil, fmt.Errorf("failed to send data: %w", err)
	}

	buffer := make([]byte, 65535)
	n, err := stream.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return buffer[:n], nil
}

func (f *QUICForwarder) getOrCreateConnection(ctx context.Context, targetSNI string) (*quic_lib.QUICConnection, error) {
	f.mutex.RLock()
	conn, exists := f.connections[targetSNI]
	f.mutex.RUnlock()

	if exists {
		return conn, nil
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, exists = f.connections[targetSNI]
	if exists {
		return conn, nil
	}

	tlsConfig := &tls.Config{
		ServerName: targetSNI,
	}

	addr := fmt.Sprintf("%s:443", targetSNI)
	conn, err := quic_lib.Dial(ctx, addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	f.connections[targetSNI] = conn
	f.log.Info("Created new connection to %s", targetSNI)

	return conn, nil
}

func (f *QUICForwarder) removeConnection(targetSNI string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if conn, exists := f.connections[targetSNI]; exists {
		conn.Close()
		delete(f.connections, targetSNI)
		f.log.Info("Removed connection to %s", targetSNI)
	}
}
