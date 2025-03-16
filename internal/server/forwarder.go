package server

import (
	"context"
	"crypto/tls"
	"net"
	"quic-transproxy/internal/logger"
	"quic-transproxy/internal/quiclib"
	"sync"
)

type QUICForwarder struct {
	logger               *logger.Logger
	sniMapper            *SNIMapper
	sniExtractor         *SNIIdentifierExtractor
	connectionIDRestorer *ConnectionIDRestorer
	connections          map[uint16]*quiclib.QUICConn
	mutex                sync.RWMutex
	ctx                  context.Context
	cancel               context.CancelFunc
}

func NewQUICForwarder(
	logger *logger.Logger,
	sniMapper *SNIMapper,
	sniExtractor *SNIIdentifierExtractor,
	connectionIDRestorer *ConnectionIDRestorer,
) *QUICForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICForwarder{
		logger:               logger,
		sniMapper:            sniMapper,
		sniExtractor:         sniExtractor,
		connectionIDRestorer: connectionIDRestorer,
		connections:          make(map[uint16]*quiclib.QUICConn),
		ctx:                  ctx,
		cancel:               cancel,
	}
}

func (f *QUICForwarder) HandleConnection(conn *quiclib.QUICConn) {
	go f.processStreams(conn)
}

func (f *QUICForwarder) processStreams(conn *quiclib.QUICConn) {
	buffer := make([]byte, 2048)

	for {
		n, err := conn.Stream.Read(buffer)
		if err != nil {
			f.logger.Error("Failed to read from QUIC stream: %v", err)
			return
		}

		packet := buffer[:n]

		sniIdentifier, err := f.sniExtractor.ExtractSNIIdentifier(packet)
		if err != nil {
			f.logger.Error("Failed to extract SNI identifier: %v", err)
			continue
		}

		sni, exists := f.sniMapper.GetSNI(sniIdentifier)
		if !exists {
			sni = "theunknown.site"
			f.sniMapper.AddMapping(sniIdentifier, sni)
		}

		restoredPacket, err := f.connectionIDRestorer.RestorePacket(packet)
		if err != nil {
			f.logger.Error("Failed to restore packet: %v", err)
			continue
		}

		targetConn, err := f.getOrCreateConnection(sniIdentifier, sni)
		if err != nil {
			f.logger.Error("Failed to get or create connection to target server: %v", err)
			continue
		}

		_, err = targetConn.Stream.Write(restoredPacket)
		if err != nil {
			f.logger.Error("Failed to write packet to target server: %v", err)
			continue
		}

		f.logger.Debug("Forwarded packet to target server %s for SNI identifier %d", sni, sniIdentifier)
	}
}

// getOrCreateConnection gets an existing connection or creates a new one
func (f *QUICForwarder) getOrCreateConnection(sniIdentifier uint16, sni string) (*quiclib.QUICConn, error) {
	f.mutex.RLock()
	conn, exists := f.connections[sniIdentifier]
	f.mutex.RUnlock()

	if exists {
		return conn, nil
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	if conn, exists = f.connections[sniIdentifier]; exists {
		return conn, nil
	}

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // FOR TEST ONLY
	}

	targetAddr := net.JoinHostPort(sni, "443")

	quicClient := quiclib.NewQUICClient()
	conn, err := quicClient.Connect(f.ctx, targetAddr, tlsConfig)
	if err != nil {
		return nil, err
	}

	f.connections[sniIdentifier] = conn
	f.logger.Info("Created new connection to target server %s for SNI identifier %d", sni, sniIdentifier)

	return conn, nil
}

func (f *QUICForwarder) Close() {
	f.cancel()

	f.mutex.Lock()
	defer f.mutex.Unlock()

	for _, conn := range f.connections {
		conn.Session.CloseWithError(0, "forwarder closed")
	}
}
