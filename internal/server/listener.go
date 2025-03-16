package server

import (
	"context"
	"crypto/tls"
	"quic-transproxy/internal/logger"
	"quic-transproxy/internal/quiclib"
)

type QUICListener struct {
	listenAddr string
	logger     *logger.Logger
	quicServer quiclib.QUICServer
	connChan   chan *quiclib.QUICConn
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewQUICListener(listenAddr string, logger *logger.Logger) *QUICListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICListener{
		listenAddr: listenAddr,
		logger:     logger,
		quicServer: quiclib.NewQUICServer(),
		connChan:   make(chan *quiclib.QUICConn, 10),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (l *QUICListener) Start() error {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{generateSelfSignedCert()}, // PLACEHOLDER: Need to generate REAL certificate in production
	}

	err := l.quicServer.Listen(l.listenAddr, tlsConfig)
	if err != nil {
		l.logger.Error("Failed to listen for QUIC connections: %v", err)
		return err
	}

	l.logger.Info("Listening for QUIC connections on %s", l.listenAddr)

	go l.acceptConnections()

	return nil
}

func (l *QUICListener) acceptConnections() {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
			conn, err := l.quicServer.Accept(l.ctx)
			if err != nil {
				l.logger.Error("Failed to accept QUIC connection: %v", err)
				continue
			}

			l.logger.Info("Accepted new QUIC connection")

			select {
			case l.connChan <- conn:
			default:
				l.logger.Warn("Connection channel full, closing connection")
				conn.Session.CloseWithError(0, "server busy")
			}
		}
	}
}

func (l *QUICListener) GetConnectionChan() <-chan *quiclib.QUICConn {
	return l.connChan
}

func (l *QUICListener) Close() error {
	l.cancel()
	if l.quicServer != nil {
		return l.quicServer.Close()
	}
	return nil
}

func generateSelfSignedCert() tls.Certificate {
	// PLACEHOLDER: Need to generate REAL certificate in production
	return tls.Certificate{}
}
