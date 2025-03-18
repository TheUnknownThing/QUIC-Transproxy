package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"quic-transproxy/internal/shared/logger"
	"quic-transproxy/internal/shared/packet"
	"quic-transproxy/internal/shared/quic_lib"
	"time"
)

type QUICListener struct {
	listenAddr string
	listenPort int
	log        logger.Logger
	listener   *quic_lib.QUICListener
}

func NewQUICListener(addr string, port int, log logger.Logger) *QUICListener {
	return &QUICListener{
		listenAddr: addr,
		listenPort: port,
		log:        log,
	}
}

func (l *QUICListener) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", l.listenAddr, l.listenPort)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{generateSelfSignedCert()},
		NextProtos:   []string{"quic-transproxy"},
	}

	var err error
	l.listener, err = quic_lib.NewQUICListener(addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}
	defer l.listener.Close()

	l.log.Info("QUIC listener started on %s", addr)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := l.listener.Accept(ctx)
			if err != nil {
				l.log.Error("Error accepting connection: %v", err)
				continue
			}

			l.log.Info("Accepted new connection")

			handler := NewConnectionHandler(conn, l.log)

			go handler.Handle(ctx)
		}
	}
}

func generateSelfSignedCert() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"QUIC Transproxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return tlsCert
}

type ConnectionHandler struct {
	conn          *quic_lib.QUICConnection
	log           logger.Logger
	sniSniffer    *SNISniffer
	sniMapper     *SNIMapper
	quicForwarder *QUICForwarder
}

func NewConnectionHandler(conn *quic_lib.QUICConnection, log logger.Logger) *ConnectionHandler {
	return &ConnectionHandler{
		conn:          conn,
		log:           log,
		sniSniffer:    NewSNISniffer(),
		sniMapper:     NewSNIMapper(),
		quicForwarder: NewQUICForwarder(log),
	}
}

func (h *ConnectionHandler) Handle(ctx context.Context) {
	defer h.conn.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			stream, err := h.conn.AcceptStream(ctx)
			if err != nil {
				h.log.Error("Error accepting stream: %v", err)
				return
			}

			go h.handleStream(ctx, stream)
		}
	}
}

func (h *ConnectionHandler) handleStream(ctx context.Context, stream *quic_lib.QUICStream) {
	defer stream.Close()

	buffer := make([]byte, 65535)
	n, err := stream.Read(buffer)
	if err != nil {
		h.log.Error("Error reading from stream: %v", err)
		return
	}

	data := buffer[:n]
	h.log.Debug("Received %d bytes from client", n)

	p := packet.NewPacket(data)
	sniIdentifier := p.ExtractSNIIdentifier()

	if len(sniIdentifier) != 2 {
		h.log.Error("Invalid SNI identifier length: %d", len(sniIdentifier))
		return
	}

	sni := h.sniSniffer.Sniff(p.Data)

	if sni != "" {
		h.sniMapper.Update(sniIdentifier, sni)
	}

	targetSNI := h.sniMapper.Lookup(sniIdentifier)
	if targetSNI == "" {
		h.log.Warn("No target SNI found for identifier")
		return
	}

	p.RestorePacket()

	response, err := h.quicForwarder.Forward(ctx, targetSNI, p.Data)
	if err != nil {
		h.log.Error("Error forwarding packet: %v", err)
		return
	}

	_, err = stream.Write(response)
	if err != nil {
		h.log.Error("Error writing response: %v", err)
		return
	}

	h.log.Debug("Sent %d bytes response to client", len(response))
}
