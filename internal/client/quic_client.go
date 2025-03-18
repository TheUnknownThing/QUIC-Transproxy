package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"quic-transproxy/internal/shared/logger"
	"quic-transproxy/internal/shared/quic_lib"
	"sync"
)

type QUICClient struct {
	proxyAddr     string
	proxyPort     int
	log           logger.Logger
	listener      *Listener
	sniGen        *SNIIdentifierGenerator
	packetMod     *PacketModifier
	conn          *quic_lib.QUICConnection
	responseConns map[string]*net.UDPConn
	mutex         sync.RWMutex
}

func NewQUICClient(proxyAddr string, proxyPort int, listener *Listener, log logger.Logger) *QUICClient {
	return &QUICClient{
		proxyAddr:     proxyAddr,
		proxyPort:     proxyPort,
		log:           log,
		listener:      listener,
		sniGen:        NewSNIIdentifierGenerator(),
		packetMod:     NewPacketModifier(),
		responseConns: make(map[string]*net.UDPConn),
	}
}

func (c *QUICClient) getOrCreateUDPConn(addrStr string) (*net.UDPConn, error) {
	c.mutex.RLock()
	conn, exists := c.responseConns[addrStr]
	c.mutex.RUnlock()

	if exists {
		return conn, nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	conn, exists = c.responseConns[addrStr]
	if exists {
		return conn, nil
	}

	udpConn, err := net.Dial("udp", addrStr)
	if err != nil {
		return nil, err
	}

	udpConn2, ok := udpConn.(*net.UDPConn)
	if !ok {
		udpConn.Close()
		return nil, fmt.Errorf("failed to convert to UDPConn")
	}

	c.responseConns[addrStr] = udpConn2
	return udpConn2, nil
}

func (c *QUICClient) Start(ctx context.Context) error {
	proxyAddrStr := fmt.Sprintf("%s:%d", c.proxyAddr, c.proxyPort)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For debugging purposes
		NextProtos:         []string{"quic-transproxy"},
	}

	var err error
	// TODO: 0-RTT Handshake (DialEarly)
	c.conn, err = quic_lib.Dial(ctx, proxyAddrStr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to proxy server: %w", err)
	}
	defer c.conn.Close()

	c.log.Info("Connected to proxy server at %s", proxyAddrStr)

	packetCh := c.listener.GetPacketChannel()
	addrCh := c.listener.GetAddrChannel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case data := <-packetCh:
			srcAddr, ok := <-addrCh
			if !ok {
				c.log.Error("Address channel closed")
				return fmt.Errorf("address channel closed")
			}

			sniIdentifier := c.sniGen.GenerateFromAddr(srcAddr)

			modifiedPacket := c.packetMod.ModifyPacket(data, sniIdentifier)

			stream, err := c.conn.OpenStream()
			if err != nil {
				c.log.Error("Failed to open stream: %v", err)
				continue
			}

			_, err = stream.Write(modifiedPacket.Data)
			if err != nil {
				c.log.Error("Failed to send data: %v", err)
				stream.Close()
				continue
			}

			go c.handleResponse(ctx, stream, srcAddr)
		}
	}
}

// handleResponse 处理服务器响应
func (c *QUICClient) handleResponse(ctx context.Context, stream *quic_lib.QUICStream, srcAddr net.Addr) {
	defer stream.Close()

	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := stream.Read(buffer)
			if err != nil {
				c.log.Error("Error reading response: %v", err)
				return
			}

			c.log.Debug("Received %d bytes from proxy server", n)

			udpAddr, ok := srcAddr.(*net.UDPAddr)
			if !ok {
				c.log.Error("Invalid source address type")
				continue
			}

			addrStr := udpAddr.String()
			udpConn, err := c.getOrCreateUDPConn(addrStr)
			if err != nil {
				c.log.Error("Failed to get UDP conn: %v", err)
				continue
			}

			_, err = udpConn.Write(buffer[:n])
			if err != nil {
				c.log.Error("Failed to send response: %v", err)
			}
		}
	}
}
