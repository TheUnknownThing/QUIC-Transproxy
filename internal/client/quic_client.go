package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"quic-transproxy/internal/shared/logger"
	"quic-transproxy/internal/shared/quic_lib"
	"sync"
	"time"
)

const (
	maxReconnectAttempts = 10
	initialBackoff       = 500 * time.Millisecond
	maxBackoff           = 30 * time.Second
)

type QUICClient struct {
	proxyAddr     string
	proxyPort     int
	log           logger.Logger
	listener      *Listener
	sniGen        *SNIIdentifierGenerator
	packetMod     *PacketModifier
	conn          *quic_lib.QUICConnection
	connMutex     sync.Mutex
	reconnecting  bool
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
		reconnecting:  false,
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

func (c *QUICClient) ensureConnection(ctx context.Context) error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	if c.conn != nil {
		return nil
	}

	if c.reconnecting {
		return fmt.Errorf("reconnection already in progress")
	}

	c.reconnecting = true
	defer func() { c.reconnecting = false }()

	proxyAddrStr := fmt.Sprintf("%s:%d", c.proxyAddr, c.proxyPort)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-transproxy"},
	}

	backoff := initialBackoff
	var err error

	for attempt := 1; attempt <= maxReconnectAttempts; attempt++ {
		c.log.Info("Connecting to proxy server at %s (attempt %d/%d)",
			proxyAddrStr, attempt, maxReconnectAttempts)

		c.conn, err = quic_lib.Dial(ctx, proxyAddrStr, tlsConfig)
		if err == nil {
			c.log.Info("Successfully connected to proxy server")

			go c.monitorConnection(ctx)
			return nil
		}

		c.log.Error("Failed to connect: %v. Retrying in %v...", err, backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff = time.Duration(math.Min(
				float64(backoff*2),
				float64(maxBackoff),
			))
		}
	}

	return fmt.Errorf("failed to connect after %d attempts: %w", maxReconnectAttempts, err)
}

func (c *QUICClient) monitorConnection(ctx context.Context) {
	pingTicker := time.NewTicker(10 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTicker.C:
			if c.conn == nil {
				c.log.Warn("Connection to server lost, attempting to reconnect...")
				c.reconnect(ctx)
				continue
			}

			if !c.isConnectionAlive() {
				c.log.Warn("Connection to server unhealthy, attempting to reconnect...")
				c.reconnect(ctx)
			}
		}
	}
}

func (c *QUICClient) isConnectionAlive() bool {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	if c.conn == nil {
		return false
	}

	return true
}

func (c *QUICClient) reconnect(ctx context.Context) {
	c.connMutex.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMutex.Unlock()

	go func() {
		if err := c.ensureConnection(ctx); err != nil {
			c.log.Error("Failed to reconnect: %v", err)
		}
	}()
}

func (c *QUICClient) Start(ctx context.Context) error {
	if err := c.ensureConnection(ctx); err != nil {
		return err
	}

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

			if err := c.ensureConnection(ctx); err != nil {
				c.log.Error("Connection unavailable: %v", err)
				continue
			}

			sniIdentifier := c.sniGen.GenerateFromAddr(srcAddr)

			modifiedPacket := c.packetMod.ModifyPacket(data, sniIdentifier)

			c.connMutex.Lock()
			currentConn := c.conn
			c.connMutex.Unlock()

			if currentConn == nil {
				c.log.Error("Connection lost, packet will be dropped")
				continue
			}

			stream, err := currentConn.OpenStream()
			if err != nil {
				c.log.Error("Failed to open stream: %v", err)
				go c.reconnect(ctx)
				continue
			}

			_, err = stream.Write(modifiedPacket.Data)
			if err != nil {
				c.log.Error("Failed to send data: %v", err)
				stream.Close()
				go c.reconnect(ctx)
				continue
			}

			go c.handleResponse(ctx, stream, srcAddr)
		}
	}
}

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
				go c.reconnect(ctx)
				return
			}

			c.log.Debug("Received %d bytes from proxy server", n)

			// 将响应转发回原始客户端
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
