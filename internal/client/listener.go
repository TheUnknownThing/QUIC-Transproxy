package client

import (
	"context"
	"fmt"
	"net"
	"quic-transproxy/internal/shared/logger"
	"quic-transproxy/internal/shared/packet"
	"quic-transproxy/internal/shared/safemap"
)

type TransparentProxyClient struct {
	listenAddr      string
	listenPort      int
	listenConn      *net.UDPConn
	proxyServerAddr string
	proxyServerPort int
	log             logger.Logger
	sniGenerator    *SNIIdentifierGenerator

	appConnections *safemap.SafeMap[string, *net.UDPAddr]
	serverConn     *net.UDPConn // Connection to the proxy server
}

func NewTransparentProxyClient(listenAddr string, listenPort int, proxyAddr string, proxyPort int, log logger.Logger) *TransparentProxyClient {
	return &TransparentProxyClient{
		listenAddr:      listenAddr,
		listenPort:      listenPort,
		proxyServerAddr: proxyAddr,
		proxyServerPort: proxyPort,
		log:             log,
		sniGenerator:    NewSNIIdentifierGenerator(),
		appConnections:  safemap.New[string, *net.UDPAddr](),
	}
}

func (c *TransparentProxyClient) Start(ctx context.Context) error {
	err := c.connectToProxyServer()
	if err != nil {
		return fmt.Errorf("failed to connect to proxy server: %w", err)
	}
	defer c.serverConn.Close()

	return c.listenForLocalTraffic(ctx)
}

func (c *TransparentProxyClient) connectToProxyServer() error {
	serverAddr := fmt.Sprintf("%s:%d", c.proxyServerAddr, c.proxyServerPort)
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}

	c.serverConn = conn
	c.log.Info("Connected to proxy server at %s", serverAddr)

	go c.receiveFromProxyServer()

	return nil
}

func (c *TransparentProxyClient) listenForLocalTraffic(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", c.listenAddr, c.listenPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	c.listenConn = conn

	defer conn.Close()

	c.log.Info("Listening for local traffic on %s", addr)

	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				c.log.Error("Error reading from application: %v", err)
				continue
			}

			data := make([]byte, n)
			copy(data, buffer[:n])

			c.log.Debug("Received %d bytes from application %s", n, addr.String())

			sniIdentifier := c.sniGenerator.GenerateFromAddr(addr)

			c.appConnections.Set(string(sniIdentifier), addr)

			c.forwardToProxyServer(data, addr)
		}
	}
}

func (c *TransparentProxyClient) forwardToProxyServer(data []byte, appAddr *net.UDPAddr) {
	sniIdentifier := c.sniGenerator.GenerateFromAddr(appAddr)

	modifiedPacket := packet.NewPacket(data)
	modifiedPacket.AppendSNIIdentifier(sniIdentifier)

	_, err := c.serverConn.Write(modifiedPacket.Data)
	if err != nil {
		c.log.Error("Failed to forward packet to proxy server: %v", err)
		return
	}

	c.log.Debug("Forwarded %d bytes to proxy server", len(modifiedPacket.Data))
}

func (c *TransparentProxyClient) receiveFromProxyServer() {
	buffer := make([]byte, 65535)
	for {
		n, _, err := c.serverConn.ReadFromUDP(buffer)
		if err != nil {
			c.log.Error("Error reading from proxy server: %v", err)
			continue
		}
		pkt := packet.NewPacket(buffer[:n])
		sniIdentifier := pkt.ExtractSNIIdentifierStr()

		// Find the original client address
		appAddr, exists := c.appConnections.Get(sniIdentifier)
		if !exists {
			c.log.Error("Client address not found for SNI identifier %X", sniIdentifier)
			continue
		}

		c.forwardToApplication(pkt.Data, appAddr)
	}
}

func (c *TransparentProxyClient) forwardToApplication(data []byte, appAddr *net.UDPAddr) {
	_, err := c.listenConn.WriteToUDP(data, appAddr)
	if err != nil {
		c.log.Error("Failed to forward packet to application: %v", err)
		return
	}

	c.log.Debug("Forwarded %d bytes to application %s", len(data), appAddr.String())
}
