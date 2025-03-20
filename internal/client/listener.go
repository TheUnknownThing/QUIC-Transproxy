package client

import (
	"context"
	"fmt"
	"net"
	"quic-transproxy/internal/shared/logger"
	"quic-transproxy/internal/shared/packet"
	"sync"
)

type TransparentProxyClient struct {
	listenAddr      string
	listenPort      int
	proxyServerAddr string
	proxyServerPort int
	log             logger.Logger
	sniGenerator    *SNIIdentifierGenerator

	appConnections map[string]*net.UDPConn
	serverConn     *net.UDPConn // Connection to the proxy server
	mutex          sync.RWMutex
}

func NewTransparentProxyClient(listenAddr string, listenPort int, proxyAddr string, proxyPort int, log logger.Logger) *TransparentProxyClient {
	return &TransparentProxyClient{
		listenAddr:      listenAddr,
		listenPort:      listenPort,
		proxyServerAddr: proxyAddr,
		proxyServerPort: proxyPort,
		log:             log,
		sniGenerator:    NewSNIIdentifierGenerator(),
		appConnections:  make(map[string]*net.UDPConn),
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
	defer conn.Close()

	c.log.Info("Listening for local traffic on %s", addr)

	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			n, appAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				c.log.Error("Error reading from application: %v", err)
				continue
			}

			appData := make([]byte, n)
			copy(appData, buffer[:n])

			c.log.Debug("Received %d bytes from application %s", n, appAddr.String())

			c.saveAppConnection(appAddr.String(), conn)

			c.forwardToProxyServer(appData, appAddr)
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

		responseData := make([]byte, n)
		copy(responseData, buffer[:n])

		c.log.Debug("Received %d bytes from proxy server", n)

		// 获取原始请求的源地址（本地应用）
		// 注意：这里需要一种方式来确定这个响应应该发送给哪个本地应用
		// 实际实现中，可能需要额外的标识符或基于Connection ID的映射

		// 简化实现，假设最后一个请求的应用是目标
		c.forwardToApplication(responseData)
	}
}

func (c *TransparentProxyClient) forwardToApplication(data []byte) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// 实际实现应该有更好的映射机制
	// 这里简化处理，将响应发送到所有已知应用连接
	for appAddr, conn := range c.appConnections {
		addr, err := net.ResolveUDPAddr("udp", appAddr)
		if err != nil {
			c.log.Error("Failed to resolve application address: %v", err)
			continue
		}

		_, err = conn.WriteToUDP(data, addr)
		if err != nil {
			c.log.Error("Failed to forward response to application %s: %v", appAddr, err)
			continue
		}

		c.log.Debug("Forwarded %d bytes to application %s", len(data), appAddr)
	}
}

func (c *TransparentProxyClient) saveAppConnection(appAddr string, conn *net.UDPConn) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.appConnections[appAddr]; !exists {
		c.appConnections[appAddr] = conn
		c.log.Debug("Saved new application connection: %s", appAddr)
	}
}
