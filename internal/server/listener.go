package server

import (
	"context"
	"fmt"
	"net"
	"quic-transproxy/internal/shared/logger"
	"quic-transproxy/internal/shared/packet"
	"quic-transproxy/internal/shared/safemap"
)

type TransparentProxyServer struct {
	listenAddr string
	listenPort int
	log        logger.Logger
	sniSniffer *SNISniffer

	clientToWebsite *safemap.SafeMap[string, *net.UDPConn] // SNI_identifier -> Target_address
	websiteToClient *safemap.SafeMap[*net.UDPConn, string] // Address -> Client_address
}

func NewTransparentProxyServer(listenAddr string, listenPort int, log logger.Logger) *TransparentProxyServer {
	return &TransparentProxyServer{
		listenAddr:      listenAddr,
		listenPort:      listenPort,
		log:             log,
		sniSniffer:      NewSNISniffer(),
		clientToWebsite: safemap.New[string, *net.UDPConn](),
		websiteToClient: safemap.New[*net.UDPConn, string](),
	}
}

func (s *TransparentProxyServer) Start(ctx context.Context) error {
	return s.listenForInboundTraffic(ctx)
}

func (c *TransparentProxyServer) listenForInboundTraffic(ctx context.Context) error {
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

	c.log.Info("Listening for inbound traffic on %s", addr)

	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				c.log.Error("Error reading from UDP connection: %v", err)
				continue
			}

			c.log.Debug("Received %d bytes from %s", n, addr.String())

			pkt := packet.NewPacket(buffer[:n])
			sniIdentifier := pkt.ExtractSNIIdentifierStr()
			if sniIdentifier == "" {
				c.log.Debug("No SNI identifier found in packet")
				continue
			}

			targetConn, exists := c.clientToWebsite.Get(sniIdentifier)
			if !exists {
				c.log.Debug("No target address found for SNI identifier %s", sniIdentifier)
				// sniff
				targetAddr := c.sniSniffer.Sniff(pkt.Data)
				if targetAddr == "" {
					c.log.Debug("No target address found for SNI identifier %s", sniIdentifier)
					continue
				}

				targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
				if err != nil {
					c.log.Error("Error resolving target address %s: %v", targetAddr, err)
					continue
				}

				targetConn, err := net.DialUDP("udp", nil, targetUDPAddr)
				if err != nil {
					c.log.Error("Error dialing target address %s: %v", targetAddr, err)
					continue
				}

				c.clientToWebsite.Set(sniIdentifier, targetConn)
				c.websiteToClient.Set(targetConn, addr.String())

				go c.handleOutboundTraffic(conn, targetConn, addr)

				_, err = targetConn.Write(pkt.Data)
				if err != nil {
					c.log.Error("Error writing to target: %v", err)
					c.clientToWebsite.Delete(sniIdentifier)
					c.websiteToClient.Delete(targetConn)
					targetConn.Close()
					continue
				}
			} else {
				_, err = targetConn.Write(pkt.Data)
				if err != nil {
					c.log.Error("Error writing to target: %v", err)
					c.clientToWebsite.Delete(sniIdentifier)
					c.websiteToClient.Delete(targetConn)
					targetConn.Close()
					continue
				}
			}
		}
	}
}

func (c *TransparentProxyServer) handleOutboundTraffic(clientConn *net.UDPConn, targetConn *net.UDPConn, clientAddr *net.UDPAddr) {
	defer func() {
		targetConn.Close()
		c.clientToWebsite.ForEach(func(sni string, conn *net.UDPConn) bool {
			if conn == targetConn {
				c.clientToWebsite.Delete(sni)
			}
			return true
		})
		c.websiteToClient.Delete(targetConn)
	}()

	buffer := make([]byte, 65535)
	for {
		n, err := targetConn.Read(buffer)
		if err != nil {
			c.log.Error("Error reading from target: %v", err)
			return
		}

		c.log.Debug("Received %d bytes from target", n)

		// 转发响应回客户端
		_, err = clientConn.WriteToUDP(buffer[:n], clientAddr)
		if err != nil {
			c.log.Error("Error writing to client: %v", err)
			return
		}
	}
}
