package server

import (
	"context"
	"fmt"
	"net"
	"quic-transproxy/internal/shared/logger"
	"quic-transproxy/internal/shared/packet"
	"sync"
)

type TransparentProxyServer struct {
	clientPort  int
	websitePort int
	log         logger.Logger
	sniSniffer  *SNISniffer
	sniMapper   *SNIMapper

	clientToWebsite map[string]string // SNI_identifier -> Target_address
	websiteToClient map[string]string // Address -> Client_address
	mutex           sync.RWMutex
}

func NewTransparentProxyServer(clientPort, websitePort int, log logger.Logger) *TransparentProxyServer {
	return &TransparentProxyServer{
		clientPort:      clientPort,
		websitePort:     websitePort,
		log:             log,
		sniSniffer:      NewSNISniffer(),
		sniMapper:       NewSNIMapper(),
		clientToWebsite: make(map[string]string),
		websiteToClient: make(map[string]string),
	}
}

func (s *TransparentProxyServer) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		err := s.listenForClients(ctx)
		errCh <- err
	}()

	go func() {
		err := s.listenForWebsites(ctx)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *TransparentProxyServer) listenForClients(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.clientPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	s.log.Info("Listening for client traffic on %s", addr)

	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			n, clientAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				s.log.Error("Error reading from client: %v", err)
				continue
			}

			clientData := make([]byte, n)
			copy(clientData, buffer[:n])

			s.log.Debug("Received %d bytes from client %s", n, clientAddr.String())

			go s.handleClientPacket(ctx, clientData, clientAddr)
		}
	}
}

func (s *TransparentProxyServer) listenForWebsites(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.websitePort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	s.log.Info("Listening for website responses on %s", addr)

	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			n, websiteAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				s.log.Error("Error reading from website: %v", err)
				continue
			}

			websiteData := make([]byte, n)
			copy(websiteData, buffer[:n])

			s.log.Debug("Received %d bytes from website %s", n, websiteAddr.String())

			go s.handleWebsitePacket(ctx, websiteData, websiteAddr)
		}
	}
}

func (s *TransparentProxyServer) handleClientPacket(ctx context.Context, data []byte, clientAddr *net.UDPAddr) {
	pkt := packet.NewPacket(data)
	sniIdentifier := pkt.ExtractSNIIdentifier()

	if len(sniIdentifier) != 2 {
		s.log.Error("Invalid SNI identifier length: %d", len(sniIdentifier))
		return
	}

	// if there exists a mapping for this SNI identifier, forward the packet to the website
	sni := s.sniMapper.Lookup(sniIdentifier)
	if sni == "" {
		// sniff SNI from the packet
		sni := s.sniSniffer.Sniff(pkt.Data)

		if sni == "" {
			s.log.Warn("Could not sniff SNI from client packet")
			return
		}

		s.sniMapper.Update(sniIdentifier, sni)
	}

	pkt.RestorePacket()

	targetAddr := fmt.Sprintf("%s:443", sni)
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)

	s.log.Debug("Creating connection to website %s", targetAddr)

	if err != nil {
		s.log.Error("Failed to resolve target address: %v", err)
		return
	}

	s.updateMapping(clientAddr.String(), sniIdentifier, raddr.String())

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		s.log.Error("Failed to create UDP connection: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(pkt.Data)
	if err != nil {
		s.log.Error("Failed to forward packet to website: %v", err)
		return
	}

	s.log.Debug("Forwarded %d bytes to website %s", len(pkt.Data), targetAddr)
}

func (s *TransparentProxyServer) handleWebsitePacket(ctx context.Context, data []byte, websiteAddr *net.UDPAddr) {
	// clientAddrStr := s.getClientAddrByWebsite(websiteAddr.String())
	clientAddrStr := "127.0.0.1:8000"
	if clientAddrStr == "" {
		s.log.Warn("No client mapping found for website %s", websiteAddr.String())
		return
	}

	clientAddr, err := net.ResolveUDPAddr("udp", clientAddrStr)
	if err != nil {
		s.log.Error("Failed to resolve client address: %v", err)
		return
	}

	s.log.Debug("Forwarding %d bytes to client %s", len(data), clientAddrStr)

	conn, err := net.DialUDP("udp", nil, clientAddr)
	if err != nil {
		s.log.Error("Failed to create UDP connection to client: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		s.log.Error("Failed to forward packet to client: %v", err)
		return
	}

	s.log.Debug("Forwarded %d bytes to client %s", len(data), clientAddrStr)
}

func (s *TransparentProxyServer) updateMapping(clientAddr string, sniIdentifier []byte, websiteAddr string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	identifierStr := fmt.Sprintf("%x", sniIdentifier)
	s.clientToWebsite[identifierStr] = websiteAddr
	s.websiteToClient[websiteAddr] = clientAddr
}

func (s *TransparentProxyServer) getClientAddrByWebsite(websiteAddr string) string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.websiteToClient[websiteAddr]
}
