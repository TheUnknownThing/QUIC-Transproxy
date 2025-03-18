package client

import (
	"context"
	"fmt"
	"net"
	"quic-transproxy/internal/shared/logger"
)

type Listener struct {
	listenAddr string
	listenPort int
	log        logger.Logger
	packetCh   chan []byte
	addrCh     chan net.Addr
}

func NewListener(addr string, port int, log logger.Logger) *Listener {
	return &Listener{
		listenAddr: addr,
		listenPort: port,
		log:        log,
		packetCh:   make(chan []byte, 100),
		addrCh:     make(chan net.Addr, 100),
	}
}

func (l *Listener) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", l.listenAddr, l.listenPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	l.log.Info("Listener started on %s", addr)

	buffer := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			n, srcAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				l.log.Error("Error reading UDP: %v", err)
				continue
			}

			data := make([]byte, n)
			copy(data, buffer[:n])

			l.log.Debug("Received %d bytes from %s", n, srcAddr.String())

			select {
			case l.packetCh <- data:
				l.addrCh <- srcAddr
			default:
				l.log.Warn("Channel full, dropping packet")
			}
		}
	}
}

func (l *Listener) GetPacketChannel() <-chan []byte {
	return l.packetCh
}

func (l *Listener) GetAddrChannel() <-chan net.Addr {
	return l.addrCh
}
