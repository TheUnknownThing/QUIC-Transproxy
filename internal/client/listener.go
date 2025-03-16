package client

import (
	"context"
	"net"
	"quic-transproxy/internal/logger"
)

type Listener struct {
	listenAddr string
	logger     *logger.Logger
	packetChan chan []byte
	udpConn    *net.UDPConn
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewListener(listenAddr string, logger *logger.Logger) *Listener {
	ctx, cancel := context.WithCancel(context.Background())
	return &Listener{
		listenAddr: listenAddr,
		logger:     logger,
		packetChan: make(chan []byte, 100),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (l *Listener) Start() error {
	addr, err := net.ResolveUDPAddr("udp", l.listenAddr)
	if err != nil {
		return err
	}

	l.udpConn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	l.logger.Info("Listening on %s", l.listenAddr)

	go l.receivePackets()

	return nil
}

func (l *Listener) receivePackets() {
	buffer := make([]byte, 2048)

	for {
		select {
		case <-l.ctx.Done():
			return
		default:
			n, _, err := l.udpConn.ReadFromUDP(buffer)
			if err != nil {
				l.logger.Error("Failed to read UDP packet: %v", err)
				continue
			}

			packet := make([]byte, n)
			copy(packet, buffer[:n])

			select {
			case l.packetChan <- packet:
				l.logger.Debug("Received packet of length %d", n)
			default:
				l.logger.Warn("Packet channel full, dropping packet")
			}
		}
	}
}

// GetPacketChan returns the channel that receives packets
func (l *Listener) GetPacketChan() <-chan []byte {
	return l.packetChan
}

func (l *Listener) Close() error {
	l.cancel()
	if l.udpConn != nil {
		return l.udpConn.Close()
	}
	return nil
}
