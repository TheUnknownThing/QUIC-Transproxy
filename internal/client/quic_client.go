package client

import (
	"context"
	"crypto/tls"
	"net"
	"quic-transproxy/internal/logger"
	"quic-transproxy/internal/quiclib"
)

type QUICClient struct {
	proxyAddr       string
	logger          *logger.Logger
	quicClient      quiclib.QUICClient
	quicConn        *quiclib.QUICConn
	listener        *Listener
	sniGenerator    *SNIIdentifierGenerator
	connectionIDMod *ConnectionIDModifier
	ctx             context.Context
	cancel          context.CancelFunc
}

func NewQUICClient(
	proxyAddr string,
	logger *logger.Logger,
	listener *Listener,
	sniGenerator *SNIIdentifierGenerator,
	connectionIDMod *ConnectionIDModifier,
) *QUICClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICClient{
		proxyAddr:       proxyAddr,
		logger:          logger,
		quicClient:      quiclib.NewQUICClient(),
		listener:        listener,
		sniGenerator:    sniGenerator,
		connectionIDMod: connectionIDMod,
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Connect to the proxy server
func (c *QUICClient) Connect() error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // FOR TEST ONLY
	}

	var err error
	c.quicConn, err = c.quicClient.Connect(c.ctx, c.proxyAddr, tlsConfig)
	if err != nil {
		c.logger.Error("Failed to connect to proxy server: %v", err)
		return err
	}

	c.logger.Info("Connected to proxy server at %s", c.proxyAddr)

	return nil
}

func (c *QUICClient) Start() {
	go c.processPackets()
}

func (c *QUICClient) processPackets() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case packet := <-c.listener.GetPacketChan():
			c.handlePacket(packet)
		}
	}
}

func (c *QUICClient) handlePacket(packet []byte) {
	// SIMPLIFY: NEED TO PARSE THE ACTUAL PACKET TO GET THE IP AND PORT
	sniIdentifier := c.sniGenerator.GenerateIdentifier(net.ParseIP("127.0.0.1"), 12345)

	modifiedPacket, err := c.connectionIDMod.ModifyPacket(packet, sniIdentifier)
	if err != nil {
		c.logger.Error("Failed to modify packet: %v", err)
		return
	}

	_, err = c.quicConn.Stream.Write(modifiedPacket)
	if err != nil {
		c.logger.Error("Failed to write packet to proxy server: %v", err)
		return
	}

	c.logger.Debug("Forwarded packet with SNI identifier %d to proxy server", sniIdentifier)
}

func (c *QUICClient) Close() error {
	c.cancel()
	if c.quicClient != nil {
		return c.quicClient.Close()
	}
	return nil
}
