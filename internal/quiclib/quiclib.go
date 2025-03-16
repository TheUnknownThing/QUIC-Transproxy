package quiclib

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

type QUICConn struct {
	Session quic.Connection
	Stream  quic.Stream
}

type PacketInfo struct {
	SourceAddr     net.Addr
	DestAddr       net.Addr
	ConnectionID   []byte
	OriginalPacket []byte
	ModifiedPacket []byte
}

type QUICClient interface {
	Connect(ctx context.Context, addr string, tlsConfig *tls.Config) (*QUICConn, error)
	Close() error
}

type DefaultQUICClient struct {
	conn *QUICConn
}

func NewQUICClient() QUICClient {
	return &DefaultQUICClient{}
}

func (c *DefaultQUICClient) Connect(ctx context.Context, addr string, tlsConfig *tls.Config) (*QUICConn, error) {
	session, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{})
	if err != nil {
		return nil, err
	}

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	c.conn = &QUICConn{
		Session: session,
		Stream:  stream,
	}

	return c.conn, nil
}

func (c *DefaultQUICClient) Close() error {
	if c.conn != nil {
		return c.conn.Session.CloseWithError(0, "client closed")
	}
	return nil
}

type QUICServer interface {
	Listen(addr string, tlsConfig *tls.Config) error
	Accept(ctx context.Context) (*QUICConn, error)
	Close() error
}

type DefaultQUICServer struct {
	listener *quic.Listener
}

func NewQUICServer() QUICServer {
	return &DefaultQUICServer{}
}

func (s *DefaultQUICServer) Listen(addr string, tlsConfig *tls.Config) error {
	listener, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{})
	if err != nil {
		return err
	}
	s.listener = listener
	return nil
}

func (s *DefaultQUICServer) Accept(ctx context.Context) (*QUICConn, error) {
	session, err := s.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}

	return &QUICConn{
		Session: session,
		Stream:  stream,
	}, nil
}

func (s *DefaultQUICServer) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
