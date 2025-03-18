package quic_lib

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

type QUICConnection struct {
	conn quic.Connection
}

type QUICListener struct {
	listener *quic.Listener
}

type QUICStream struct {
	stream quic.Stream
}

func NewQUICListener(addr string, tlsConfig *tls.Config) (*QUICListener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	quicConfig := &quic.Config{}
	listener, err := quic.Listen(udpConn, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	return &QUICListener{
		listener: listener,
	}, nil
}

func (l *QUICListener) Accept(ctx context.Context) (*QUICConnection, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}

	return &QUICConnection{
		conn: conn,
	}, nil
}

func (l *QUICListener) Close() error {
	return l.listener.Close()
}

func Dial(ctx context.Context, addr string, tlsConfig *tls.Config) (*QUICConnection, error) {
	quicConfig := &quic.Config{}
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	return &QUICConnection{
		conn: conn,
	}, nil
}

func (c *QUICConnection) OpenStream() (*QUICStream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	return &QUICStream{
		stream: stream,
	}, nil
}

func (c *QUICConnection) AcceptStream(ctx context.Context) (*QUICStream, error) {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}

	return &QUICStream{
		stream: stream,
	}, nil
}

func (c *QUICConnection) Close() error {
	return c.conn.CloseWithError(0, "normal close")
}

func (s *QUICStream) Read(b []byte) (int, error) {
	return s.stream.Read(b)
}

func (s *QUICStream) Write(b []byte) (int, error) {
	return s.stream.Write(b)
}

func (s *QUICStream) Close() error {
	return s.stream.Close()
}
