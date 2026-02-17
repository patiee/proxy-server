package socks5

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"log"

	"github.com/patiee/proxy/config"
)

// ProxyHandler defines the interface for underlying proxy logic
type ProxyHandler interface {
	ProxyConnection(clientConn, destConn net.Conn, clientReader, destReader *bufio.Reader, scheme, host string)
	GetDialContext() func(ctx context.Context, network, addr string) (net.Conn, error)
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetInsecureSkipVerify() bool
	GetRootCAs() *x509.CertPool
}

// Server implements SOCKS5 server.
type Server struct {
	User     string
	Password string
	Upstream *config.UpstreamConfig
	Timeout  time.Duration
	log      *log.Logger

	// ProxyHandler handles the underlying HTTP/HTTPS proxying logic
	ProxyHandler ProxyHandler
}

// NewServer creates a new SOCKS5 server.
func NewServer(user, password string, upstream *config.UpstreamConfig, timeout time.Duration, logger *log.Logger, handler ProxyHandler) *Server {
	return &Server{
		User:         user,
		Password:     password,
		Upstream:     upstream,
		Timeout:      timeout,
		log:          logger,
		ProxyHandler: handler,
	}
}

// ServeSOCKS5 accepts SOCKS5 connections on the listener.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	dial := s.ProxyHandler.GetDialContext()
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	session := NewSession(conn, s.log, s, dial)
	if err := session.Handle(); err != nil {
		s.log.Printf("SOCKS5 session error: %v\n", err)
	}
}
