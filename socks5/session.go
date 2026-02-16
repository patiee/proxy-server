package socks5

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// Session handles a single SOCKS5 connection session.
type Session struct {
	conn   net.Conn
	server *Server
	reader *bufio.Reader
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSession creates a new SOCKS5 session.
func NewSession(conn net.Conn, server *Server, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Session {
	return &Session{
		conn:   conn,
		server: server,
		reader: bufio.NewReader(conn),
		Dial:   dial,
	}
}

// Handle manages the SOCKS5 session lifecycle.
func (s *Session) Handle() error {
	defer s.conn.Close()
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("SOCKS5 Session Panic: %v\n", r)
		}
	}()

	// Use configured timeout or default to 10s
	timeout := s.server.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	s.conn.SetDeadline(time.Now().Add(timeout))

	if err := s.Handshake(); err != nil {
		return err
	}

	destAddr, err := s.ReadRequest()
	if err != nil {
		return err
	}

	s.conn.SetDeadline(time.Time{})
	return s.Connect(destAddr)
}

// Handshake performs the SOCKS5 authentication handshake.
func (s *Session) Handshake() error {
	methods, err := ReadMethods(s.reader)
	if err != nil {
		return err
	}

	// Check if auth is required
	authRequired := s.server.User != ""
	useMethod := byte(MethodNoAcceptable) // No acceptable methods

	for _, m := range methods {
		if authRequired {
			if m == MethodUserPass {
				useMethod = MethodUserPass
				break
			}
		} else {
			if m == MethodNoAuth {
				useMethod = MethodNoAuth
				break
			}
		}
	}

	if err := WriteServerSelection(s.conn, useMethod); err != nil {
		return err
	}

	if useMethod == MethodNoAcceptable {
		return fmt.Errorf("no acceptable methods")
	}

	if useMethod == MethodUserPass {
		return s.authenticate()
	}
	return nil
}

// authenticate handles Username/Password authentication (RFC 1929).
func (s *Session) authenticate() error {
	user, password, err := ReadAuthRequest(s.reader)
	if err != nil {
		return err
	}

	if user != s.server.User || password != s.server.Password {
		WriteAuthResponse(s.conn, AuthFailure)
		return fmt.Errorf("authentication failed")
	}

	WriteAuthResponse(s.conn, AuthSuccess)
	return nil
}

// ReadRequest reads and parses the SOCKS5 request.
func (s *Session) ReadRequest() (string, error) {
	cmd, host, port, err := ReadMessage(s.reader)
	if err != nil {
		return "", err
	}

	if cmd != CmdConnect {
		// Send Command Not Supported
		// Generic dummy address 0.0.0.0:0
		dummyAddr := "0.0.0.0:0"
		writeMessage(s.conn, ReplyCommandNotSupported, dummyAddr)
		return "", fmt.Errorf("unsupported command: %d", cmd)
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

// Connect establishes the connection to the destination and proxies data.
func (s *Session) Connect(dest string) error {
	var destConn net.Conn
	var err error

	if s.Dial != nil {
		destConn, err = s.Dial(context.Background(), "tcp", dest)
	} else {
		// Fallback to direct dial if no custom dialer provided (shouldn't happen with correct usage)
		destConn, err = (&net.Dialer{}).DialContext(context.Background(), "tcp", dest)
	}

	if err != nil {
		WriteReply(s.conn, ReplyHostUnreachable, "0.0.0.0:0")
		return err
	}
	defer destConn.Close()

	// Reply Success
	// Use local address of the connection
	localAddr := destConn.LocalAddr().String()
	WriteReply(s.conn, ReplySucceeded, localAddr)

	return s.Proxy(destConn, dest)
}

// Proxy handles the data transfer, including peek detection for HTTP/HTTPS.
func (s *Session) Proxy(destConn net.Conn, destAddr string) error {
	// Peek detection
	peek, _ := s.reader.Peek(1)

	if len(peek) > 0 {
		if peek[0] == 0x16 {
			// TLS -> potentially HTTPS
			return s.handleHTTPS(destConn, destAddr)
		}

		// Simple heuristic for HTTP methods
		m := peek[0]
		if m == 'G' || m == 'P' || m == 'H' || m == 'D' || m == 'C' || m == 'O' || m == 'T' {
			// Try proxying as HTTP
			s.server.ProxyHandler.ProxyConnection(s.conn, destConn, s.reader, bufio.NewReader(destConn), "http", destAddr)
			return nil
		}
	}

	// Blind Tunnel
	go io.Copy(destConn, s.reader)
	io.Copy(s.conn, destConn)
	return nil
}

// handleHTTPS handles TLS handshake and forwarding.
func (s *Session) handleHTTPS(destConn net.Conn, destAddr string) error {
	// Handshake Server
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				hello.ServerName = destAddr // fallback
			}
			return s.server.ProxyHandler.GetCertificate(hello)
		},
	}

	// Use readOnlyConn to wrap s.reader + s.conn because s.reader has buffered data
	tlsClientConn := tls.Server(&readOnlyConn{s.reader, s.conn}, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		return err
	}
	defer tlsClientConn.Close()

	// Handshake Client
	destTLSConfig := &tls.Config{
		InsecureSkipVerify: s.server.ProxyHandler.GetInsecureSkipVerify(),
		ServerName:         destAddr,
	}
	if rootCAs := s.server.ProxyHandler.GetRootCAs(); rootCAs != nil {
		destTLSConfig.RootCAs = rootCAs
	}
	tlsDestConn := tls.Client(destConn, destTLSConfig)
	if err := tlsDestConn.Handshake(); err != nil {
		return err
	}
	defer tlsDestConn.Close()

	// Proxy HTTP over TLS
	s.server.ProxyHandler.ProxyConnection(tlsClientConn, tlsDestConn, bufio.NewReader(tlsClientConn), bufio.NewReader(tlsDestConn), "https", destAddr)
	return nil
}

// readOnlyConn wraps a bufio.Reader and a net.Conn to allow reading buffered data
type readOnlyConn struct {
	reader *bufio.Reader
	net.Conn
}

func (c *readOnlyConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
