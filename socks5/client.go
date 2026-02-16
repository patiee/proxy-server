package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Client implements a SOCKS5 client
type Client struct {
	// Addr is the SOCKS5 server address (host:port)
	Addr string
	// Auth is the optional authentication credentials
	Auth *Auth
	// Forward is the dialer to use for connecting to the SOCKS5 server
	Forward *net.Dialer
}

// NewClient creates a new SOCKS5 client
func NewClient(addr string, auth *Auth) *Client {
	return &Client{
		Addr: addr,
		Auth: auth,
	}
}

// Dial connects to the target address via the SOCKS5 proxy
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, addr)
}

// DialContext connects to the target address via the SOCKS5 proxy using the provided context
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("socks5: only tcp network is supported")
	}

	// Dial the SOCKS5 server
	var dialer net.Dialer
	if c.Forward != nil {
		dialer = *c.Forward
	}
	conn, err := dialer.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, err
	}

	// Ensure the handshake respects the context deadline
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Perform SOCKS5 handshake
	if err := c.handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Send CONNECT command
	if err := c.connect(conn, addr); err != nil {
		conn.Close()
		return nil, err
	}

	// Reset deadline after successful handshake
	if _, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(time.Time{})
	}

	return conn, nil
}

func (c *Client) handshake(conn net.Conn) error {
	// Send supported methods
	methods := []byte{MethodNoAuth}
	if c.Auth != nil {
		methods = append(methods, MethodUserPass)
	}

	if err := WriteMethods(conn, methods); err != nil {
		return fmt.Errorf("socks5 write methods: %w", err)
	}

	// Read server selection
	method, err := ReadServerSelection(conn)
	if err != nil {
		return fmt.Errorf("socks5 read selection: %w", err)
	}

	switch method {
	case MethodNoAuth:
		// No auth required
		return nil
	case MethodUserPass:
		// User/Pass auth required
		return c.authenticate(conn)
	case MethodNoAcceptable:
		return errors.New("socks5: no acceptable methods")
	default:
		return fmt.Errorf("socks5: unsupported method selected: %d", method)
	}
}

func (c *Client) authenticate(conn net.Conn) error {
	if c.Auth == nil {
		return errors.New("socks5: server requires auth but none provided")
	}

	if err := WriteAuthRequest(conn, c.Auth.User, c.Auth.Password); err != nil {
		return fmt.Errorf("socks5 write auth: %w", err)
	}

	status, err := ReadAuthResponse(conn)
	if err != nil {
		return fmt.Errorf("socks5 read auth response: %w", err)
	}

	if status != AuthSuccess {
		return errors.New("socks5 authentication failed")
	}

	return nil
}

func (c *Client) connect(conn net.Conn, addr string) error {
	if err := WriteRequest(conn, CmdConnect, addr); err != nil {
		return fmt.Errorf("socks5 write connect: %w", err)
	}

	// Read response
	rep, bindAddr, bindPort, err := ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("socks5 read connect response: %w", err)
	}

	if rep != ReplySucceeded {
		return fmt.Errorf("socks5 connect failed: status %d", rep)
	}

	// We might want to use bindAddr/bindPort if needed, but usually discarded for client Connect
	_ = bindAddr
	_ = bindPort

	return nil
}
