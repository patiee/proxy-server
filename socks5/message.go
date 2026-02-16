package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// ReadMethods reads the supported authentication methods from the client.
// Returns the list of supported methods.
func ReadMethods(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read methods header: %w", err)
	}

	if header[0] != Version {
		return nil, fmt.Errorf("invalid version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, fmt.Errorf("read methods body: %w", err)
	}

	return methods, nil
}

// WriteMethods writes the list of supported authentication methods to the server.
func WriteMethods(w io.Writer, methods []byte) error {
	buf := make([]byte, 2+len(methods))
	buf[0] = Version
	buf[1] = byte(len(methods))
	copy(buf[2:], methods)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write methods: %w", err)
	}
	return nil
}

// ReadServerSelection reads the server's selected authentication method.
func ReadServerSelection(r io.Reader) (byte, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, fmt.Errorf("read server selection: %w", err)
	}

	if buf[0] != Version {
		return 0, fmt.Errorf("invalid version: %d", buf[0])
	}

	return buf[1], nil
}

// WriteServerSelection writes the server's selected authentication method.
func WriteServerSelection(w io.Writer, method byte) error {
	if _, err := w.Write([]byte{Version, method}); err != nil {
		return fmt.Errorf("write server selection: %w", err)
	}
	return nil
}

// ReadAuthRequest reads the username/password authentication request.
func ReadAuthRequest(r io.Reader) (string, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", "", fmt.Errorf("read auth header: %w", err)
	}

	if header[0] != UserPassAuthVersion {
		return "", "", fmt.Errorf("unsupported auth version: %d", header[0])
	}

	userLen := int(header[1])
	userBytes := make([]byte, userLen)
	if _, err := io.ReadFull(r, userBytes); err != nil {
		return "", "", fmt.Errorf("read auth user: %w", err)
	}

	lenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", "", fmt.Errorf("read auth pass len: %w", err)
	}

	passLen := int(lenBuf[0])
	passBytes := make([]byte, passLen)
	if _, err := io.ReadFull(r, passBytes); err != nil {
		return "", "", fmt.Errorf("read auth pass: %w", err)
	}

	return string(userBytes), string(passBytes), nil
}

// WriteAuthRequest writes the username/password authentication request.
func WriteAuthRequest(w io.Writer, user, pass string) error {
	uLen := len(user)
	pLen := len(pass)
	if uLen > 255 || pLen > 255 {
		return errors.New("user or password too long")
	}

	buf := make([]byte, 3+uLen+pLen)
	buf[0] = UserPassAuthVersion
	buf[1] = byte(uLen)
	copy(buf[2:], user)
	buf[2+uLen] = byte(pLen)
	copy(buf[3+uLen:], pass)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write auth request: %w", err)
	}
	return nil
}

// ReadAuthResponse reads the username/password authentication response status.
func ReadAuthResponse(r io.Reader) (byte, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, fmt.Errorf("read auth response: %w", err)
	}

	if buf[0] != UserPassAuthVersion {
		return 0, fmt.Errorf("invalid auth response version: %d", buf[0])
	}

	return buf[1], nil
}

// WriteAuthResponse writes the username/password authentication response status.
func WriteAuthResponse(w io.Writer, status byte) error {
	if _, err := w.Write([]byte{UserPassAuthVersion, status}); err != nil {
		return fmt.Errorf("write auth response: %w", err)
	}
	return nil
}

// ReadRequestOrReply reads a SOCKS5 request or reply header (up to address).
// This is slightly generic as Request and Reply have almost same structure:
// Req: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
// Rep: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
// Returns (CMD/REP, IP/Domain, Port, error)
func ReadMessage(r io.Reader) (byte, string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, "", 0, fmt.Errorf("read header: %w", err)
	}

	if header[0] != Version {
		return 0, "", 0, fmt.Errorf("invalid version: %d", header[0])
	}

	cmdOrRep := header[1]
	// RSV is header[2], ignored
	atyp := header[3]

	var host string
	switch atyp {
	case AtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, "", 0, fmt.Errorf("read ipv4: %w", err)
		}
		host = net.IP(buf).String()
	case AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return 0, "", 0, fmt.Errorf("read domain len: %w", err)
		}
		buf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, "", 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(buf)
	case AtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, "", 0, fmt.Errorf("read ipv6: %w", err)
		}
		host = net.IP(buf).String()
	default:
		return 0, "", 0, fmt.Errorf("unsupported atyp: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return 0, "", 0, fmt.Errorf("read port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	return cmdOrRep, host, port, nil
}

// WriteRequest writes a SOCKS5 request.
func WriteRequest(w io.Writer, cmd byte, addr string) error {
	return writeMessage(w, cmd, addr)
}

// WriteReply writes a SOCKS5 reply.
func WriteReply(w io.Writer, rep byte, addr string) error {
	return writeMessage(w, rep, addr)
}

func writeMessage(w io.Writer, cmdOrRep byte, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port %s: %w", portStr, err)
	}

	buf := []byte{Version, cmdOrRep, 0x00} // RSV=0

	ip := net.ParseIP(host)
	if ip == nil {
		// Domain
		if len(host) > 255 {
			return errors.New("domain too long")
		}
		buf = append(buf, AtypDomain, byte(len(host)))
		buf = append(buf, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		buf = append(buf, AtypIPv4)
		buf = append(buf, ip4...)
	} else {
		// IPv6
		buf = append(buf, AtypIPv6)
		buf = append(buf, ip.To16()...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	buf = append(buf, portBuf...)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	return nil
}
