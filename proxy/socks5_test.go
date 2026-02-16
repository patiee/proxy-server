package proxy_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/patiee/proxy/config"
	proxy "github.com/patiee/proxy/proxy"
)

func TestSOCKS5Configuration(t *testing.T) {
	socksURL, _ := url.Parse("socks5://127.0.0.1:1080")
	conf := &config.Config{
		Port: "8080",
		Upstream: &config.UpstreamConfig{
			URL:     socksURL,
			Timeout: 10 * time.Second,
		},
	}

	proxyServer, err := proxy.NewProxyServer(conf)
	if err != nil {
		t.Fatalf("Failed to create proxy server with SOCKS5 upstream: %v", err)
	}

	// Verify Transport.Proxy is nil (since we use DialContext for SOCKS5)
	if proxyServer.Handler.Transport.Proxy != nil {
		t.Log("Transport.Proxy is set, ensuring it is not used for SOCKS5 logic or is nil if we set it to nil")
		// Actually implementation sets it to nil.
		t.Fatal("Expected Transport.Proxy to be nil for SOCKS5 integration, got set")
	}

	// Verify DialContext is set
	if proxyServer.Handler.Transport.DialContext == nil {
		t.Errorf("Expected Transport.DialContext to be set for SOCKS5, got nil")
	}

	// Verify DialContext is set
	if proxyServer.Handler.Transport.DialContext == nil {
		t.Errorf("Expected Transport.DialContext to be set for SOCKS5, got nil")
	}
}

func TestSOCKS5Integration(t *testing.T) {
	// 1. Start a dummy destination server
	destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from destination"))
	}))
	defer destServer.Close()

	destURL, _ := url.Parse(destServer.URL)
	destPort := destURL.Port()
	if destPort == "" {
		destPort = "80"
	}

	// 2. Start a mock SOCKS5 server
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock SOCKS5 server: %v", err)
	}
	defer socksListener.Close()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5Connection(t, conn)
		}
	}()

	// 3. Configure ProxyServer to use the mock SOCKS5 server
	socksAddr := socksListener.Addr().String()
	socksUpstreamURL, _ := url.Parse("socks5://" + socksAddr)

	conf := &config.Config{
		Port: "0", // Let it pick a random port
		Upstream: &config.UpstreamConfig{
			URL:     socksUpstreamURL,
			Timeout: 5 * time.Second,
		},
	}
	proxyServer, err := proxy.NewProxyServer(conf)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}

	// 4. Send a request through the proxy server
	// We'll use the proxy's ServeHTTP directly via httptest.NewRecorder to avoid spinning up another listener
	// gracefully, or we could just use pure ServeHTTP.

	req := httptest.NewRequest("GET", destServer.URL, nil)
	w := httptest.NewRecorder()

	proxyServer.ServeHTTP(w, req)

	// 5. Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	body := w.Body.String()
	if body != "Hello from destination" {
		t.Errorf("Expected body 'Hello from destination', got '%s'", body)
	}
}

func handleSOCKS5Connection(t *testing.T, conn net.Conn) {
	defer conn.Close()

	// SOCKS5 Handshake
	// Client sends: VER(1) | NMETHODS(1) | METHODS(1-255)
	buf := make([]byte, 258)
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		t.Logf("SOCKS5 verification failed read handshake: %v", err)
		return
	}

	if buf[0] != 0x05 {
		t.Logf("SOCKS5 verification failed: invalid version %d", buf[0])
		return
	}
	nMethods := int(buf[1])
	if n < 2+nMethods {
		// Read remaining methods if needed
		_, err = io.ReadFull(conn, buf[n:2+nMethods])
		if err != nil {
			t.Logf("SOCKS5 verification failed read methods: %v", err)
			return
		}
	}

	// Server responds: VER(1) | METHOD(1)
	// We choose 0x00 (No authentication)
	conn.Write([]byte{0x05, 0x00})

	// SOCKS5 Request
	// Client sends: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2)
	// CMD: 0x01 (CONNECT)
	// ATYP: 0x01 (IPv4), 0x03 (Domain), 0x04 (IPv6)

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Logf("SOCKS5 request read failed: %v", err)
		return
	}

	if header[0] != 0x05 || header[1] != 0x01 {
		t.Logf("SOCKS5 invalid command request: %v", header)
		return
	}

	var destAddr string
	var destPort int

	switch header[3] {
	case 0x01: // IPv4
		ipv4 := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipv4); err != nil {
			return
		}
		destAddr = net.IP(ipv4).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		destAddr = string(domain)
	case 0x04: // IPv6
		ipv6 := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipv6); err != nil {
			return
		}
		destAddr = net.IP(ipv6).String()
	default:
		t.Logf("SOCKS5 unsupported address type: %d", header[3])
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	destPort = int(binary.BigEndian.Uint16(portBuf))

	dest := fmt.Sprintf("%s:%d", destAddr, destPort)
	t.Logf("SOCKS5 connecting to %s", dest)

	// Connect to destination
	destConn, err := net.Dial("tcp", dest)
	if err != nil {
		t.Logf("SOCKS5 failed to dial destination: %v", err)
		// Reply with verification failure
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // 0x05: Connection refused
		return
	}
	defer destConn.Close()

	// Reply success
	// VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
	localAddr := destConn.LocalAddr().(*net.TCPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01}
	reply = append(reply, localAddr.IP.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(localAddr.Port))
	reply = append(reply, portBytes...)

	conn.Write(reply)

	// Proxy data
	go io.Copy(destConn, conn)
	io.Copy(conn, destConn)
}
