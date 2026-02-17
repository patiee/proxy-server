package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/patiee/proxy/cert"
	"github.com/patiee/proxy/errors"
)

// ProxyHandler handles HTTP/HTTPS proxying logic
type ProxyHandler struct {
	InsecureSkipVerify bool
	Via                *string
	Timeout            time.Duration
	log                *log.Logger

	CertManager *cert.CertificateManager
	Transport   *http.Transport

	RequestFilters  []func(*http.Request) error
	ResponseFilters []func(*http.Response) error
	HttpsFilters    []func(*http.Request) bool
}

// GetDialContext returns the DialContext from the Transport
func (h *ProxyHandler) GetDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if h.Transport != nil {
		return h.Transport.DialContext
	}
	return nil
}

// GetCertificate returns the certificate for the given ClientHello
func (h *ProxyHandler) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if h.CertManager != nil {
		return h.CertManager.GetCertificate(hello)
	}
	return nil, nil
}

// GetInsecureSkipVerify returns the InsecureSkipVerify setting
func (h *ProxyHandler) GetInsecureSkipVerify() bool {
	return h.InsecureSkipVerify
}

// GetRootCAs returns the RootCAs from the Transport's TLSClientConfig
func (h *ProxyHandler) GetRootCAs() *x509.CertPool {
	if h.Transport != nil && h.Transport.TLSClientConfig != nil {
		return h.Transport.TLSClientConfig.RootCAs
	}
	return nil
}

// NewProxyHandler creates a new ProxyHandler.
func NewProxyHandler(certManager *cert.CertificateManager, transport *http.Transport, logger *log.Logger) *ProxyHandler {
	return &ProxyHandler{
		CertManager: certManager,
		Transport:   transport,
		log:         logger,
	}
}

// ServeHTTP handles the proxy requests.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Apply RequestFilters (for ALL methods)
	for _, f := range h.RequestFilters {
		if err := f(r); err != nil {
			h.log.Printf("Filter error: %v\n", err)
			if b, ok := err.(*errors.BlockedRequestError); ok {
				http.Error(w, fmt.Sprintf("Request Forbidden: %s", b.Message), http.StatusForbidden)
			} else {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}
	}

	// 2. Set Via header if configured
	if h.Via != nil {
		if prior := r.Header.Get("Via"); prior != "" {
			r.Header.Set("Via", prior+", "+*h.Via)
		} else {
			r.Header.Set("Via", *h.Via)
		}
	}

	if r.Method == http.MethodConnect {
		// 3. Check if we should intercept (MITM) using HttpsFilters
		shouldMitm := false
		if h.CertManager != nil {
			for _, f := range h.HttpsFilters {
				if f(r) {
					shouldMitm = true
					break
				}
			}
		}

		if shouldMitm {
			h.handleMITM(w, r)
		} else {
			h.handleHTTPS(w, r)
		}
		return
	}

	h.handleHTTP(w, r)
}

// handleHTTPS handles the CONNECT request by blindly tunneling the connection.
func (h *ProxyHandler) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

// handleMITM intercepts the HTTPS connection.
func (h *ProxyHandler) handleMITM(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send 200 OK to signal tunnel establishment
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		return
	}

	// Perform TLS Handshake with Client (Server-side)
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				hello.ServerName = r.Host
				if strings.Contains(hello.ServerName, ":") {
					host, _, err := net.SplitHostPort(hello.ServerName)
					if err == nil {
						hello.ServerName = host
					}
				}
			}
			return h.CertManager.GetCertificate(hello)
		},
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		h.log.Printf("MITM Handshake error: %v\n", err)
		clientConn.Close()
		return
	}
	defer tlsClientConn.Close()

	// Connect to Destination (Client-side)
	destAddr := r.Host
	if !strings.Contains(destAddr, ":") {
		destAddr += ":443"
	}

	// Use h.Transport if available for dialing?
	// h.Transport is an http.Transport, not a raw dialer.
	// We need raw TLS connection here.

	// Create raw dialer/TLS config based on Transport settings if needed
	// For now, standard net.Dial and tls.Client
	rawDestConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		h.log.Printf("MITM Destination dial error: %v\n", err)
		return
	}

	destTLSConfig := &tls.Config{
		InsecureSkipVerify: h.InsecureSkipVerify,
		ServerName:         r.URL.Hostname(), // r.Host might contain port
	}
	// Extract hostname if port is present
	if strings.Contains(destAddr, ":") {
		host, _, _ := net.SplitHostPort(destAddr)
		destTLSConfig.ServerName = host
	}

	if h.Transport != nil && h.Transport.TLSClientConfig != nil {
		destTLSConfig.RootCAs = h.Transport.TLSClientConfig.RootCAs
	}

	tlsDestConn := tls.Client(rawDestConn, destTLSConfig)
	if err := tlsDestConn.Handshake(); err != nil {
		h.log.Printf("MITM Destination Handshake error: %v\n", err)
		rawDestConn.Close()
		return
	}
	defer tlsDestConn.Close()

	// Proxy Loop
	h.ProxyConnection(tlsClientConn, tlsDestConn, bufio.NewReader(tlsClientConn), bufio.NewReader(tlsDestConn), "https", r.Host)
}

func (h *ProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	req := r.Clone(r.Context())
	req.RequestURI = ""

	resp, err := h.Transport.RoundTrip(req)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Apply response filters
	for _, f := range h.ResponseFilters {
		if err := f(resp); err != nil {
			msg := "Response Blocked"
			statusCode := http.StatusInternalServerError
			if b, ok := err.(*errors.BlockedRequestError); ok {
				msg = fmt.Sprintf("Response Blocked: %s", b.Message)
				statusCode = http.StatusForbidden
			}
			http.Error(w, msg, statusCode)
			return
		}
	}

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ProxyConnection handles the HTTP proxying loop for a given client and destination connection.
// It is exposed to allow SOCKS5 server to use the same logic.
func (h *ProxyHandler) ProxyConnection(clientConn, destConn net.Conn, clientReader, destReader *bufio.Reader, scheme, host string) {
	for {
		// Read Request
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				// optional: log error
			}
			break
		}

		req.URL.Scheme = scheme
		req.URL.Host = host

		// Apply Request Filters
		blocked := false
		for _, f := range h.RequestFilters {
			if err := f(req); err != nil {
				// Determine error type
				statusCode := http.StatusInternalServerError
				msg := "Internal Proxy Error"
				if b, ok := err.(*errors.BlockedRequestError); ok {
					statusCode = http.StatusForbidden
					msg = fmt.Sprintf("Request Blocked: %s", b.Message)
				}

				// Write error response to client
				resp := &http.Response{
					StatusCode:    statusCode,
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        make(http.Header),
					Body:          io.NopCloser(strings.NewReader(msg)),
					ContentLength: int64(len(msg)),
				}
				resp.Write(clientConn)
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}

		// Forward to Destination
		if err := req.Write(destConn); err != nil {
			break
		}

		// Read Response
		resp, err := http.ReadResponse(destReader, req)
		if err != nil {
			break
		}

		if req.Method == http.MethodConnect && resp.StatusCode == http.StatusOK {
			resp.ContentLength = 0
			resp.Body = http.NoBody
		}

		// Apply Response Filters
		for _, f := range h.ResponseFilters {
			if err := f(resp); err != nil {
				statusCode := http.StatusInternalServerError
				msg := "Response Blocked"
				if b, ok := err.(*errors.BlockedRequestError); ok {
					statusCode = http.StatusForbidden
					msg = fmt.Sprintf("Response Blocked: %s", b.Message)
				}
				resp = &http.Response{
					StatusCode:    statusCode,
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        make(http.Header),
					Body:          io.NopCloser(strings.NewReader(msg)),
					ContentLength: int64(len(msg)),
				}
				break
			}
		}

		// Write Response to Client
		if err := resp.Write(clientConn); err != nil {
			break
		}
	}
}
