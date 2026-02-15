package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patiee/proxy/cert"
	"github.com/patiee/proxy/config"
)

// ProxyServer represents a proxy server.
type ProxyServer struct {
	port               string
	via                *string
	upstream           *config.UpstreamConfig
	timeout            time.Duration
	InsecureSkipVerify bool

	// Filters modify or block the request.
	Filters []func(*http.Request) error

	// HttpsHandlers determine if a CONNECT request should be intercepted (MITM).
	// Returns true to intercept, false to tunnel blindly.
	HttpsHandlers []func(*http.Request) bool

	// ResponseFilters modify or block the response.
	ResponseFilters []func(*http.Response) error

	CertManager *cert.CertificateManager

	Transport *http.Transport
	Client    *http.Client
}

// NewProxyServer creates a new ProxyServer with the given configuration.
func NewProxyServer(conf *config.Config) (*ProxyServer, error) {
	p := &ProxyServer{
		port:     conf.Port,
		via:      conf.Via,
		upstream: conf.Upstream,
	}

	if conf.InsecureSkipVerify != nil {
		p.InsecureSkipVerify = *conf.InsecureSkipVerify
	} else {
		p.InsecureSkipVerify = true
	}

	if conf.Timeout != nil && *conf.Timeout > 0 {
		p.timeout = time.Duration(*conf.Timeout) * time.Second
	} else {
		p.timeout = 10 * time.Second
	}

	// Default Transport
	p.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.InsecureSkipVerify,
		},
	}

	if conf.Upstream != nil {
		// Use configured transport with upstream
		p.Transport.Proxy = http.ProxyURL(conf.Upstream.URL)
	}

	// Initialize Client with configured Transport and Timeout
	p.Client = &http.Client{
		Transport: p.Transport,
		Timeout:   p.timeout,
	}

	// Initialize CertManager if paths are provided
	if conf.CaCertPath != nil && conf.CaKeyPath != nil {
		if err := p.SetCA(*conf.CaCertPath, *conf.CaKeyPath); err != nil {
			return nil, fmt.Errorf("failed to load CA: %v", err)
		}
	}

	return p, nil
}

// AddFilter adds a filter function to the proxy server.
func (p *ProxyServer) AddFilter(f func(*http.Request) error) {
	p.Filters = append(p.Filters, f)
}

// AddHttpsHandler adds a handler to determine if HTTPS should be intercepted.
func (p *ProxyServer) AddHttpsHandler(f func(*http.Request) bool) {
	p.HttpsHandlers = append(p.HttpsHandlers, f)
}

// AddResponseFilter adds a response filter function.
func (p *ProxyServer) AddResponseFilter(f func(*http.Response) error) {
	p.ResponseFilters = append(p.ResponseFilters, f)
}

// SetCA configures the Certificate Authority for MITM.
func (p *ProxyServer) SetCA(certPath, keyPath string) error {
	ca, err := cert.LoadCA(certPath, keyPath)
	if err != nil {
		return err
	}
	p.CertManager = cert.NewCertificateManager(ca)
	return nil
}

// ServeHTTP handles the proxy requests.
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply filters
	for _, f := range p.Filters {
		if err := f(r); err != nil {
			fmt.Printf("Filter error: %v\n", err)
			if b, ok := err.(*BlockedRequestError); ok {
				http.Error(w, fmt.Sprintf("Request Blocked: %s", b.Message), http.StatusForbidden)
			} else {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}
	}

	// Set Via header if configured
	if p.via != nil {
		if prior := r.Header.Get("Via"); prior != "" {
			r.Header.Set("Via", prior+", "+*p.via)
		} else {
			r.Header.Set("Via", *p.via)
		}
	}

	if r.Method == http.MethodConnect {
		// Check if we should intercept (MITM)
		intercept := false
		for _, h := range p.HttpsHandlers {
			if h(r) {
				intercept = true
				break
			}
		}

		if intercept && p.CertManager != nil {
			p.handleMITM(w, r)
		} else {
			p.handleHTTPS(w, r)
		}
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *ProxyServer) handleMITM(w http.ResponseWriter, r *http.Request) {
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

	// 1. Send 200 OK to signal tunnel establishment
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		return
	}

	// 2. Perform TLS Handshake with Client (Server-side)
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				hello.ServerName = r.URL.Hostname()
				if hello.ServerName == "" {
					if host, _, err := net.SplitHostPort(r.Host); err == nil {
						hello.ServerName = host
					} else {
						hello.ServerName = r.Host
					}
				}
			}
			return p.CertManager.GetCertificate(hello)
		},
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		fmt.Printf("MITM Client Handshake error: %v\n", err)
		tlsClientConn.Close()
		return
	}
	defer tlsClientConn.Close()

	// 3. Connect to Destination (Client-side)
	destAddr := r.Host
	if !strings.Contains(destAddr, ":") {
		destAddr += ":443"
	}

	dialContext := p.Transport.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{}).DialContext
	}

	var rawDestConn net.Conn
	// Simplified connection logic - assumes direct or handles upstream if dialContext is configured
	if p.upstream != nil {
		ctx := r.Context()
		rawDestConn, err = dialContext(ctx, "tcp", destAddr)
	} else {
		rawDestConn, err = dialContext(r.Context(), "tcp", destAddr)
	}
	if err != nil {
		fmt.Printf("MITM Dial error: %v\n", err)
		return
	}

	destTLSConfig := &tls.Config{
		InsecureSkipVerify: p.InsecureSkipVerify,
		ServerName:         r.URL.Hostname(),
	}
	if p.Transport != nil && p.Transport.TLSClientConfig != nil {
		destTLSConfig.RootCAs = p.Transport.TLSClientConfig.RootCAs
	}
	tlsDestConn := tls.Client(rawDestConn, destTLSConfig)
	if err := tlsDestConn.Handshake(); err != nil {
		fmt.Printf("MITM Dest Handshake error: %v\n", err)
		tlsDestConn.Close()
		return
	}
	defer tlsDestConn.Close()

	// 4. Proxy Loop
	clientReader := bufio.NewReader(tlsClientConn)
	destReader := bufio.NewReader(tlsDestConn)
	for {
		// Read Request
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("MITM ReadRequest error: %v\n", err)
			}
			break
		}

		req.URL.Scheme = "https"
		req.URL.Host = r.Host

		// Apply Request Filters
		blocked := false
		for _, f := range p.Filters {
			if err := f(req); err != nil {
				fmt.Printf("MITM Filter error: %v\n", err)
				// Determine error type
				statusCode := http.StatusInternalServerError
				msg := "Internal Proxy Error"
				if b, ok := err.(*BlockedRequestError); ok {
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
				resp.Write(tlsClientConn)
				blocked = true
				break
			}
		}
		if blocked {
			continue // Or close? Usually continue to next request on same conn if possible.
		}

		// Forward to Destination
		if err := req.Write(tlsDestConn); err != nil {
			fmt.Printf("MITM WriteRequest error: %v\n", err)
			break
		}

		// Read Response
		resp, err := http.ReadResponse(destReader, req)
		if err != nil {
			fmt.Printf("MITM ReadResponse error: %v\n", err)
			break
		}

		if req.Method == http.MethodConnect && resp.StatusCode == http.StatusOK {
			// CONNECT response has no body, but ReadResponse might leave the reader attached
			// or ContentLength -1. We must ensure we don't try to read the tunnel as body.
			resp.ContentLength = 0
			resp.Body = http.NoBody
		}

		// Apply Response Filters
		for _, f := range p.ResponseFilters {
			if err := f(resp); err != nil {
				fmt.Printf("MITM Response Filter error: %v\n", err)
				// If response filter fails, what do we do? Block response? Return error?
				// Let's assume we replace the response with an error response.
				statusCode := http.StatusInternalServerError
				msg := "Response Blocked"
				if b, ok := err.(*BlockedRequestError); ok { // Re-using error type?
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
		if err := resp.Write(tlsClientConn); err != nil {
			fmt.Printf("MITM WriteResponse error: %v\n", err)
			break
		}
	}
}

func (p *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	var destConn net.Conn
	var err error

	// Determine destination address
	destAddr := r.Host
	if p.upstream != nil {
		destAddr = p.upstream.URL.Host
	}

	// Use Transport.DialContext if available, otherwise default to net.Dialer
	dialContext := p.Transport.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{}).DialContext
	}

	// Prepare context with timeout
	ctx := r.Context()
	if p.upstream != nil && p.upstream.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.upstream.Timeout)
		defer cancel()
	}

	destConn, err = dialContext(ctx, "tcp", destAddr)

	if err != nil {
		http.Error(w, "Destination unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// If using upstream proxy, send CONNECT request
	if p.upstream != nil {
		connectReq := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: r.Host},
			Header: make(http.Header), // Propagate headers
			Host:   r.Host,
		}
		// Copy headers to propagate Via, etc.
		copyHeaders(connectReq.Header, r.Header)

		if err := connectReq.Write(destConn); err != nil {
			destConn.Close()
			http.Error(w, "Failed to send CONNECT to upstream: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		// Read response from upstream
		br := bufio.NewReader(destConn)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			destConn.Close()
			http.Error(w, "Failed to read response from upstream: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if resp.StatusCode != http.StatusOK {
			destConn.Close()
			http.Error(w, "Upstream proxy refused connection: "+resp.Status, http.StatusServiceUnavailable)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Prepare context with timeout (if upstream is configured)
	ctx := r.Context()
	if p.upstream != nil && p.upstream.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.upstream.Timeout)
		defer cancel()
	}

	// Create a new request to forward
	outReq := r.Clone(ctx)
	outReq.RequestURI = "" // RequestURI must be empty for client requests

	// Ensure Host header is set correctly
	if outReq.Host == "" {
		outReq.Host = r.URL.Host
	}

	// Use pre-configured client with current Transport
	// We shallow copy the client to ensure we use the potentially updated p.Transport
	// if the user replaced the Transport struct entirely.
	client := *p.Client
	client.Transport = p.Transport

	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Apply Response Filters
	for _, f := range p.ResponseFilters {
		if err := f(resp); err != nil {
			fmt.Printf("Response Filter error: %v\n", err)
			if b, ok := err.(*BlockedRequestError); ok {
				http.Error(w, fmt.Sprintf("Response Blocked: %s", b.Message), http.StatusForbidden)
			} else {
				http.Error(w, "Internal Proxy Error", http.StatusInternalServerError)
			}
			return
		}
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
