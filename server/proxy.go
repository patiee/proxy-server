package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patiee/proxy/config"
)

// ProxyServer represents a proxy server.
type ProxyServer struct {
	port            string
	via             *string
	upstream        *config.UpstreamConfig
	upstreamURL     *url.URL
	upstreamTimeout time.Duration
	timeout         time.Duration

	Filters []func(*http.Request) error

	Transport *http.Transport
	Client    *http.Client
}

// NewProxyServer creates a new ProxyServer with the given configuration.
func NewProxyServer(port string, via *string, upstream *config.UpstreamConfig, timeout *int) (*ProxyServer, error) {
	p := &ProxyServer{
		port:     port,
		via:      via,
		upstream: upstream,
	}

	if timeout != nil && *timeout > 0 {
		p.timeout = time.Duration(*timeout) * time.Second
	} else {
		p.timeout = 10 * time.Second
	}

	// Default Transport
	p.Transport = &http.Transport{}

	if upstream != nil {
		if !strings.HasPrefix(upstream.URL, "http://") && !strings.HasPrefix(upstream.URL, "https://") {
			return nil, fmt.Errorf("upstream proxy must start with http:// or https://")
		}
		// Validate URL parsing
		u, err := url.Parse(upstream.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL: %v", err)
		}
		p.upstreamURL = u

		// Set upstream timeout
		if upstream.Timeout != nil {
			p.upstreamTimeout = time.Duration(*upstream.Timeout) * time.Second
		}
		if p.upstreamTimeout == 0 {
			// Default timeout
			p.upstreamTimeout = 10 * time.Second
		}

		// Configure Transport with upstream proxy
		p.Transport.Proxy = http.ProxyURL(u)
	}

	// Initialize Client with configured Transport and Timeout
	p.Client = &http.Client{
		Transport: p.Transport,
		Timeout:   p.timeout,
	}

	return p, nil
}

// AddFilter adds a filter function to the proxy server.
func (p *ProxyServer) AddFilter(f func(*http.Request) error) {
	p.Filters = append(p.Filters, f)
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
		p.handleHTTPS(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	var destConn net.Conn
	var err error

	// Determine destination address
	destAddr := r.Host
	if p.upstream != nil {
		destAddr = p.upstreamURL.Host
	}

	// Use Transport.DialContext if available, otherwise default to net.Dialer
	dialContext := p.Transport.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{}).DialContext
	}

	// Prepare context with timeout
	ctx := r.Context()
	if p.upstreamTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.upstreamTimeout)
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
	if p.upstreamTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.upstreamTimeout)
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
