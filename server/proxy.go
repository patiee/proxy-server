package server

import (
	"bufio"
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
	Port     string
	Via      *string
	Upstream *config.UpstreamConfig
	Filters  []func(*http.Request)
}

// NewProxyServer creates a new ProxyServer with the given configuration.
func NewProxyServer(port string, via *string, upstream *config.UpstreamConfig) (*ProxyServer, error) {
	if upstream != nil {
		if !strings.HasPrefix(upstream.URL, "http://") && !strings.HasPrefix(upstream.URL, "https://") {
			return nil, fmt.Errorf("upstream proxy must start with http:// or https://")
		}
		// Validate URL parsing
		_, err := url.Parse(upstream.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL: %v", err)
		}
	}
	return &ProxyServer{
		Port:     port,
		Via:      via,
		Upstream: upstream,
	}, nil
}

// ApplyFilter adds a filter function to the proxy server.
func (p *ProxyServer) ApplyFilter(f func(*http.Request)) {
	p.Filters = append(p.Filters, f)
}

// ServeHTTP handles the proxy requests.
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleHTTPS(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	var destConn net.Conn
	var err error

	if p.Upstream != nil {
		// Parse upstream URL to get host
		upstreamURL, err := url.Parse(p.Upstream.URL)
		if err != nil {
			http.Error(w, "Invalid upstream configuration: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Connect to upstream proxy with configured timeout
		var timeout time.Duration
		if p.Upstream.Timeout != nil {
			timeout = time.Duration(*p.Upstream.Timeout) * time.Second
		}
		if timeout == 0 {
			timeout = 10 * time.Second // Default fallback safe guard
		}
		destConn, err = net.DialTimeout("tcp", upstreamURL.Host, timeout)
		if err != nil {
			http.Error(w, "Upstream proxy unavailable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		// Send CONNECT request to upstream
		connectReq := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: r.Host},
			Header: make(http.Header),
			Host:   r.Host,
		}
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
	} else {
		// Direct connection
		destConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
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
	// Apply all filters
	for _, f := range p.Filters {
		f(r)
	}

	// Set Via header if configured
	if p.Via != nil {
		if prior := r.Header.Get("Via"); prior != "" {
			r.Header.Set("Via", prior+", "+*p.Via)
		} else {
			r.Header.Set("Via", *p.Via)
		}
	}

	// Create a new request to forward
	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // RequestURI must be empty for client requests

	// Ensure Host header is set correctly
	if outReq.Host == "" {
		outReq.Host = r.URL.Host
	}

	client := &http.Client{}

	// Configure upstream proxy for HTTP requests
	if p.Upstream != nil {
		proxyUrl, err := url.Parse(p.Upstream.URL)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(proxyUrl),
			}
		}
		if p.Upstream.Timeout != nil && *p.Upstream.Timeout > 0 {
			client.Timeout = time.Duration(*p.Upstream.Timeout) * time.Second
		} else {
			client.Timeout = 10 * time.Second
		}
	}

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
