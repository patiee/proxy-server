package server

import (
	"io"
	"net"
	"net/http"
	"time"
)

// ProxyServer represents a proxy server.
type ProxyServer struct {
	Port    string
	Via     *string
	Filters []func(*http.Request)
}

// NewProxyServer creates a new ProxyServer with the given configuration.
func NewProxyServer(port string, via *string) *ProxyServer {
	return &ProxyServer{
		Port: port,
		Via:  via,
	}
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
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
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
		r.Header.Set("Via", *p.Via)
	}

	// Create a new request to forward
	outReq := new(http.Request)
	*outReq = *r           // shallow copy
	outReq.RequestURI = "" // RequestURI must be empty for client requests

	// Ensure Host header is set correctly
	if outReq.Host == "" {
		outReq.Host = r.URL.Host
	}

	client := &http.Client{}
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
