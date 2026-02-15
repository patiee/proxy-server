package server

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// PrivacyLevel defines the level of privacy for the proxy.
type PrivacyLevel int

const (
	// Transparent: The proxy forwards the client's IP address.
	Transparent PrivacyLevel = iota
	// Anonymous: The proxy hides the client's IP address but identifies itself as a proxy.
	Anonymous
	// Elite: The proxy hides the client's IP address and does not identify itself as a proxy.
	Elite
)

// ProxyServer represents a proxy server with a specific privacy level.
type ProxyServer struct {
	PrivacyLevel PrivacyLevel
	Port         string
}

// NewProxyServer creates a new ProxyServer with the given configuration.
func NewProxyServer(privacyLevel PrivacyLevel, port string) *ProxyServer {
	return &ProxyServer{
		PrivacyLevel: privacyLevel,
		Port:         port,
	}
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
	// Apply privacy settings
	p.applyPrivacy(r)

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

// applyPrivacy modifies the request headers based on the privacy level.
func (p *ProxyServer) applyPrivacy(r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Handle X-Forwarded-For
	if p.PrivacyLevel == Transparent {
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		r.Header.Set("X-Forwarded-For", clientIP)
	} else {
		// Anonymous and Elite: Remove X-Forwarded-For
		r.Header.Del("X-Forwarded-For")
	}

	// Handle Via
	if p.PrivacyLevel == Elite {
		r.Header.Del("Via")
	} else {
		// Transparent and Anonymous: Set Via
		r.Header.Set("Via", "1.1 "+p.Port)
	}
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
