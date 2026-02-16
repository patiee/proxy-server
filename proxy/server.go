package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/patiee/proxy/cert"
	"github.com/patiee/proxy/config"
	phttp "github.com/patiee/proxy/http"
	"github.com/patiee/proxy/socks5"
)

// ProxyServer represents a proxy server.
// It acts as a facade for HTTP and SOCKS5 servers.
type ProxyServer struct {
	port               string
	via                *string
	upstream           *config.UpstreamConfig
	timeout            time.Duration
	InsecureSkipVerify bool

	Socks5User     string
	Socks5Password string

	// HTTP Handler handles filtering and HTTP/HTTPS logic
	Handler *phttp.ProxyHandler

	// SOCKS5 Server
	Socks5 *socks5.Server

	// Certificate Manager for MITM
	CertManager *cert.CertificateManager
	// HTTP Transport for upstream connections
	Transport *http.Transport
}

// NewProxyServer creates a new ProxyServer.
func NewProxyServer(conf *config.Config) (*ProxyServer, error) {
	p := &ProxyServer{
		port:     conf.Port,
		via:      conf.Via,
		upstream: conf.Upstream,
	}

	if conf.Socks5 != nil {
		if conf.Socks5.User != nil {
			p.Socks5User = *conf.Socks5.User
		}
		if conf.Socks5.Password != nil {
			p.Socks5Password = *conf.Socks5.Password
		}
	}

	if conf.InsecureSkipVerify != nil {
		p.InsecureSkipVerify = *conf.InsecureSkipVerify
	} else {
		p.InsecureSkipVerify = false // Default
	}

	// Setup Transport
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	p.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment, // Default
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.InsecureSkipVerify,
		},
	}

	if conf.Timeout != nil {
		p.timeout = time.Duration(*conf.Timeout) * time.Second
	} else {
		p.timeout = 10 * time.Second
	}

	// Upstream Proxy
	if p.upstream != nil {
		proxyURL := p.upstream.URL
		if proxyURL.Scheme == "socks5" {
			// SOCKS5 Upstream
			var auth *socks5.Auth
			if u := proxyURL.User; u != nil {
				auth = &socks5.Auth{
					User: u.Username(),
				}
				if p, ok := u.Password(); ok {
					auth.Password = p
				}
			}

			// Use native SOCKS5 client
			socksClient := socks5.NewClient(proxyURL.Host, auth)

			// Wrap socks dialer context
			p.Transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Apply upstream connection timeout
				if p.upstream.Timeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, p.upstream.Timeout)
					defer cancel()
				}
				return socksClient.DialContext(ctx, network, addr)
			}
			p.Transport.Proxy = nil // Disable http proxy since we handle separate Transport
		} else {
			// HTTP/HTTPS Upstream
			// Use http.Transport's Proxy field
			p.Transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	// Cert Manager
	caCertPath := ""
	caKeyPath := ""
	if conf.CaCertPath != nil {
		caCertPath = *conf.CaCertPath
	}
	if conf.CaKeyPath != nil {
		caKeyPath = *conf.CaKeyPath
	}

	// Create CertManager
	var ca tls.Certificate
	var err error

	if caCertPath != "" && caKeyPath != "" {
		ca, err = tls.LoadX509KeyPair(caCertPath, caKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA key pair: %v", err)
		}
	} else {
	}

	if ca.Certificate != nil {
		p.CertManager = cert.NewCertificateManager(&ca)
	}

	// Initialize HTTP Handler
	p.Handler = phttp.NewProxyHandler(p.CertManager, p.Transport)
	p.Handler.Via = p.via
	p.Handler.InsecureSkipVerify = p.InsecureSkipVerify
	p.Handler.Timeout = p.timeout

	// Initialize SOCKS5 Server
	socks5Timeout := 10 * time.Second
	if conf.Socks5 != nil && conf.Socks5.Timeout != nil && *conf.Socks5.Timeout > 0 {
		socks5Timeout = time.Duration(*conf.Socks5.Timeout) * time.Second
	}
	p.Socks5 = socks5.NewServer(p.Socks5User, p.Socks5Password, p.upstream, socks5Timeout, p.Handler)

	return p, nil
}

// AddRequestFilter adds a request filter function to the proxy server.
func (p *ProxyServer) AddRequestFilter(f func(*http.Request) error) {
	p.Handler.RequestFilters = append(p.Handler.RequestFilters, f)
}

// AddHttpsFilter adds a filter to determine if HTTPS should be intercepted.
func (p *ProxyServer) AddHttpsFilter(f func(*http.Request) bool) {
	p.Handler.HttpsFilters = append(p.Handler.HttpsFilters, f)
}

// AddResponseFilter adds a response filter function.
func (p *ProxyServer) AddResponseFilter(f func(*http.Response) error) {
	p.Handler.ResponseFilters = append(p.Handler.ResponseFilters, f)
}

// ServeHTTP handles the proxy requests by delegating to the Handler.
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.Handler.ServeHTTP(w, r)
}

// ServeSOCKS5 accepts SOCKS5 connections.
func (p *ProxyServer) ServeSOCKS5(l net.Listener) error {
	return p.Socks5.Serve(l)
}

// SetCA configures the Certificate Authority for MITM.
// This method is now deprecated as CA is set during NewProxyServer.
// It's kept for backward compatibility but will delegate to the handler.
func (p *ProxyServer) SetCA(certPath, keyPath string) error {
	ca, err := cert.LoadCA(certPath, keyPath)
	if err != nil {
		return err
	}
	p.Handler.CertManager = cert.NewCertificateManager(ca)
	return nil
}
