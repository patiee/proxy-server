package socks5_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/patiee/proxy/cert"
	phttp "github.com/patiee/proxy/http"
	"github.com/patiee/proxy/socks5"
)

// Helper to generate a self-signed CA for testing
func generateTestCA() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		AuthorityKeyId:        []byte{1, 2, 3, 4},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	ca, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	// Parse leaf
	var parseErr error
	ca.Leaf, parseErr = x509.ParseCertificate(ca.Certificate[0])
	if parseErr != nil {
		return nil, parseErr
	}
	return &ca, nil
}

func TestSOCKS5Server_HTTP(t *testing.T) {
	// 1. Setup Backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-response"))
	}))
	defer backend.Close()

	// 2. Setup SOCKS5 Server and ProxyHandler
	transport := &http.Transport{}
	handler := phttp.NewProxyHandler(nil, transport)

	filterCalled := false
	handler.RequestFilters = append(handler.RequestFilters, func(r *http.Request) error {
		filterCalled = true
		r.Header.Set("X-Filtered", "true")
		return nil
	})

	server := socks5.NewServer("", "", nil, 10*time.Second, handler)

	// Start SOCKS5 Listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	go server.Serve(listener)
	defer listener.Close()

	// 3. Connect via SOCKS5 Client
	socksDialer, err := proxy.SOCKS5("tcp", listener.Addr().String(), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create socks dialer: %v", err)
	}

	clientTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socksDialer.Dial(network, addr)
		},
	}
	client := &http.Client{Transport: clientTransport, Timeout: 5 * time.Second}

	// 4. Send Request
	req, _ := http.NewRequest("GET", backend.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// 5. Verify
	if !filterCalled {
		t.Errorf("Filter was not called")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-response" {
		t.Errorf("Unexpected body: %s", body)
	}
}

func TestSOCKS5Server_HTTPS(t *testing.T) {
	// 1. Setup Backend (HTTPS)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Filtered") != "true" {
			t.Errorf("Backend did not receive X-Filtered header")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure-backend-response"))
	}))
	defer backend.Close()

	// Initialize CertManager with test CA
	ca, err := generateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate test CA: %v", err)
	}

	certManager := cert.NewCertificateManager(ca)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	handler := phttp.NewProxyHandler(certManager, transport)
	handler.InsecureSkipVerify = true // For backend connection

	filterCalled := false
	handler.RequestFilters = append(handler.RequestFilters, func(r *http.Request) error {
		filterCalled = true
		r.Header.Set("X-Filtered", "true")
		return nil
	})

	server := socks5.NewServer("", "", nil, 10*time.Second, handler)

	// Start SOCKS5 Listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	go server.Serve(listener)
	defer listener.Close()

	// 3. Connect via SOCKS5 Client with TLS Transport
	socksDialer, err := proxy.SOCKS5("tcp", listener.Addr().String(), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create socks dialer: %v", err)
	}

	clientTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socksDialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Trust the proxy's MITM cert
	}
	client := &http.Client{Transport: clientTransport, Timeout: 5 * time.Second}

	// 4. Send Request
	req, _ := http.NewRequest("GET", backend.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// 5. Verify
	if !filterCalled {
		t.Errorf("Filter was not called")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure-backend-response" {
		t.Errorf("Unexpected body: %s", body)
	}
}

func TestSOCKS5Server_Auth(t *testing.T) {
	// 1. Setup Backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("auth-backend-response"))
	}))
	defer backend.Close()

	// 2. Setup SOCKS5 Server with Credentials
	user := "user"
	pass := "pass"

	transport := &http.Transport{}
	handler := phttp.NewProxyHandler(nil, transport)
	server := socks5.NewServer(user, pass, nil, 10*time.Second, handler)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	go server.Serve(listener)
	defer listener.Close()

	// 3. Test Cases
	tests := []struct {
		name      string
		user      string
		pass      string
		expectErr bool
	}{
		{"Correct Credentials", "user", "pass", false},
		{"Incorrect Password", "user", "wrong", true},
		{"Incorrect User", "wrong", "pass", true},
		{"No Credentials (should fail)", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var auth *proxy.Auth
			if tt.user != "" || tt.pass != "" {
				auth = &proxy.Auth{User: tt.user, Password: tt.pass}
			}

			socksDialer, err := proxy.SOCKS5("tcp", listener.Addr().String(), auth, proxy.Direct)
			if err != nil {
				t.Fatalf("Failed to create socks dialer: %v", err)
			}

			clientTransport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return socksDialer.Dial(network, addr)
				},
			}
			client := &http.Client{Transport: clientTransport, Timeout: 2 * time.Second}

			req, _ := http.NewRequest("GET", backend.URL, nil)
			resp, err := client.Do(req)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if string(body) != "auth-backend-response" {
					t.Errorf("Unexpected body: %s", body)
				}
			}
		})
	}
}
