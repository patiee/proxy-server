package http_test

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/patiee/proxy/cert"
	proxyhttp "github.com/patiee/proxy/http"
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
		IsCA:                  true, // Add random SKI and matching AKI for Root
		SubjectKeyId:          []byte{1, 2, 3, 4},
		AuthorityKeyId:        []byte{1, 2, 3, 4},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	// Parse leaf to ensure it's valid for signing
	var parseErr error
	cert.Leaf, parseErr = x509.ParseCertificate(cert.Certificate[0])
	if parseErr != nil {
		return nil, parseErr
	}
	return &cert, nil
}

func TestMITM(t *testing.T) {
	// 1. Setup Target Server (HTTPS)
	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify propagated header from MITM filter
		if r.Header.Get("X-Intercepted") != "true" {
			t.Error("Target did not receive X-Intercepted header")
		}
		w.Header().Set("X-Response-Modified", "original")
		w.Write([]byte("Target Response"))
	})
	targetServer := httptest.NewTLSServer(targetHandler)
	defer targetServer.Close()

	// 2. Setup Proxy Handler with MITM
	skipVerify := true

	ca, err := generateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	certManager := cert.NewCertificateManager(ca)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	handler := proxyhttp.NewProxyHandler(certManager, transport)
	handler.InsecureSkipVerify = skipVerify

	// Add HttpsFilter to intercept everything
	handler.HttpsFilters = append(handler.HttpsFilters, func(r *http.Request) bool {
		return true // Intercept all
	})

	// Add Request Filter to inject header
	handler.RequestFilters = append(handler.RequestFilters, func(r *http.Request) error {
		if r.Method != http.MethodConnect {
			r.Header.Set("X-Intercepted", "true")
		}
		return nil
	})

	// Add Response Filter to modify response
	handler.ResponseFilters = append(handler.ResponseFilters, func(resp *http.Response) error {
		resp.Header.Set("X-Response-Modified", "modified")
		return nil
	})

	// Start Proxy
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// 3. Setup Client
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := targetServer.Client() // Uses target's cert pool (but we need to trust the Proxy's CA for MITM)

	// Add CA to client's RootCAs
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca.Leaf)

	// Create a custom transport that trusts our CA
	clientTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	client.Transport = clientTransport

	// 4. Perform Request
	resp, err := client.Get(targetServer.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// 5. Verify Response
	if resp.Header.Get("X-Response-Modified") != "modified" {
		t.Errorf("Response filter not applied. Header: %v", resp.Header.Get("X-Response-Modified"))
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Target Response" {
		t.Errorf("Unexpected body: %s", body)
	}
}

func TestMITM_SecureValidation(t *testing.T) {
	// 1. Setup Target CA and Server
	targetCA, err := generateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate Target CA: %v", err)
	}
	targetCM := cert.NewCertificateManager(targetCA)
	targetCert, err := targetCM.GetCertificate(&tls.ClientHelloInfo{ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Failed to generate target cert: %v", err)
	}

	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Target Response"))
	})

	targetServer := httptest.NewUnstartedServer(targetHandler)
	targetServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*targetCert},
	}
	targetServer.StartTLS()
	defer targetServer.Close()

	// 2. Setup Proxy Handler with MITM
	skipVerify := false

	ca, err := generateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	certManager := cert.NewCertificateManager(ca)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	// Add target cert to proxy's RootCAs
	certPool := x509.NewCertPool()
	certPool.AddCert(targetCert.Leaf)
	transport.TLSClientConfig.RootCAs = certPool

	handler := proxyhttp.NewProxyHandler(certManager, transport)
	handler.InsecureSkipVerify = skipVerify

	handler.HttpsFilters = append(handler.HttpsFilters, func(r *http.Request) bool {
		return true // Intercept all
	})

	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// 3. Setup Client
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := targetServer.Client()

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca.Leaf)

	clientTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	client.Transport = clientTransport

	// 4. Perform Request
	resp, err := client.Get(targetServer.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Target Response" {
		t.Errorf("Unexpected body: %s", body)
	}
}

func TestMITM_NestedConnect(t *testing.T) {
	// 1. Setup Final Target
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Final Target Reached"))
	})
	finalServer := httptest.NewServer(finalHandler)
	defer finalServer.Close()
	finalURL, _ := url.Parse(finalServer.URL)

	// 2. Setup Secondary Proxy (Manual TLS Listener to avoid httptest hijack issues)
	secCert, _ := generateTestCA()
	secTLSConfig := &tls.Config{Certificates: []tls.Certificate{*secCert}}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", secTLSConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	secondaryAddr := listener.Addr().String()
	secondaryURL := &url.URL{Scheme: "https", Host: secondaryAddr}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read CONNECT request
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}

				if req.Method != http.MethodConnect {
					c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
					return
				}

				// Dial Target
				destConn, err := net.Dial("tcp", req.Host)
				if err != nil {
					c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer destConn.Close()

				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

				// Pipe
				go func() {
					io.Copy(destConn, c)
					destConn.Close() // Close dest when client is done
				}()
				io.Copy(c, destConn)
			}(conn)
		}
	}()

	// 3. Setup Primary Proxy (MITM)
	skipVerify := true
	ca, err := generateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	certManager := cert.NewCertificateManager(ca)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	handler := proxyhttp.NewProxyHandler(certManager, transport)
	handler.InsecureSkipVerify = skipVerify
	handler.HttpsFilters = append(handler.HttpsFilters, func(r *http.Request) bool { return true }) // Intercept all

	primaryServer := httptest.NewServer(handler)
	defer primaryServer.Close()
	primaryURL, _ := url.Parse(primaryServer.URL)

	// 4. Client Logic
	t.Log("Dialing Primary...")
	conn, err := net.Dial("tcp", primaryURL.Host)
	if err != nil {
		t.Fatalf("Failed to dial primary: %v", err)
	}
	defer conn.Close()

	// B. CONNECT to Secondary (at Primary)
	t.Log("Sending CONNECT to Secondary...")
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", secondaryURL.Host, secondaryURL.Host)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("Failed to connect to secondary via primary: %v", err)
	}
	t.Log("Primary tunnel established.")

	// C. Upgrade to TLS (Client side of MITM)
	t.Log("Performing TLS Handshake with Primary...")
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Leaf)
	tlsConfig := &tls.Config{RootCAs: certPool, ServerName: secondaryURL.Hostname()}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS Handshake failed: %v", err)
	}
	t.Log("TLS Handshake complete.")

	// D. CONNECT to Final (at Secondary, THROUGH Primary)
	t.Log("Sending Nested CONNECT to Final...")
	fmt.Fprintf(tlsConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", finalURL.Host, finalURL.Host)

	tlsBr := bufio.NewReader(tlsConn)
	resp2, err := http.ReadResponse(tlsBr, nil)
	if err != nil || resp2.StatusCode != 200 {
		t.Fatalf("Failed to connect to final via secondary: %v", err)
	}
	t.Log("Nested tunnel established.")

	// E. Send GET request to Final
	t.Log("Sending GET to Final...")
	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", finalURL.Host)

	// F. Read Response
	t.Log("Reading Final Response...")
	resp3, err := http.ReadResponse(tlsBr, nil)
	if err != nil {
		t.Fatalf("Failed to read final response: %v", err)
	}
	body, _ := io.ReadAll(resp3.Body)
	if string(body) != "Final Target Reached" {
		t.Errorf("Unexpected body: %s", body)
	}
	t.Log("Test Complete.")
}
