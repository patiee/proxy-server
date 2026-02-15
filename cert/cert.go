package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertificateManager handles the generation of certificates for MITM.
type CertificateManager struct {
	ca        *tls.Certificate
	certCache sync.Map // map[string]*tls.Certificate
}

// NewCertificateManager creates a new CertificateManager with the given CA.
func NewCertificateManager(ca *tls.Certificate) *CertificateManager {
	return &CertificateManager{
		ca: ca,
	}
}

// GetCertificate returns a certificate for the given host.
// If it doesn't exist in the cache, it generates a new one signed by the CA.
func (cm *CertificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = "example.com" // Fallback if SNI is missing
	}

	if cert, ok := cm.certCache.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	cert, err := cm.signCertificate(host)
	if err != nil {
		return nil, err
	}

	cm.certCache.Store(host, cert)
	return cert, nil
}

func (cm *CertificateManager) signCertificate(host string) (*tls.Certificate, error) {
	// Generate a key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Go Proxy MITM"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        cm.ca.Leaf.SubjectKeyId,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	// Sign the certificate with the CA
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, cm.ca.Leaf, &priv.PublicKey, cm.ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode certificate and key
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Parse TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS certificate: %v", err)
	}

	return &tlsCert, nil
}

// LoadCA loads the CA certificate and key from files.
func LoadCA(certPath, keyPath string) (*tls.Certificate, error) {
	ca, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	// Parse leaf certificate to ensure it's valid for signing
	if ca.Leaf == nil {
		leaf, err := x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			return nil, err
		}
		ca.Leaf = leaf
	}

	return &ca, nil
}
