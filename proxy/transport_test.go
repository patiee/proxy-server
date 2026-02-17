package proxy_test

import (
	"net/http"
	"testing"

	"github.com/patiee/proxy/config"
	plog "github.com/patiee/proxy/log"
	proxy "github.com/patiee/proxy/proxy"
)

func TestTransportModification(t *testing.T) {
	// 1. Create ProxyServer
	c := &config.Config{
		Port: "8080",
	}
	p, err := proxy.NewProxyServer(c, plog.DefaultLogger())
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// 2. Modify a field in the existing Transport
	// Change MaxIdleConns to a specific value
	p.Handler.Transport.MaxIdleConns = 123

	// Check if Handler sees the change
	if p.Handler.Transport.MaxIdleConns != 123 {
		t.Errorf("Modifying p.Handler.Transport field failed. Got %d", p.Handler.Transport.MaxIdleConns)
	} else {
		t.Log("Modifying p.Handler.Transport field updated correctly (Expected)")
	}

	// 3. Replace the Transport object entirely?
	// Note: replacing p.Handler.Transport modifies the pointer in Handler struct.
	// Since Handler uses this pointer directly, it should work.
	newTransport := &http.Transport{MaxIdleConns: 456}
	p.Handler.Transport = newTransport

	// Check if Handler sees the replacement
	if p.Handler.Transport.MaxIdleConns == 456 {
		t.Log("Replacing p.Handler.Transport updated correctly (Expected)")
	} else {
		t.Logf("Replacing p.Handler.Transport did NOT update. Handler has %d", p.Handler.Transport.MaxIdleConns)
	}
}
