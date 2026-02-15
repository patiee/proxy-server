package server_test

import (
	"net/http"
	"testing"

	"github.com/patiee/proxy/server"
)

func TestTransportModification(t *testing.T) {
	// 1. Create ProxyServer
	p, err := server.NewProxyServer("8080", nil, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// 2. Modify a field in the existing Transport
	// Change MaxIdleConns to a specific value
	p.Transport.MaxIdleConns = 123

	// Check if Client sees the change
	clientTransport, ok := p.Client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Client.Transport is not *http.Transport")
	}

	if clientTransport.MaxIdleConns != 123 {
		t.Errorf("Modifying p.Transport field did NOT update p.Client.Transport field. Got %d", clientTransport.MaxIdleConns)
	} else {
		t.Log("Modifying p.Transport field updated p.Client.Transport field (Expected)")
	}

	// 3. Replace the Transport object entirely
	newTransport := &http.Transport{MaxIdleConns: 456}
	p.Transport = newTransport

	// Check if Client sees the replacement
	clientTransportAfterReplace, _ := p.Client.Transport.(*http.Transport)
	if clientTransportAfterReplace.MaxIdleConns == 456 {
		t.Log("Replacing p.Transport updated p.Client.Transport (Unexpected for current impl)")
	} else {
		t.Logf("Replacing p.Transport did NOT update p.Client.Transport. Client has %d, Transport has %d", clientTransportAfterReplace.MaxIdleConns, p.Transport.MaxIdleConns)
	}
}
