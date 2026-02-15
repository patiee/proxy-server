package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/patiee/proxy/server"
)

func TestPrivacyLevels(t *testing.T) {
	tests := []struct {
		name         string
		privacyLevel server.PrivacyLevel
		expectVia    bool
		expectXFF    bool
	}{
		{
			name:         "Transparent",
			privacyLevel: server.Transparent,
			expectVia:    true,
			expectXFF:    true,
		},
		{
			name:         "Anonymous",
			privacyLevel: server.Anonymous,
			expectVia:    true,
			expectXFF:    false,
		},
		{
			name:         "Elite",
			privacyLevel: server.Elite,
			expectVia:    false,
			expectXFF:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start a dummy backend server to capture the proxied request
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify headers received by backend

				// Check Via header
				if tt.expectVia {
					if r.Header.Get("Via") == "" {
						t.Errorf("Backend expected Via header, got none")
					}
				} else {
					if r.Header.Get("Via") != "" {
						t.Errorf("Backend expected no Via header, got %s", r.Header.Get("Via"))
					}
				}

				// Check X-Forwarded-For header
				if tt.expectXFF {
					if r.Header.Get("X-Forwarded-For") == "" {
						t.Errorf("Backend expected X-Forwarded-For header, got none")
					}
				} else {
					if r.Header.Get("X-Forwarded-For") != "" {
						t.Errorf("Backend expected no X-Forwarded-For header, got %s", r.Header.Get("X-Forwarded-For"))
					}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			proxyServer := server.NewProxyServer(tt.privacyLevel, "8080")

			// Create a request to the backend through the proxy
			req := httptest.NewRequest("GET", backend.URL, nil)
			req.RemoteAddr = "127.0.0.1:1234"

			// Simulate previous proxy if testing Transparent
			if tt.privacyLevel == server.Transparent {
				req.Header.Set("X-Forwarded-For", "192.168.1.1")
			}

			w := httptest.NewRecorder()
			proxyServer.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Proxy returned status %v", w.Code)
			}
		})
	}
}
