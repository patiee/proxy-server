package http_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/patiee/proxy/config"
	"github.com/patiee/proxy/errors"
	proxyhttp "github.com/patiee/proxy/http"
	plog "github.com/patiee/proxy/log"
)

func TestProxyHeaders(t *testing.T) {
	defaultVia := "1.1 8080"
	customVia := "proxy-server-v1.0.0 127.0.0.1:8080"

	// Define a custom filter function
	addHeaderFilter := func(r *http.Request) error {
		r.Header.Set("X-Filtered", "true")
		return nil
	}

	// Define X-Forwarded-For filter
	xffFilter := func(r *http.Request) error {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		r.Header.Set("X-Forwarded-For", clientIP)
		return nil
	}

	mockURL, _ := url.Parse("http://mock_upstream")

	tests := []struct {
		name               string
		viaConfig          *string
		upstreamConfig     *config.UpstreamConfig
		filterConfigs      []func(*http.Request) error
		headersToSet       map[string]string
		expectVia          bool
		expectedVia        string
		expectXFF          bool
		expectFilter       bool
		expectSecondFilter bool
		expectStatus       int
	}{
		{
			name:          "Standard Proxy Behavior (Default Via = nil)",
			viaConfig:     nil,
			filterConfigs: []func(*http.Request) error{xffFilter},
			headersToSet:  map[string]string{"X-Before": "test"},
			expectVia:     false,
			expectXFF:     true,
			expectFilter:  false,
		},
		{
			name:          "Configured Via Header",
			viaConfig:     &defaultVia,
			filterConfigs: []func(*http.Request) error{xffFilter},
			headersToSet:  map[string]string{"X-Before": "test"},
			expectVia:     true,
			expectedVia:   defaultVia,
			expectXFF:     true,
			expectFilter:  false,
		},
		{
			name:          "Custom Via Header",
			viaConfig:     &customVia,
			filterConfigs: []func(*http.Request) error{xffFilter},
			headersToSet:  map[string]string{"X-Before": "test"},
			expectVia:     true,
			expectedVia:   customVia,
			expectXFF:     true,
			expectFilter:  false,
		},
		{
			name:          "Appends XFF",
			viaConfig:     nil,
			filterConfigs: []func(*http.Request) error{xffFilter},
			headersToSet:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			expectVia:     false,
			expectXFF:     true,
			expectFilter:  false,
		},
		{
			name:          "Custom Request Filter",
			viaConfig:     nil,
			filterConfigs: []func(*http.Request) error{xffFilter, addHeaderFilter},
			headersToSet:  map[string]string{"X-Before": "test"},
			expectVia:     false,
			expectXFF:     true,
			expectFilter:  true,
			expectStatus:  0,
		},
		{
			name:      "Multiple Filters",
			viaConfig: nil,
			filterConfigs: []func(*http.Request) error{
				xffFilter,
				addHeaderFilter,
				func(r *http.Request) error {
					r.Header.Set("X-Second-Filter", "working")
					return nil
				},
			},
			headersToSet:       map[string]string{"X-Before": "test"},
			expectVia:          false,
			expectXFF:          true,
			expectFilter:       true,
			expectSecondFilter: true,
		},
		{
			name:           "Upstream Proxy Chaining",
			viaConfig:      nil,
			upstreamConfig: &config.UpstreamConfig{URL: mockURL, Timeout: 10 * time.Second},
			filterConfigs:  []func(*http.Request) error{xffFilter},
			headersToSet:   map[string]string{"X-Before": "test"},
			expectVia:      false,
			expectXFF:      false, // Upstream mock doesn't forward to backend in test logic above, so backend logic skipped
			expectFilter:   false,
		},
		{
			name:          "Blocking Filter",
			viaConfig:     nil,
			filterConfigs: []func(*http.Request) error{func(r *http.Request) error { return errors.NewBlockedRequestError("blocked") }},
			headersToSet:  map[string]string{"X-Before": "test"},
			expectVia:     false,
			expectXFF:     false,
			expectFilter:  false,
			expectStatus:  http.StatusForbidden,
		},
		{
			name:          "Internal Error Filter",
			viaConfig:     nil,
			filterConfigs: []func(*http.Request) error{func(r *http.Request) error { return fmt.Errorf("internal failure") }},
			headersToSet:  map[string]string{"X-Before": "test"},
			expectVia:     false,
			expectXFF:     false,
			expectFilter:  false,
			expectStatus:  http.StatusInternalServerError,
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
					} else if r.Header.Get("Via") != tt.expectedVia {
						t.Errorf("Backend expected Via header %s, got %s", tt.expectedVia, r.Header.Get("Via"))
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
					// If we sent one, it should contain it
					if val, ok := tt.headersToSet["X-Forwarded-For"]; ok {
						if !strings.Contains(r.Header.Get("X-Forwarded-For"), val) {
							t.Errorf("Backend expected XFF to contain %s, got %s", val, r.Header.Get("X-Forwarded-For"))
						}
					}
				}

				// Check Filter effect
				if tt.expectFilter {
					if r.Header.Get("X-Filtered") != "true" {
						t.Errorf("Backend expected X-Filtered header, got none")
					}
				}

				// Check Second Filter effect
				if tt.expectSecondFilter {
					if r.Header.Get("X-Second-Filter") != "working" {
						t.Errorf("Backend expected X-Second-Filter header, got none")
					}
				}

				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			var upstream *httptest.Server
			if tt.upstreamConfig != nil && tt.upstreamConfig.URL.Host == "mock_upstream" {
				upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify upstream received the request
					t.Logf("Upstream received request: %s %s", r.Method, r.URL.String())

					if r.Method == http.MethodConnect {
						w.WriteHeader(http.StatusOK)
						return
					}

					// Check if target is backend
					if !strings.Contains(r.URL.String(), backend.URL) && !strings.Contains(backend.URL, r.URL.String()) {
						t.Errorf("Upstream expected target %s, got %s", backend.URL, r.URL.String())
					}

					// Imitate successful proxying by just returning OK from upstream
					w.WriteHeader(http.StatusOK)
				}))
				defer upstream.Close()

				// Parse host:port from upstream.URL
				u, _ := url.Parse(upstream.URL)
				tt.upstreamConfig.URL = u
			}

			// Setup Transport
			transport := &http.Transport{}
			if tt.upstreamConfig != nil {
				transport.Proxy = http.ProxyURL(tt.upstreamConfig.URL)
			}

			handler := proxyhttp.NewProxyHandler(nil, transport, plog.DefaultLogger())
			handler.Via = tt.viaConfig

			for _, filter := range tt.filterConfigs {
				handler.RequestFilters = append(handler.RequestFilters, filter)
			}

			// Create a request to the backend through the proxy
			req := httptest.NewRequest("GET", backend.URL, nil)
			req.RemoteAddr = "127.0.0.1:1234"

			// Set headers
			for k, v := range tt.headersToSet {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			expectedStatus := http.StatusOK
			if tt.expectStatus != 0 {
				expectedStatus = tt.expectStatus
			}

			if w.Code != expectedStatus {
				t.Errorf("Proxy returned status %d, expected %d", w.Code, expectedStatus)
			}
		})
	}
}
