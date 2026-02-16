package config_test

import (
	"testing"

	"github.com/patiee/proxy/config"
)

func TestLoadConfigJson(t *testing.T) {

	defaultViaConf := "1.1 8080"
	defaultUser := "user"
	defaultPass := "pass"
	defaultTimeout := 30

	tests := []struct {
		name             string
		input            string
		expectedPort     string
		expectedVia      *string
		expectedUser     *string
		expectedPassword *string
		expectedTimeout  *int
		shouldError      bool
	}{
		{
			name:         "Valid Config",
			input:        `{"port": "9090"}`,
			expectedPort: "9090",
			expectedVia:  nil,
			shouldError:  false,
		},
		{
			name:        "Missing Port",
			input:       `{}`,
			shouldError: true,
		},
		{
			name:         "Configured Via",
			input:        `{"port": "8081", "via": "1.1 8080"}`,
			expectedPort: "8081",
			expectedVia:  &defaultViaConf,
			shouldError:  false,
		},
		{
			name:             "Configured Socks5",
			input:            `{"port": "1080", "socks5": {"user": "user", "password": "pass", "timeout": 30}}`,
			expectedPort:     "1080",
			expectedUser:     &defaultUser,
			expectedPassword: &defaultPass,
			expectedTimeout:  &defaultTimeout,
			shouldError:      false,
		},
		{
			name:        "Invalid JSON",
			input:       `{invalid js`,
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.LoadConfigJson([]byte(tt.input))
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if cfg.Port != tt.expectedPort {
				t.Errorf("Expected port %s, got %s", tt.expectedPort, cfg.Port)
			}

			if (cfg.Via == nil && tt.expectedVia != nil) || (cfg.Via != nil && tt.expectedVia == nil) {
				t.Errorf("Expected Via %v, got %v", tt.expectedVia, cfg.Via)
			} else if cfg.Via != nil && tt.expectedVia != nil && *cfg.Via != *tt.expectedVia {
				t.Errorf("Expected Via %s, got %s", *tt.expectedVia, *cfg.Via)
			}

			if tt.expectedUser != nil {
				if cfg.Socks5 == nil {
					t.Errorf("Expected Socks5 config, got nil")
				} else {
					if cfg.Socks5.User == nil || *cfg.Socks5.User != *tt.expectedUser {
						t.Errorf("Expected Socks5 User %s, got %v", *tt.expectedUser, cfg.Socks5.User)
					}
					if cfg.Socks5.Password == nil || *cfg.Socks5.Password != *tt.expectedPassword {
						t.Errorf("Expected Socks5 Password %s, got %v", *tt.expectedPassword, cfg.Socks5.Password)
					}
					if tt.expectedTimeout != nil {
						if cfg.Socks5.Timeout == nil || *cfg.Socks5.Timeout != *tt.expectedTimeout {
							t.Errorf("Expected Socks5 Timeout %d, got %v", *tt.expectedTimeout, cfg.Socks5.Timeout)
						}
					}
				}
			}
		})
	}
}
