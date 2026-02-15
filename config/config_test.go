package config_test

import (
	"testing"

	"github.com/patiee/proxy/config"
	"github.com/patiee/proxy/server"
)

func TestLoadConfigJson(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedPort string
		expectedPL   server.PrivacyLevel
		shouldError  bool
	}{
		{
			name:         "Valid Transparent",
			input:        `{"port": "9090", "privacy_level": "transparent"}`,
			expectedPort: "9090",
			expectedPL:   server.Transparent,
			shouldError:  false,
		},
		{
			name:         "Valid Anonymous",
			input:        `{"port": "8081", "privacy_level": "anonymous"}`,
			expectedPort: "8081",
			expectedPL:   server.Anonymous,
			shouldError:  false,
		},
		{
			name:         "Valid Elite",
			input:        `{"port": "8082", "privacy_level": "elite"}`,
			expectedPort: "8082",
			expectedPL:   server.Elite,
			shouldError:  false,
		},
		{
			name:         "Default Port and Privacy",
			input:        `{}`,
			expectedPort: "8080",
			expectedPL:   server.Transparent,
			shouldError:  false,
		},
		{
			name:         "Invalid JSON",
			input:        `{invalid js`,
			expectedPort: "",
			expectedPL:   server.Transparent,
			shouldError:  true,
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

			if cfg.PrivacyLevel != tt.expectedPL {
				t.Errorf("Expected privacy level %d, got %d", tt.expectedPL, cfg.PrivacyLevel)
			}
		})
	}
}
