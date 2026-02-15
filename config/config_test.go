package config_test

import (
	"testing"

	"github.com/patiee/proxy/config"
)

func TestLoadConfigJson(t *testing.T) {
	defaultViaConf := "1.1 8080"
	tests := []struct {
		name         string
		input        string
		expectedPort string
		expectedVia  *string
		shouldError  bool
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
		})
	}
}
