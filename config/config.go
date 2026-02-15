package config

import (
	"encoding/json"
	"fmt"
	"os"

	"strconv"

	"github.com/joho/godotenv"
)

// UpstreamConfig holds the upstream proxy configuration.
type UpstreamConfig struct {
	URL     string
	Timeout *int // Timeout in seconds
}

// Config holds the proxy configuration.
type Config struct {
	Port               string
	Via                *string
	Upstream           *UpstreamConfig
	Timeout            *int // Global client timeout in seconds
	CaCertPath         *string
	CaKeyPath          *string
	InsecureSkipVerify *bool
}

// LoadConfig loads configuration from .env file or environment variables.
func LoadConfig() (*Config, error) {
	_ = godotenv.Load() // Load .env file if it exists

	port := os.Getenv("PROXY_PORT")
	if port == "" {
		return nil, fmt.Errorf("PROXY_PORT is not set")
	}

	var via *string
	if v, ok := os.LookupEnv("PROXY_VIA"); ok {
		via = &v
	}

	var timeout *int
	if v, ok := os.LookupEnv("PROXY_TIMEOUT"); ok {
		t, err := strconv.Atoi(v)
		if err == nil {
			timeout = &t
		}
	}

	var caCertPath *string
	if v, ok := os.LookupEnv("PROXY_CA_CERT"); ok {
		caCertPath = &v
	}
	var caKeyPath *string
	if v, ok := os.LookupEnv("PROXY_CA_KEY"); ok {
		caKeyPath = &v
	}

	var insecureSkipVerify *bool
	if v, ok := os.LookupEnv("PROXY_INSECURE_SKIP_VERIFY"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			insecureSkipVerify = &b
		}
	}

	var upstream *UpstreamConfig
	if v, ok := os.LookupEnv("PROXY_UPSTREAM_URL"); ok {
		if upstream == nil {
			defaultTimeout := 10
			upstream = &UpstreamConfig{Timeout: &defaultTimeout}
		}
		upstream.URL = v

		if v, ok := os.LookupEnv("PROXY_UPSTREAM_TIMEOUT"); ok {
			t, err := strconv.Atoi(v)
			if err == nil {
				upstream.Timeout = &t
			}
		}
	}

	if upstream != nil && upstream.URL == "" {
		upstream = nil
	}

	return &Config{
		Port:               port,
		Via:                via,
		Upstream:           upstream,
		Timeout:            timeout,
		CaCertPath:         caCertPath,
		CaKeyPath:          caKeyPath,
		InsecureSkipVerify: insecureSkipVerify,
	}, nil
}

type JsonConfig struct {
	Port               string              `json:"port"`
	Via                *string             `json:"via"`
	Upstream           *JsonUpstreamConfig `json:"upstream"`
	Timeout            *int                `json:"timeout"`
	CaCertPath         *string             `json:"ca_cert_path"`
	CaKeyPath          *string             `json:"ca_key_path"`
	InsecureSkipVerify *bool               `json:"insecure_skip_verify"`
}

type JsonUpstreamConfig struct {
	URL     string `json:"url"`
	Timeout *int   `json:"timeout"`
}

// LoadConfigJson loads configuration from JSON bytes.
func LoadConfigJson(data []byte) (*Config, error) {
	var conf JsonConfig
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, err
	}

	if conf.Port == "" {
		return nil, fmt.Errorf("port is not set")
	}

	config := &Config{
		Port:               conf.Port,
		Via:                conf.Via,
		Timeout:            conf.Timeout,
		CaCertPath:         conf.CaCertPath,
		CaKeyPath:          conf.CaKeyPath,
		InsecureSkipVerify: conf.InsecureSkipVerify,
	}

	if conf.Upstream != nil {
		config.Upstream = &UpstreamConfig{
			URL:     conf.Upstream.URL,
			Timeout: conf.Upstream.Timeout,
		}
	}
	return config, nil
}
