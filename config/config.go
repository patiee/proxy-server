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
	Port     string
	Via      *string
	Upstream *UpstreamConfig
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
		Port:     port,
		Via:      via,
		Upstream: upstream,
	}, nil
}

type JsonConfig struct {
	Port     string              `json:"port"`
	Via      *string             `json:"via"`
	Upstream *JsonUpstreamConfig `json:"upstream"`
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
		Port: conf.Port,
		Via:  conf.Via,
	}

	if conf.Upstream != nil {
		config.Upstream = &UpstreamConfig{
			URL:     conf.Upstream.URL,
			Timeout: conf.Upstream.Timeout,
		}
	}
	return config, nil
}
