package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"strconv"

	"github.com/joho/godotenv"
)

// UpstreamConfig holds the upstream proxy configuration.
type UpstreamConfig struct {
	URL     *url.URL
	Timeout time.Duration
}

// Config holds the proxy configuration.
// Socks5Config holds the SOCKS5 server configuration.
type Socks5Config struct {
	User     *string `json:"user"`
	Password *string `json:"password"`
	Timeout  *int    `json:"timeout"`
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
	Socks5             *Socks5Config
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
		if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "socks5://") {
			return nil, fmt.Errorf("upstream proxy must start with http://, https://, or socks5://")
		}
		u, err := url.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL: %v", err)
		}

		upstreamTimeout := 10 * time.Second // Default
		if v, ok := os.LookupEnv("PROXY_UPSTREAM_TIMEOUT"); ok {
			t, err := strconv.Atoi(v)
			if err == nil && t > 0 {
				upstreamTimeout = time.Duration(t) * time.Second
			}
		}

		upstream = &UpstreamConfig{
			URL:     u,
			Timeout: upstreamTimeout,
		}
	}

	var socks5 *Socks5Config
	socks5User := os.Getenv("PROXY_SOCKS5_USER")
	socks5Password := os.Getenv("PROXY_SOCKS5_PASSWORD")
	socks5TimeoutRaw := os.Getenv("PROXY_SOCKS5_TIMEOUT")

	if socks5User != "" || socks5Password != "" || socks5TimeoutRaw != "" {
		socks5 = &Socks5Config{}
		if socks5User != "" {
			socks5.User = &socks5User
		}
		if socks5Password != "" {
			socks5.Password = &socks5Password
		}
		if socks5TimeoutRaw != "" {
			if t, err := strconv.Atoi(socks5TimeoutRaw); err == nil {
				socks5.Timeout = &t
			}
		}
	}

	return &Config{
		Port:               port,
		Via:                via,
		Upstream:           upstream,
		Timeout:            timeout,
		CaCertPath:         caCertPath,
		CaKeyPath:          caKeyPath,
		InsecureSkipVerify: insecureSkipVerify,
		Socks5:             socks5,
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
	Socks5             *Socks5Config       `json:"socks5"`
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
		Socks5:             conf.Socks5,
	}

	if conf.Upstream != nil {
		if !strings.HasPrefix(conf.Upstream.URL, "http://") && !strings.HasPrefix(conf.Upstream.URL, "https://") && !strings.HasPrefix(conf.Upstream.URL, "socks5://") {
			return nil, fmt.Errorf("upstream proxy must start with http://, https://, or socks5://")
		}
		u, err := url.Parse(conf.Upstream.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL: %v", err)
		}

		upstreamTimeout := 10 * time.Second
		if conf.Upstream.Timeout != nil && *conf.Upstream.Timeout > 0 {
			upstreamTimeout = time.Duration(*conf.Upstream.Timeout) * time.Second
		}

		config.Upstream = &UpstreamConfig{
			URL:     u,
			Timeout: upstreamTimeout,
		}
	}
	return config, nil
}
