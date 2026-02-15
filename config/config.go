package config

import (
	"encoding/json"
	"os"

	"github.com/joho/godotenv"
)

// Config holds the proxy configuration.
type Config struct {
	Port string
	Via  *string
}

// LoadConfig loads configuration from .env file or environment variables.
func LoadConfig() (*Config, error) {
	_ = godotenv.Load() // Load .env file if it exists

	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = "8080"
	}

	var via *string
	if v, ok := os.LookupEnv("PROXY_VIA"); ok {
		via = &v
	}

	return &Config{
		Port: port,
		Via:  via,
	}, nil
}

type JsonConfig struct {
	Port string  `json:"port"`
	Via  *string `json:"via"`
}

// LoadConfigJson loads configuration from JSON bytes.
func LoadConfigJson(data []byte) (*Config, error) {
	var conf JsonConfig
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, err
	}

	if conf.Port == "" {
		conf.Port = "8080"
	}

	return &Config{
		Port: conf.Port,
		Via:  conf.Via,
	}, nil
}
