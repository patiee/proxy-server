package config

import (
	"encoding/json"
	"os"

	"github.com/joho/godotenv"
	"github.com/patiee/proxy/server"
)

// Config holds the proxy configuration.
type Config struct {
	Port         string
	PrivacyLevel server.PrivacyLevel
}

// LoadConfig loads configuration from .env file or environment variables.
func LoadConfig() (*Config, error) {
	_ = godotenv.Load() // Load .env file if it exists

	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = "8080"
	}

	privacyLevelStr := os.Getenv("PRIVACY_LEVEL")
	var privacyLevel server.PrivacyLevel
	switch privacyLevelStr {
	case "transparent":
		privacyLevel = server.Transparent
	case "anonymous":
		privacyLevel = server.Anonymous
	case "elite":
		privacyLevel = server.Elite
	default:
		privacyLevel = server.Transparent // Default to Transparent
	}

	return &Config{
		Port:         port,
		PrivacyLevel: privacyLevel,
	}, nil
}

type JsonConfig struct {
	Port         string `json:"port"`
	PrivacyLevel string `json:"privacy_level"`
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

	var privacyLevel server.PrivacyLevel
	switch conf.PrivacyLevel {
	case "transparent":
		privacyLevel = server.Transparent
	case "anonymous":
		privacyLevel = server.Anonymous
	case "elite":
		privacyLevel = server.Elite
	default:
		privacyLevel = server.Transparent
	}

	return &Config{
		Port:         conf.Port,
		PrivacyLevel: privacyLevel,
	}, nil
}
