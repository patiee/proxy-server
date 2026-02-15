package main

import (
	"log"
	"net/http"

	"github.com/patiee/proxy/config"
	"github.com/patiee/proxy/server"
)

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	server := server.NewProxyServer(config.PrivacyLevel, config.Port)

	log.Printf("Starting proxy server on port %s with privacy level %d", config.Port, config.PrivacyLevel)
	if err := http.ListenAndServe(":"+config.Port, server); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}
