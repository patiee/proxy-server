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

	server := server.NewProxyServer(config.Port, config.Via)
	log.Printf("Starting proxy server on port %s", config.Port)
	if err := http.ListenAndServe(":"+config.Port, server); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}
