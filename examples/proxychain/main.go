package main

import (
	"log"
	"net/http"
	"os"

	"github.com/patiee/proxy/config"
	proxy "github.com/patiee/proxy/proxy"
)

func main() {
	// Load configuration from JSON file
	configData, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	conf, err := config.LoadConfigJson(configData)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	if conf.Upstream == nil {
		log.Println("WARNING: No upstream proxy configured.")
		log.Println("To test chaining, set PROXY_UPSTREAM_URL environment variable (e.g. export PROXY_UPSTREAM_URL=localhost:9090)")
	} else {
		log.Printf("Chaining via upstream proxy: %v", *conf.Upstream)
	}

	// Create new proxy server with upstream configuration
	// Create Proxy Server
	// The implementation now uses ProxyServer from server/http
	p, err := proxy.NewProxyServer(conf) // Changed from server.NewProxyServer to proxy.NewProxyServer and variable name from proxy to p
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	log.Printf("Starting proxy server on port %s, forwarding to %v", conf.Port, conf.Upstream)
	if err := http.ListenAndServe(":"+conf.Port, p); err != nil { // Changed proxy to p
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}
