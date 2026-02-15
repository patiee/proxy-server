package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"os"

	"github.com/patiee/proxy/config"
	"github.com/patiee/proxy/server"
)

// xffFilter implements the X-Forwarded-For filter
func xffFilter(r *http.Request) error {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if prior, ok := r.Header["X-Forwarded-For"]; ok {
		clientIP = strings.Join(prior, ", ") + ", " + clientIP
	}
	r.Header.Set("X-Forwarded-For", clientIP)
	log.Printf("Applied X-Forwared-For: %s", clientIP)
	return nil
}

// blockReddit filter blocks blocking requests to reddit.com
func blockReddit(r *http.Request) error {
	if strings.Contains(r.Host, "reddit.com") {
		log.Printf("Blocking request to %s", r.Host)
		return fmt.Errorf("blocked domain: %s", r.Host)
	}
	return nil
}

func main() {
	// Load configuration from JSON file
	configData, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	config, err := config.LoadConfigJson(configData)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Create new proxy server
	proxy, err := server.NewProxyServer(config.Port, config.Via, config.Upstream, config.Timeout)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Apply filters
	proxy.AddFilter(xffFilter)
	proxy.AddFilter(blockReddit)

	log.Printf("Starting proxy server on port %s with X-Forwarded-For filter", config.Port)
	if err := http.ListenAndServe(":"+config.Port, proxy); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}
