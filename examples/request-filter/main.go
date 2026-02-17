package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"os"

	"github.com/patiee/proxy/config"
	"github.com/patiee/proxy/errors"
	plog "github.com/patiee/proxy/log"
	proxy "github.com/patiee/proxy/proxy"
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
		return errors.NewBlockedRequestError(fmt.Sprintf("blocked domain: %s", r.Host))
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

	// Create Proxy Server
	log := plog.DefaultLogger()
	p, err := proxy.NewProxyServer(config, log)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Apply filters
	p.AddRequestFilter(xffFilter)
	p.AddRequestFilter(blockReddit)

	log.Printf("Starting proxy server on port :%s with X-Forwarded-For filter", config.Port)
	if err := http.ListenAndServe(":"+config.Port, p); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}
