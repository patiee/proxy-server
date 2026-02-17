package main

import (
	"log"
	"net"
	"net/http"
	"os"

	"github.com/patiee/proxy/config"
	"github.com/patiee/proxy/errors"
	plog "github.com/patiee/proxy/log"
	proxy "github.com/patiee/proxy/proxy"
)

func main() {
	// Load configuration
	configBytes, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	conf, err := config.LoadConfigJson(configBytes)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create Proxy Server
	log := plog.DefaultLogger()
	p, err := proxy.NewProxyServer(conf, log)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Add a simple request filter
	p.AddRequestFilter(func(r *http.Request) error {
		log.Printf("Intercepted request to: %s", r.URL.String())
		r.Header.Set("X-Proxy-Intercepted", "true")
		return nil
	})

	// Add a blocking filter example
	p.AddRequestFilter(func(r *http.Request) error {
		if r.Host == "example.com" {
			log.Println("Blocking request to example.com")
			return &errors.BlockedRequestError{Message: "Access to example.com is blocked by SOCKS5 proxy"}
		}
		return nil
	})

	listener, err := net.Listen("tcp", ":"+conf.Port)
	if err != nil {
		log.Fatalf("Failed to listen on port :%s: %v", conf.Port, err)
	}

	log.Printf("SOCKS5 Proxy Server running on port :%s\n", conf.Port)
	if err := p.ServeSOCKS5(listener); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
