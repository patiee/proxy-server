# Proxy Library

A flexible HTTP/HTTPS proxy library for Go, supporting multiple privacy levels. This library allows you to easily embed a proxy server into your application with configurable anonymity settings.

## Features

-   **HTTP & HTTPS Support**: Handles standard HTTP requests and HTTPS tunneling (via CONNECT).
-   **Privacy Levels**:
    -   **Transparent**: Forwards client IP in `X-Forwarded-For`.
    -   **Anonymous**: Hides client IP, identifies as a proxy via `Via` header.
    -   **Elite**: Hides client IP and does not identify as a proxy.
-   **Configurable**: Load configuration from environment variables, `.env` files, or JSON data.

## Installation

```bash
go get github.com/patiee/proxy
```

## Usage

### Basic Usage

```go
package main

import (
	"log"
	"net/http"

	"github.com/patiee/proxy/server"
)

func main() {
	// Create a proxy server with desired privacy level
	// Options: server.Transparent, server.Anonymous, server.Elite
	srv := server.NewProxyServer(server.Elite, "8080")

	log.Println("Starting proxy on :8080")
	if err := http.ListenAndServe(":8080", srv); err != nil {
		log.Fatal(err)
	}
}
```

### Loading Configuration

You can use the `config` package to load settings from environment variables or JSON.

**From Environment (.env):**
```go
import "github.com/patiee/proxy/config"

cfg, err := config.LoadConfig()
if err != nil {
    // handle error
}
srv := server.NewProxyServer(cfg.PrivacyLevel, cfg.Port)
```

**From JSON:**
```go
import "github.com/patiee/proxy/config"

jsonData := []byte(`{"port": "9090", "privacy_level": "anonymous"}`)
cfg, err := config.LoadConfigJson(jsonData)
if err != nil {
    // handle error
}
srv := server.NewProxyServer(cfg.PrivacyLevel, cfg.Port)
```

## Build, Run, and Test

### Prerequisites
-   Go 1.23.4 or higher

### Build
To build the example server:
```bash
go build -o proxy-server cmd/main.go
```

### Run
Run the example server (ensure you have built it or use `go run`):
```bash
# Using go run
go run cmd/main.go

# Using built binary with custom settings
PROXY_PORT=8081 PRIVACY_LEVEL=elite ./proxy-server
```

### Test
Run unit tests:
```bash
go test ./...
```
To force using the local Go version if you have version mismatches:
```bash
GOTOOLCHAIN=local go test ./...
```
