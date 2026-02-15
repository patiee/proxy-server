# Proxy Library

A flexible HTTP/HTTPS proxy library for Go, supporting request filtering, upstream chaining, and configurable headers.

## Features

-   **HTTP & HTTPS Support**: Handles standard HTTP requests and HTTPS tunneling (via CONNECT).
-   **Configurable Headers**:
    -   **Via Header**: Optional `Via` header support (appends if exists).
-   **Request Filtering**:
    -   **Multiple Filters**: Chainable request filters using `ApplyFilter`.
    -   **Custom Logic**: Easily implement things like `X-Forwarded-For` or custom header manipulation.
-   **Proxy Chaining**:
    -   **Upstream Proxy**: Forward requests to another proxy (HTTP forwarding and HTTPS tunneling).
    -   **Validation**: Enforces valid `http://` or `https://` schemes for upstream URLs.
-   **Configuration**:
    -   Load from environment variables, `.env` files, or JSON.

## Installation

```bash
go get github.com/patiee/proxy
```

## Configuration

Configuration can be loaded from environment variables or a JSON file.

### Environment Variables

| Variable | Description | Required | Example |
|---|---|---|---|
| `PROXY_PORT` | Port to listen on | **Yes** | `8080` |
| `PROXY_VIA` | Value for `Via` header | No | `proxy-server-v1.0.0 [IP_ADDRESS]:[PORT]` |
| `PROXY_UPSTREAM_URL` | Upstream proxy URL (specific) | No | `http://localhost:9090` |
| `PROXY_UPSTREAM_TIMEOUT` | Upstream timeout in seconds | No | `10` |

### JSON Configuration

```json
{
  "port": "8080",
  "via": "proxy-server-v1.0.0 [IP_ADDRESS]:[PORT]",
  "upstream": {
    "url": "http://localhost:9090",
    "timeout": 10
  }
}
```

## Usage

### Basic Usage

```go
package main

import (
	"log"
	"net/http"

	"github.com/patiee/proxy/config"
	"github.com/patiee/proxy/server"
)

func main() {
	// Load config
	conf, err := config.LoadConfig() // or LoadConfigJson(bytes)
	if err != nil {
		log.Fatal(err)
	}

	// Create proxy server
	srv, err := server.NewProxyServer(conf.Port, conf.Via, conf.Upstream)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting proxy on :%s", conf.Port)
	if err := http.ListenAndServe(":"+conf.Port, srv); err != nil {
		log.Fatal(err)
	}
}
```

### Adding Filters (e.g., X-Forwarded-For)

`X-Forwarded-For` is **not** added by default. You can add it using a filter:

```go
// Define filter
func xffFilter(r *http.Request) {
    // ... implementation ...
    r.Header.Set("X-Forwarded-For", clientIP)
}

// Apply filter
srv.ApplyFilter(xffFilter)
```

See `examples/request-filter/main.go` for a complete example.

### Proxy Chaining

To chain to an upstream proxy, configure the `upstream` field. You can specify a URL string (defaults to 10s timeout) or an object:

```json
{
  "port": "8082",
  "upstream": {
    "url": "http://localhost:8081",
    "timeout": 15
  }
}
```

See `examples/proxychain/main.go` for a complete example.

## Examples

Check the `examples/` directory for ready-to-run examples:

-   `examples/request-filter`: Demonstrates adding `X-Forwarded-For`.
-   `examples/proxychain`: Demonstrates proxy chaining.
