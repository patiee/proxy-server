# Proxy Server

A flexible HTTP/HTTPS and SOCKS5 proxy server for Go, supporting request filtering, upstream chaining, and configurable headers.

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
-   **SOCKS5 Support**:
    -   **Upstream**: Connect to `socks5://` upstream proxies.
    -   **Server**: Act as a SOCKS5 server using `ServeSOCKS5`. Supports transparent HTTP/HTTPS filtering over SOCKS5.
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
	"github.com/patiee/proxy/proxy"
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

### SOCKS5 Support

#### Upstream SOCKS5 Proxy chaining

To usage an upstream SOCKS5 proxy, set the `upstream` URL scheme to `socks5://`. You can also configure authentication and timeouts.

**JSON Configuration:**

```json
{
  "port": "8080",
  "upstream": {
    "url": "socks5://internal-proxy:1080",
    "timeout": 10
  },
  "socks5": {
    "user": "myuser",
    "password": "mypassword",
    "timeout": 30
  }
}
```

**Environment Variables:**

-   `PROXY_UPSTREAM_URL`: `socks5://internal-proxy:1080`
-   `PROXY_SOCKS5_USER`: SOCKS5 username
-   `PROXY_SOCKS5_PASSWORD`: SOCKS5 password
-   `PROXY_SOCKS5_TIMEOUT`: SOCKS5 connection/handshake timeout in seconds (default: 10s)

#### SOCKS5 Server

The proxy can also act as a SOCKS5 server, accepting SOCKS5 connections from clients and forwarding them (potentially via another upstream proxy).

**Configuration:**

Simply configure the SOCKS5 credentials in the `socks5` section (or via env vars). If configured, the server will accept SOCKS5 connections on the main `port`.

**Note:** The server auto-detects the protocol (HTTP/HTTPS/SOCKS5) on the same port.

```json
{
  "port": "1080",
  "socks5": {
    "user": "server-user",
    "password": "server-password",
    "timeout": 30
  }
}
```

-   `timeout`: Takes effect for the initial SOCKS5 handshake deadline.

## Examples

Check the `examples/` directory for ready-to-run examples:

-   `examples/request-filter`: Demonstrates adding `X-Forwarded-For`.
-   `examples/proxychain`: Demonstrates proxy chaining (HTTP/HTTPS).
-   `examples/socks5`: Demonstrates SOCKS5 server usage.
