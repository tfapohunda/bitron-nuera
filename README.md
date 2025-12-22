# Bitron Nuera

A simple API Proxy service that forwards HTTP requests from clients to an upstream API, handling authentication translation and basic observability.

## Build

```bash
cargo build --release
```

## Run Unit Tests

```bash
cargo test
```

## Configuration

Create a `config.toml` file similar to the one shown below. A sample config file is located at the root of the project.

```toml
[server]
address = "0.0.0.0:3000"

[upstream]
url = "http://127.0.0.1:3001"

[auth]
tokens = [
    { client = "token1", upstream = "upstream_token_1" },
    { client = "token2", upstream = "upstream_token_2" },
]
```

| Section | Field | Description |
|---------|-------|-------------|
| `server` | `address` | Address and port the proxy listens on |
| `upstream` | `url` | Target service URL to forward requests to |
| `auth` | `tokens` | Token mappings from client tokens to upstream tokens |

## Run

```bash
# Default config path (config.toml)
cargo run --release

# Custom config path
cargo run --release -- --config-path /path/to/config.toml
```

## Usage

Send requests with a Bearer token that matches a `client` token in your config:

```bash
curl -H "Authorization: Bearer token1" http://localhost:3000/api/endpoint
```

The proxy will:

1. Validate the client token against configured mappings
2. Replace it with the corresponding upstream token
3. Forward the request to the upstream service
4. Return the response with an `x-request-id` header for tracing
