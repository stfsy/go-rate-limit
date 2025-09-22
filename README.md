# go-rate-limit

A small, dependency-light Go package providing a token-bucket HTTP rate limiter and a few small header-related middlewares.

This library is intended to be embedded into HTTP servers as middleware. It offers:

- A per-client token-bucket `RateLimiter` keyed by client IP.
- `RateLimitMiddleware(cfg)` which wires the limiter into an HTTP stack and returns a middleware handler.
- Small header-safety middlewares: `MaxHeaderLengthMiddleware` and `ControlCharHeaderMiddleware`.

This README focuses on developer usage, configuration, testing and security considerations.

## Installation

Use the module path shown in `go.mod`:

	go get github.com/stfsy/go-rate-limit

## Quick usage

The simplest integration is to create a middleware with reasonable defaults and use it in your HTTP stack:

```go
package main

import (
	"context"
	"net/http"

	"github.com/stfsy/go-rate-limit"
)

func main() {
	mw, err := ratelimit.RateLimitMiddleware(ratelimit.RateLimiterConfig{
		RequestsPerMinute: 100, // allowed per client
		Context:           context.Background(),
		TrustedProxyHeader: "X-Forwarded-For", // only set if behind a trusted proxy
	})
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	// adapt to your server framework; this middleware expects the signature
	// func(http.ResponseWriter, *http.Request, http.HandlerFunc)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mw(w, r, func(w http.ResponseWriter, r *http.Request) {
			mux.ServeHTTP(w, r)
		})
	})

	http.ListenAndServe(":8080", handler)
}
```

### Notes about TrustedProxyHeader

- The `TrustedProxyHeader` value (for example `X-Forwarded-For`) tells the middleware to prefer that header when extracting the client IP. **Only set this when your application is behind a trusted reverse proxy that you control.**
- If untrusted clients can set that header, they may spoof IPs and bypass rate limits. A more secure approach is to configure `TrustedProxies` (CIDR list) and validate the immediate peer (not currently exposed by the public API) before trusting forwarded headers.

## Configuration

RateLimiterConfig fields of interest:

- `RequestsPerMinute int` — tokens per minute. Values <= 0 default to 30. Extremely large values are clamped to a sane upper bound.
- `Context context.Context` — used to control background cleanup goroutine lifecycle. Passing `context.Background()` is acceptable; prefer a cancellable context if you want to stop cleanup.
- `TrustedProxyHeader string` — name of a forwarding header to trust when present (e.g. `X-Forwarded-For`). Only set if behind a trusted proxy.
- `MaxClientIpsPerMinute int` — caps tracked unique IPs (default 500). When cap is reached new IPs are rejected until entries expire.
- `CleanupInterval`, `VisitorStaleDuration`, `CleanupBatchSize` — tuning for the background cleanup worker.

## Middlewares

- `MaxHeaderLengthMiddleware(headerName string, maxLen int)` — rejects requests where the named header's value exceeds `maxLen` bytes.
- `ControlCharHeaderMiddleware(headerName string)` — rejects requests whose named header contains ASCII control characters (helps prevent header injection/log forging).

Combine these with rate limit middleware to protect parsing of forwarded headers and avoid denial-of-service via oversized headers.

## Testing and fuzzing

- Unit tests are provided (`*_test.go`) and can be run with:

	go test ./...

- The repo contains fuzz targets (e.g. `FuzzGetClientIP`) that use Go's native fuzzing. To run a short fuzz session:

	go test -fuzz=FuzzGetClientIP -fuzztime=30s

- Recommendation: run fuzzing without `-race` for long campaigns, then re-run interesting/minimized failures with `go test -race` to detect data races.

## Security considerations

- Do not trust forwarded headers unless your server sits behind a trusted proxy. Consider adding an option to configure trusted proxy CIDRs.
- The rate limiter uses per-visitor mutexes and an RWMutex for the visitors map. Avoid removing those synchronization primitives — tests and concurrency rely on them.
- The middleware rejects requests when the limiter cannot determine a client IP. This avoids collapsing multiple clients into a single empty-key bucket.

## Contributing

1. Fork the repository and create a branch.
2. Run tests and linters locally. The repo includes `test.sh` and `lint.sh` wrappers.
3. Make a small, focused change with corresponding tests.
4. Open a PR with a clear description.

## Development tips

- When fuzzing, seed inputs matter. The repo includes some seed cases for `FuzzGetClientIP` that exercise IPv4, IPv6 and forwarded header forms.
- If you change public behavior (API surface) add tests and update README. Keep public APIs minimal.

## License

MIT
