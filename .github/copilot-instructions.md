# Copilot Coding Agent Instructions — go-rate-limit

This repo is a small Go package that implements a token-bucket HTTP rate limiter (package `ratelimit`). Aim: keep edits minimal, run tests, and respect existing concurrency patterns.

Key files
- `rate_limiter.go` — core implementation (RateLimiter, Visitor, helpers, middleware)
- `rate_limiter_test.go` — unit tests (uses `testify/assert` and short sleeps for timing tests)
- `test.sh` — runs tests: `go test -cover -timeout 2s ./...`
- `lint.sh` — runs golangci-lint in Docker

Big picture
- Single package, no server: the library provides `RateLimitMiddleware(cfg)` for integration.
- Internal model: a map of visitor IP → *Visitor. Each Visitor has its own mutex; the visitors map is protected by a RWMutex. Cleanup runs in a background goroutine started by `NewRateLimiter` and is driven by a context.

Important behaviors & examples (copy/paste-ready)
- Default RPM when creating with `NewRateLimiter(ctx, rpm)`: 30 if rpm ≤ 0.
- Default MaxClientIpsPerMinute in middleware: 500 (see `RateLimitMiddleware`). When cap reached, new IPs are rejected by returning false from `Allow`.
- `RateLimitMiddleware` sets `Retry-After: 60` and calls `kit.SendTooManyRequests(rw, nil)` on rejection (dependency: `github.com/stfsy/go-api-kit`).
- `getClientIP` uses the left-most value in a trusted forwarded header (e.g., `X-Forwarded-For`) and falls back to `RemoteAddr`.

Concurrency & testing notes for agents
- Do not remove per-visitor mutexes or the RWMutex pattern — tests and behavior rely on them.
- `NewRateLimiter` spawns a background waiter (`cleanupVisitors`) that honors the provided context. In tests, prefer passing `context.Background()` or a cancellable context and cancel it when needed to stop goroutines.
- Tests rely on short timeouts: `test.sh` sets `-timeout 2s`. Avoid long sleeps in tests; follow the pattern from `TestRateLimiter_TokenRefresh` which constructs a limiter with a fast `rate` for quick refresh testing.

Developer workflows
- Build: `go build ./...`
- Test (quick): `./test.sh` (honors the 2s timeout)
- Lint: `./lint.sh` (dockerized golangci-lint)
- Go version: see `go.mod` (go 1.24.5). Use that or a compatible toolchain.

Patterns to follow when editing
- Keep public API surface minimal: functions/types exported only when needed by consumers.
- Preserve logging via `fmt.Printf` in places where the code currently logs; match existing message formats when changing behavior.
- When adding tests, use `testify/assert` as in existing tests and prefer deterministic, short sleeps or injected rates to avoid flaky timing.

Integration points & dependencies
- `github.com/stfsy/go-api-kit` — used for response helpers like `kit.SendTooManyRequests`.
- No external server or DB; the package is intended to be embedded in HTTP stacks.

Commit guidelines
- Use Conventional Commits for changes (e.g., `fix(ratelimit): prevent nil pointer in cleanup`).