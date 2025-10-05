package ratelimit

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	kit "github.com/stfsy/go-api-kit/server/handlers"
)

// RateLimiter represents a simple token bucket rate limiter
type RateLimiter struct {
	visitors   map[string]*Visitor
	mu         sync.RWMutex
	rate       time.Duration
	capacity   int
	ctx        context.Context
	maxClients int
	// cleanup configuration
	cleanupInterval   time.Duration
	visitorStaleAfter time.Duration
	cleanupBatchSize  int
	cleanupOnce       sync.Once
	cleanupCursor     int
}

// RateLimiterConfig holds configuration options for the rate limit middleware.
// New options can be added here (trusted proxies, max visitors, etc.).
type RateLimiterConfig struct {
	RequestsPerMinute int
	Context           context.Context
	// TrustedProxyHeader is the name of the header (e.g. "X-Forwarded-For")
	// that should be trusted when extracting the client IP. If empty,
	// forwarded headers will be ignored and RemoteAddr will be used.
	TrustedProxyHeader string
	// MaxClientIpsPerMinute caps the number of unique client IPs tracked by the
	// rate limiter. When the number of tracked IPs reaches this value,
	// new IPs will be rejected until entries expire or are removed.
	// A value of 0 means no cap.
	MaxClientIpsPerMinute int
	// CleanupInterval controls how often the background cleanup runs.
	// If zero, a sensible default (5m) is used.
	CleanupInterval time.Duration
	// VisitorStaleDuration controls how long a visitor can be idle before it
	// is considered stale and eligible for removal. If zero, default is 10m.
	VisitorStaleDuration time.Duration
	// CleanupBatchSize limits the number of visitor entries inspected per cleanup
	// tick to spread work across ticks. If zero, a sensible default is used.
	CleanupBatchSize int
}

// Visitor represents a client's rate limiting state
type Visitor struct {
	tokens    int
	lastToken time.Time
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(ctx context.Context, requestsPerMinute int) (*RateLimiter, error) {
	// Default and validation: ensure requestsPerMinute is within a sane range to
	// avoid creating a zero `rate` (which would cause a divide-by-zero panic
	// in Allow). We default to 30 RPM when a non-positive value is supplied,
	// and clamp excessively large values to a conservative upper bound.
	const defaultRPM = 30
	const maxRPM = 1000000 // 1 million requests per minute is a practical cap

	if requestsPerMinute <= 0 {
		requestsPerMinute = defaultRPM
	}
	if requestsPerMinute > maxRPM {
		fmt.Printf("requestsPerMinute (%d) too large; clamping to %d\n", requestsPerMinute, maxRPM)
		requestsPerMinute = maxRPM
	}

	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}

	rl := &RateLimiter{}
	rl.ctx = ctx
	rl.visitors = make(map[string]*Visitor)
	rl.rate = time.Minute / time.Duration(requestsPerMinute)
	// Defensive: ensure rl.rate is never zero. This should not happen because
	// requestsPerMinute has been clamped, but keep a final guard.
	if rl.rate <= 0 {
		rl.rate = time.Nanosecond
	}
	rl.capacity = requestsPerMinute

	// initialize cleanup defaults; actual goroutine is started via StartCleanup
	rl.cleanupInterval = 5 * time.Minute
	rl.visitorStaleAfter = 10 * time.Minute
	rl.cleanupBatchSize = 100 // default inspect 100 entries per tick

	return rl, nil
}

// Allow checks if a request from the given IP is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	// Defensive: empty IPs must not be used as a map key because that would
	// collapse many unrelated requests into a single visitor entry. Treat an
	// empty or all-whitespace ip as not allowed.
	if strings.TrimSpace(ip) == "" {
		fmt.Printf("RateLimiter.Allow called with empty client IP; rejecting\n")
		return false
	}
	// Fast path: read-lock to locate visitor without blocking other readers
	rl.mu.RLock()
	visitor, exists := rl.visitors[ip]
	rl.mu.RUnlock()

	if !exists {
		// Need to create a visitor; upgrade to write lock. Double-check after locking.
		rl.mu.Lock()
		visitor, exists = rl.visitors[ip]
		if !exists {
			// Enforce maxClients cap if configured
			if rl.maxClients > 0 && len(rl.visitors) >= rl.maxClients {
				fmt.Printf("Rate limiter max clients reached (%d); rejecting new IP: %s\n", rl.maxClients, ip)
				rl.mu.Unlock()
				// We reject creating a new visitor when the cap is reached
				return false
			}

			visitor = &Visitor{
				tokens:    rl.capacity - 1, // Use one token immediately
				lastToken: time.Now(),
			}
			rl.visitors[ip] = visitor
			rl.mu.Unlock()
			return true
		}
		rl.mu.Unlock()
	}

	visitor.mu.Lock()
	defer visitor.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(visitor.lastToken)

	// Use int64 to avoid intermediate overflows for large elapsed durations.
	tokensToAdd64 := int64(0)
	if rl.rate > 0 {
		tokensToAdd64 = int64(elapsed / rl.rate)
	}

	if tokensToAdd64 > 0 {
		// Defensive cap: never add more tokens than the configured capacity in
		// a single refill step. This prevents extremely large elapsed times
		// from making huge jumps and advancing lastToken by an unbounded amount.
		if tokensToAdd64 > int64(rl.capacity) {
			tokensToAdd64 = int64(rl.capacity)
		}

		tokensToAdd := int(tokensToAdd64)
		visitor.tokens += tokensToAdd
		if visitor.tokens > rl.capacity {
			visitor.tokens = rl.capacity
		}
		// Advance lastToken by the amount of time corresponding to the tokens
		// we actually added. This preserves the fractional remainder of the
		// elapsed interval so refill accounting stays accurate.
		visitor.lastToken = visitor.lastToken.Add(time.Duration(tokensToAdd64) * rl.rate)
	}

	if visitor.tokens > 0 {
		visitor.tokens--
		return true
	}

	return false
}

// cleanupVisitors removes old visitor entries to prevent memory leaks
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-rl.visitorStaleAfter)

			// Collect keys once to allow batched inspection without holding write lock.
			rl.mu.RLock()
			total := len(rl.visitors)
			if total == 0 {
				rl.mu.RUnlock()
				continue
			}
			ips := make([]string, 0, total)
			for ip := range rl.visitors {
				ips = append(ips, ip)
			}
			rl.mu.RUnlock()

			// Walk a batch of entries each tick starting from a cursor to spread work.
			start := rl.cleanupCursor % len(ips)
			end := start + rl.cleanupBatchSize
			if end > len(ips) {
				end = len(ips)
			}
			batch := ips[start:end]
			rl.cleanupCursor = end % len(ips)

			for _, ip := range batch {
				rl.mu.RLock()
				v := rl.visitors[ip]
				rl.mu.RUnlock()
				if v == nil {
					continue
				}
				v.mu.Lock()
				stale := v.lastToken.Before(cutoff)
				v.mu.Unlock()
				if stale {
					rl.mu.Lock()
					// double-check under write lock then delete
					if vv, ok := rl.visitors[ip]; ok {
						vv.mu.Lock()
						if vv.lastToken.Before(cutoff) {
							delete(rl.visitors, ip)
						}
						vv.mu.Unlock()
					}
					rl.mu.Unlock()
				}
			}
		}
	}
}

// StartCleanup starts the cleanup goroutine once. It's safe to call multiple
// times; the background worker will only be started once.
func (rl *RateLimiter) StartCleanup() {
	rl.cleanupOnce.Do(func() {
		go rl.cleanupVisitors()
	})
}

// getClientIP extracts the client IP address from the request.
// If trustedHeader is non-empty we will attempt to extract and validate
// the left-most entry from that header (commonly X-Forwarded-For).
func (rl *RateLimiter) getClientIP(r *http.Request, trustedHeader string) string {
	// If a trusted header was provided, try using its first IP
	if trustedHeader != "" {
		if hv := r.Header.Get(trustedHeader); hv != "" {
			// X-Forwarded-For can contain multiple comma-separated IPs.
			// Pick the left-most (originating client) and validate it.
			for _, part := range splitAndTrim(hv, ',') {
				ip := stripPort(part)
				if parsed := parseIP(ip); parsed != "" {
					return parsed
				}
			}
		}
		// trusted header was specified but missing or no valid IP found -
		// do not fall back to RemoteAddr when a trusted header was explicitly
		// configured: treat this as untrusted and return empty so callers
		// (middleware) can reject the request.
		return ""
	}

	// As a last resort, use RemoteAddr (strip port if present). Validate and
	// normalize the host portion — return a parsed IP string or empty if the
	// RemoteAddr does not contain a valid IP. This prevents returning raw
	// malformed tokens to callers.
	host := trimSpace(stripPort(r.RemoteAddr))
	if parsed := parseIP(host); parsed != "" {
		// Defensive validation: parsed result should not contain spaces,
		// commas or ASCII control characters. If it does, consider it
		// untrusted and return empty so callers enforce policy.
		if strings.ContainsAny(parsed, " \n\r\t") || strings.Contains(parsed, ",") {
			return ""
		}
		return parsed
	}
	return ""
}

// splitAndTrim splits s by sep and trims spaces from each part.
// splitAndTrim does a byte-oriented split on sep and trims ASCII whitespace
// from each part. It aims to minimize allocations by operating on a []byte
// view of the input and using bytes.TrimSpace on subslices.
func splitAndTrim(s string, sep rune) []string {
	// Fast-path for common ASCII separators (like ',') using byte-oriented scan.
	if sep <= 0xFF {
		sepB := byte(sep)
		b := []byte(s)
		// estimate capacity using occurrences of sep
		est := strings.Count(s, string(sepB)) + 1
		out := make([]string, 0, est)
		start := 0
		for i := 0; i < len(b); i++ {
			if b[i] == sepB {
				part := bytes.TrimSpace(b[start:i])
				if len(part) > 0 {
					out = append(out, string(part))
				}
				start = i + 1
			}
		}
		if start <= len(b)-1 {
			part := bytes.TrimSpace(b[start:])
			if len(part) > 0 {
				out = append(out, string(part))
			}
		}
		return out
	}

	// Fallback for non-ASCII separators: use rune-aware splitting.
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == sep })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p2 := strings.TrimSpace(p); p2 != "" {
			out = append(out, p2)
		}
	}
	return out
}

// trimSpace delegates to the stdlib implementation; keep as a small wrapper
// so existing tests and callers can remain unchanged.
func trimSpace(s string) string {
	return strings.TrimSpace(s)
}

// stripPort removes a trailing :port if present (handles IPv6 brackets too)
func stripPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

// parseIP returns the string if it's a valid IP, else empty string.
// Uses the allocation-friendly net/netip API where available.
func parseIP(s string) string {
	if s == "" {
		return ""
	}
	// Trim surrounding whitespace first.
	s = strings.TrimSpace(s)

	// Reject inputs containing ASCII control characters or spaces early.
	if strings.ContainsAny(s, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\v\f\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f ") {
		return ""
	}

	// Accept bracketed IPv6 forms ("[::1]") by unwrapping brackets before
	// attempting to parse. netip.ParseAddr does not accept bracketed forms.
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}

	// Strip any zone identifier after '%' (e.g. "fe80::1%eth0"). We only
	// keep the address portion for parsing. If the zone contains unusual
	// characters (including spaces) it will have been rejected above.
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}

	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.String()
	}
	return ""
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(cfg RateLimiterConfig) (func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc), error) {
	if cfg.MaxClientIpsPerMinute <= 0 {
		// Estimated concurrent active users = (N × f) × D where D is average session duration in minutes.
		// S = 1.2 (some sharing), M = 1.1 (some mobile churn) → f ≈ 1.09
		// Active users ≈ 10,900 users/minute
		// D = 5 min → concurrent ≈ 54,500
		//
		// We set an even more conservative default cap to limit memory usage.
		cfg.MaxClientIpsPerMinute = 500
	}

	limiter, err := NewRateLimiter(cfg.Context, cfg.RequestsPerMinute)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter: %w", err)
	}
	limiter.maxClients = cfg.MaxClientIpsPerMinute
	// apply optional cleanup overrides
	if cfg.CleanupInterval > 0 {
		limiter.cleanupInterval = cfg.CleanupInterval
	}
	if cfg.VisitorStaleDuration > 0 {
		limiter.visitorStaleAfter = cfg.VisitorStaleDuration
	}
	if cfg.CleanupBatchSize > 0 {
		limiter.cleanupBatchSize = cfg.CleanupBatchSize
	}

	limiter.StartCleanup()

	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		clientIP := limiter.getClientIP(r, cfg.TrustedProxyHeader)

		// If clientIP is empty then we cannot reliably rate-limit the request.
		// Reject the request rather than treating it as a shared/empty key.
		if strings.TrimSpace(clientIP) == "" {
			fmt.Printf("RateLimitMiddleware: could not determine client IP; rejecting request (RemoteAddr=%q, header=%q)\n", r.RemoteAddr, cfg.TrustedProxyHeader)
			kit.SendBadRequest(rw, nil)
			return
		}

		if !limiter.Allow(clientIP) {
			fmt.Printf("Rate limit exceeded for IP: %s on path: %s\n", clientIP, r.URL.Path)
			rw.Header().Set("Retry-After", "60")
			kit.SendTooManyRequests(rw, nil)
			return
		}

		next(rw, r)
	}, nil
}
