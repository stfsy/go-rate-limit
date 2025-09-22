package ratelimit

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzGetClientIP fuzzes the header parsing logic for getClientIP.
// It ensures the helper never panics and returns a sane, comma-free value.
func FuzzGetClientIP(f *testing.F) {
	// seeds: headerName, headerValue, remoteAddr
	seeds := [][]string{
		{"X-Forwarded-For", "203.0.113.5, 198.51.100.7", "10.0.0.1:1234"},
		{"X-Forwarded-For", "192.168.0.1", "127.0.0.1:8080"},
		{"X-Real-IP", "10.0.0.5", "127.0.0.1:8080"},
		{"", "", "192.0.2.1:5555"},
		{"X-Forwarded-For", "[2001:db8::1]:443, 198.51.100.7", "[2001:db8::1]:443"},
	}

	for _, s := range seeds {
		f.Add(s[0], s[1], s[2])
	}

	f.Fuzz(func(t *testing.T, headerName, headerValue, remoteAddr string) {
		if remoteAddr == "" {
			remoteAddr = "127.0.0.1:1"
		}

		req := httptest.NewRequest("GET", "/", nil)
		if headerName != "" {
			req.Header.Set(headerName, headerValue)
		}
		req.RemoteAddr = remoteAddr

		out := getClientIP(req, headerName)

		// Always getClientIP should return a non-empty, comma-free token
		if out == "" {
			t.Fatalf("empty client IP for header=%q value=%q remote=%q", headerName, headerValue, remoteAddr)
		}
		if strings.Contains(out, ",") {
			t.Fatalf("returned IP contains comma: %q", out)
		}
		if strings.ContainsAny(out, "\n\r\t") {
			t.Fatalf("returned IP contains control chars: %q", out)
		}
		if strings.Contains(out, " ") {
			t.Fatalf("returned IP contains space: %q", out)
		}
	})
}

// FuzzAllow ensures calling Allow with arbitrary IP strings does not panic
// and returns a boolean. The limiter is small to limit memory growth during fuzzing.
func FuzzAllow(f *testing.F) {
	seeds := []string{"127.0.0.1", "10.0.0.1", "203.0.113.5", "[2001:db8::1]"}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, ip string) {
		rl, err := NewRateLimiter(context.Background(), 5)
		if err != nil {
			t.Fatalf("failed to create rate limiter: %v", err)
		}
		// keep cap moderate so the fuzz harness doesn't blow memory
		rl.maxClients = 50

		// call Allow with the fuzzed IP; just ensure no panic and a bool is returned
		_ = rl.Allow(ip)
	})
}
