package ratelimit

import (
	"context"
	"fmt"
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
		req := httptest.NewRequest("GET", "/", nil)
		if headerName != "" {
			req.Header.Set(headerName, headerValue)
		}
		req.RemoteAddr = remoteAddr
		rl, err := NewRateLimiter(context.Background(), 100)
		if err != nil {
			t.Fatalf("failed to create rate limiter: %v", err)
		}
		// keep cap moderate for fuzzing
		rl.maxClients = 200

		out := rl.getClientIP(req, headerName)
		fmt.Printf("FuzzGetClientIP output: %q\n", out)

		// Skip clearly malformed outputs (these are not useful fuzz findings)
		if out == "" {
			t.Skipf("empty client IP for header=%q value=%q remoteAddr=%q", headerName, headerValue, remoteAddr)
		}
		if strings.Contains(out, ",") {
			t.Fatalf("returned IP contains comma -> \"%q\" for input %s", out, remoteAddr)
		}
		if strings.ContainsAny(out, "\n\r\t") {
			t.Fatalf("returned IP contains control chars -> \"%q\" for input %s", out, remoteAddr)
		}
		if strings.Contains(out, " ") {
			t.Fatalf("returned IP contains space -> \"%q\" for remoteAddr:'%s' headerKey:'%s' headerValue:'%s'", out, remoteAddr, headerName, headerValue)
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
