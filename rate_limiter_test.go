package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	a "github.com/stretchr/testify/assert"
)

func TestRateLimiter_Allow(t *testing.T) {
	assert := a.New(t)

	limiter, err := NewRateLimiter(context.Background(), 2) // 2 requests per minute
	assert.NoError(err)

	// First request should be allowed
	assert.True(limiter.Allow("127.0.0.1"))

	// Second request should be allowed
	assert.True(limiter.Allow("127.0.0.1"))

	// Third request should be denied (rate limit exceeded)
	assert.False(limiter.Allow("127.0.0.1"))

	// Different IP should be allowed
	assert.True(limiter.Allow("192.168.1.1"))
}

func TestRateLimiter_TokenRefresh(t *testing.T) {
	assert := a.New(t)

	// Create a rate limiter with very fast refresh for testing
	limiter := &RateLimiter{
		visitors: make(map[string]*Visitor),
		rate:     100 * time.Millisecond, // Very fast for testing
		capacity: 1,
		ctx:      context.Background(),
	}

	// Use up the token
	assert.True(limiter.Allow("127.0.0.1"))
	assert.False(limiter.Allow("127.0.0.1"))

	// Wait for token refresh (short time for testing)
	time.Sleep(150 * time.Millisecond)

	// Request should be allowed again
	assert.True(limiter.Allow("127.0.0.1"))
}

func TestRateLimitMiddleware_Allow(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rw := httptest.NewRecorder()
	called := false

	middleware, err := RateLimitMiddleware(RateLimiterConfig{RequestsPerMinute: 100, Context: context.Background(), TrustedProxyHeader: "X-Forwarded-For"}) // 100 requests per minute
	assert.NoError(err)
	middleware(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	assert.True(called, "Handler should be called when under rate limit")
	assert.Equal(200, rw.Code)
}

func TestRateLimitMiddleware_Block(t *testing.T) {
	assert := a.New(t)

	middleware, err := RateLimitMiddleware(RateLimiterConfig{RequestsPerMinute: 1, Context: context.Background(), TrustedProxyHeader: "X-Forwarded-For"}) // Very restrictive: 1 request per minute
	assert.NoError(err)

	// First request should pass
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "127.0.0.1:12345"
	rw1 := httptest.NewRecorder()
	called1 := false

	middleware(rw1, req1, func(w http.ResponseWriter, r *http.Request) {
		called1 = true
	})

	assert.True(called1, "First request should be allowed")
	assert.Equal(200, rw1.Code)

	// Second request should be blocked
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	rw2 := httptest.NewRecorder()
	called2 := false

	middleware(rw2, req2, func(w http.ResponseWriter, r *http.Request) {
		called2 = true
	})

	assert.False(called2, "Second request should be blocked")
	assert.Equal(429, rw2.Code)
	assert.Equal("60", rw2.Header().Get("Retry-After"))
}

func TestGetClientIP(t *testing.T) {
	assert := a.New(t)
	limiter, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)

	// Test X-Forwarded-For header
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.Header.Set("X-Forwarded-For", "192.168.1.100")
	req1.RemoteAddr = "127.0.0.1:12345"
	assert.Equal("192.168.1.100", limiter.getClientIP(req1, "X-Forwarded-For"))

	// Test fallback to RemoteAddr
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = "192.168.0.1:8080"
	assert.Equal("192.168.0.1", limiter.getClientIP(req3, ""))
}

func TestGetClientIP_MultiXForwardedFor(t *testing.T) {
	assert := a.New(t)
	limiter, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)

	// Multiple IPs in X-Forwarded-For: left-most should be chosen
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 198.51.100.7, 192.0.2.1")
	req.RemoteAddr = "10.0.0.1:34567"

	ip := limiter.getClientIP(req, "X-Forwarded-For")
	assert.Equal("203.0.113.5", ip)
}

func TestGetClientIP_MalformedRemoteAddrReturnsEmpty(t *testing.T) {
	assert := a.New(t)
	limiter, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)

	req := httptest.NewRequest("GET", "/test", nil)
	// malformed RemoteAddr should result in empty parse
	req.RemoteAddr = "::% 0"

	// direct call to getClientIP should return empty
	got := limiter.getClientIP(req, "")
	assert.Equal("", got)

	// middleware should reject when it cannot determine client IP
	middleware, err := RateLimitMiddleware(RateLimiterConfig{RequestsPerMinute: 100, Context: context.Background(), TrustedProxyHeader: ""})
	assert.NoError(err)

	rw := httptest.NewRecorder()
	called := false
	middleware(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	assert.False(called)
	assert.Equal(400, rw.Code)
}

func TestGetClientIP_MalformedRemoteAddrReturnsEmpty2(t *testing.T) {
	assert := a.New(t)
	limiter, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)

	req := httptest.NewRequest("GET", "/test", nil)
	// malformed RemoteAddr should result in empty parse
	req.RemoteAddr = "0"
	req.Header.Set("0", "::% 0") // also malformed

	// direct call to getClientIP should return empty
	got := limiter.getClientIP(req, "")
	assert.Equal("", got)

	// middleware should reject when it cannot determine client IP
	middleware, err := RateLimitMiddleware(RateLimiterConfig{RequestsPerMinute: 100, Context: context.Background(), TrustedProxyHeader: ""})
	assert.NoError(err)

	rw := httptest.NewRecorder()
	called := false
	middleware(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	assert.False(called)
	assert.Equal(400, rw.Code)
}

func TestGetClientIP_HeaderBracketedIPv6WithPort(t *testing.T) {
	assert := a.New(t)
	limiter, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "[2001:db8::1]:443")
	// simulate missing RemoteAddr as in the fuzz seed
	req.RemoteAddr = ""

	ip := limiter.getClientIP(req, "X-Forwarded-For")
	assert.Equal("2001:db8::1", ip)
}

func TestControlCharHeaderMiddleware(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5\n") // contains control char
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("X-Forwarded-For")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	assert.False(called, "Handler should not be called when header contains control chars")
	assert.Equal(400, rw.Code)
}

func TestSplitAndTrim_TrimEmptyParts(t *testing.T) {
	assert := a.New(t)

	s := "  a, b ,c,, ,d "
	got := splitAndTrim(s, ',')
	expected := []string{"a", "b", "c", "d"}
	assert.Equal(expected, got)
}

func TestTrimSpace_VariousWhitespace(t *testing.T) {
	assert := a.New(t)

	in := "\t  hello world \n"
	assert.Equal("hello world", trimSpace(in))

	in2 := "nochange"
	assert.Equal("nochange", trimSpace(in2))
}

func TestStripPort_IPVariants(t *testing.T) {
	assert := a.New(t)

	assert.Equal("192.168.0.1", stripPort("192.168.0.1:8080"))
	assert.Equal("2001:db8::1", stripPort("[2001:db8::1]:443"))
	// No port should return as-is (IPv4)
	assert.Equal("10.0.0.5", stripPort("10.0.0.5"))
	// Bracketed IPv6 without port remains unchanged
	assert.Equal("[::1]", stripPort("[::1]"))
}

func TestParseIP_ValidAndInvalid(t *testing.T) {
	assert := a.New(t)

	// valid IPv4
	assert.Equal("192.168.0.1", parseIP("192.168.0.1"))

	// invalid string
	assert.Equal("", parseIP("not-an-ip"))

	// valid IPv6
	assert.Equal("2001:db8::1", parseIP("2001:db8::1"))
}

func TestMaxClientIpsCap(t *testing.T) {
	assert := a.New(t)

	rl, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)
	rl.maxClients = 2

	// Allowed: first two distinct IPs
	assert.True(rl.Allow("10.0.0.1"))
	assert.True(rl.Allow("10.0.0.2"))

	// Third distinct IP should be rejected due to cap
	assert.False(rl.Allow("10.0.0.3"))

	// Existing IPs should still be allowed if tokens permit
	assert.True(rl.Allow("10.0.0.1")) // existing visitor should still be present and allowed
}

func TestAllowEmptyIPRejected(t *testing.T) {
	assert := a.New(t)

	rl, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)

	// Empty IP should be rejected
	assert.False(rl.Allow(""))
	assert.False(rl.Allow("   "))
}

func TestMiddlewareRejectsEmptyClientIP(t *testing.T) {
	assert := a.New(t)

	// Build middleware that will call getClientIP which will return empty
	// because RemoteAddr is empty and no trusted header is provided.
	middleware, err := RateLimitMiddleware(RateLimiterConfig{RequestsPerMinute: 100, Context: context.Background(), TrustedProxyHeader: ""})
	assert.NoError(err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "" // simulate missing RemoteAddr
	rw := httptest.NewRecorder()
	called := false

	middleware(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	assert.False(called, "Handler should not be called when client IP cannot be determined")
	assert.Equal(400, rw.Code)
}

func TestNewRateLimiter_ClampsLargeRPM(t *testing.T) {
	assert := a.New(t)

	// extremely large value should be clamped and should not cause division by zero
	rl, err := NewRateLimiter(context.Background(), 1_000_000_000)
	assert.NoError(err)
	// rate should be > 0
	assert.True(rl.rate > 0)

	// And Allow should not panic when called (use a normal IP)
	assert.NotPanics(func() { _ = rl.Allow("127.0.0.1") })
}

func TestParseIP_BracketedIPv6(t *testing.T) {
	assert := a.New(t)

	// bracketed IPv6 should be unwrapped and parsed
	got := parseIP("[2001:db8::1]")
	assert.Equal("2001:db8::1", got)

	// stripPort should remove port and keep bracketed form; parseIP should
	// normalize to unbracketed address
	limiter, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[2001:db8::1]:443"

	ip := limiter.getClientIP(req, "")
	assert.Equal("2001:db8::1", ip)

	// Ensure the visitor map uses the normalized unbracketed key
	rl, err := NewRateLimiter(context.Background(), 10)
	assert.NoError(err)
	assert.True(rl.Allow(ip))

	rl.mu.RLock()
	_, exists := rl.visitors[ip]
	rl.mu.RUnlock()

	assert.True(exists, "visitor map should contain normalized unbracketed IP key")
}

func TestCleanupEvictsStaleVisitor(t *testing.T) {
	assert := a.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl, err := NewRateLimiter(ctx, 10)
	assert.NoError(err)

	// configure aggressive cleanup for test
	rl.cleanupInterval = 20 * time.Millisecond
	rl.visitorStaleAfter = 30 * time.Millisecond
	rl.cleanupBatchSize = 100
	rl.StartCleanup()

	ip := "10.10.10.10"
	assert.True(rl.Allow(ip))

	// wait long enough for the visitor to become stale and for cleanup to run
	time.Sleep(rl.visitorStaleAfter + rl.cleanupInterval + 20*time.Millisecond)

	rl.mu.RLock()
	_, exists := rl.visitors[ip]
	rl.mu.RUnlock()

	assert.False(exists, "stale visitor should have been evicted by cleanup")
}

func TestCleanupKeepsActiveVisitor(t *testing.T) {
	assert := a.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl, err := NewRateLimiter(ctx, 10)
	assert.NoError(err)

	// configure aggressive cleanup for test
	rl.cleanupInterval = 20 * time.Millisecond
	rl.visitorStaleAfter = 200 * time.Millisecond
	rl.cleanupBatchSize = 100
	rl.StartCleanup()

	ip := "10.10.10.11"
	assert.True(rl.Allow(ip))

	// touch the visitor to set lastToken to now
	rl.mu.RLock()
	v := rl.visitors[ip]
	rl.mu.RUnlock()
	v.mu.Lock()
	v.lastToken = time.Now()
	v.mu.Unlock()

	// wait a single cleanup tick (less than stale threshold)
	time.Sleep(rl.cleanupInterval + 10*time.Millisecond)

	rl.mu.RLock()
	_, exists := rl.visitors[ip]
	rl.mu.RUnlock()

	assert.True(exists, "recently active visitor should not be evicted")
}
