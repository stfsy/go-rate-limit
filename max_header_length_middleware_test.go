package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	a "github.com/stretchr/testify/assert"
)

func TestMaxHeaderLengthMiddleware_AllowsUnderLimit(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	rw := httptest.NewRecorder()
	called := false

	mw := MaxHeaderLengthMiddleware("X-Forwarded-For", 100)
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.True(called)
	assert.Equal(200, rw.Code)
}

func TestMaxHeaderLengthMiddleware_BlocksOverLimit(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	// build a header value longer than 10
	req.Header.Set("X-Forwarded-For", strings.Repeat("a", 20))
	rw := httptest.NewRecorder()
	called := false

	mw := MaxHeaderLengthMiddleware("X-Forwarded-For", 10)
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called)
	assert.Equal(http.StatusBadRequest, rw.Code)
}

func TestMaxHeaderLengthMiddleware_NoOpWhenDisabled(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", strings.Repeat("a", 100))
	rw := httptest.NewRecorder()
	called := false

	mw := MaxHeaderLengthMiddleware("", 0)
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.True(called)
	assert.Equal(200, rw.Code)
}
