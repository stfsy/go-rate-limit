package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	a "github.com/stretchr/testify/assert"
)

func TestControlCharHeaderMiddleware_AllowsValid(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("X-Forwarded-For")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.True(called, "next should be called for valid header")
	assert.Equal(200, rw.Code)
}

func TestControlCharHeaderMiddleware_BlocksControlChars(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5\n") // contains control char
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("X-Forwarded-For")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called, "next should not be called when header contains control chars")
	assert.Equal(http.StatusBadRequest, rw.Code)
}

func TestControlCharHeaderMiddleware_NoOpWhenHeaderNameEmpty(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.True(called, "middleware should be no-op when header name is empty")
	assert.Equal(200, rw.Code)
}
