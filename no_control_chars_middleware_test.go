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

func TestControlCharHeaderMiddleware_MultiValueHeader(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	// set multiple values for the same header; one contains a control char
	req.Header.Add("X-Forwarded-For", "203.0.113.5")
	req.Header.Add("X-Forwarded-For", "198.51.100.7\n")
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("X-Forwarded-For")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called, "next should not be called when any header value contains control chars")
	assert.Equal(http.StatusBadRequest, rw.Code)
}

func TestASCIIValidator_AllowsPrintableASCII(t *testing.T) {
	// removed: ASCIIValidator no longer exported; behavior is enforced via middleware
}

func TestASCIIValidator_BlocksNonASCII(t *testing.T) {
	// removed: ASCIIValidator no longer exported; behavior is enforced via middleware
}

func TestControlCharHeaderMiddleware_API_Token_StrictASCII(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Api-Token", "valid-token123")
	rw := httptest.NewRecorder()
	called := false

	mw := TokenHeaderMiddleware("X-Api-Token")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.True(called, "next should be called for valid ASCII token")
	assert.Equal(200, rw.Code)

	// now try a token with a non-ASCII byte (ü -> multi-byte utf-8)
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Api-Token", "bad-token-ünicode")
	rw2 := httptest.NewRecorder()
	called2 := false

	mw(rw2, req2, func(w http.ResponseWriter, r *http.Request) {
		called2 = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called2, "next should NOT be called for non-ASCII token")
	assert.Equal(http.StatusBadRequest, rw2.Code)
}

func TestControlCharHeaderMiddleware_BlocksNUL(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	// contains NUL byte
	req.Header.Set("X-Forwarded-For", "203.0.113.5\x00")
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("X-Forwarded-For")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called, "next should not be called when header contains NUL")
	assert.Equal(http.StatusBadRequest, rw.Code)
}

func TestControlCharHeaderMiddleware_BlocksDEL(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	// contains DEL (0x7F)
	req.Header.Set("X-Forwarded-For", "203.0.113.5\x7f")
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("X-Forwarded-For")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called, "next should not be called when header contains DEL")
	assert.Equal(http.StatusBadRequest, rw.Code)
}

func TestControlCharHeaderMiddleware_BlocksTab(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	// contains TAB (0x09)
	req.Header.Set("X-Forwarded-For", "203.0.113.5\t")
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("X-Forwarded-For")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called, "next should not be called when header contains TAB")
	assert.Equal(http.StatusBadRequest, rw.Code)
}

func TestControlCharHeaderMiddleware_BlocksNonASCIIByte(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	// contains a non-ASCII single byte (0x80)
	req.Header.Set("X-Forwarded-For", "203.0.113.5\x80")
	rw := httptest.NewRecorder()
	called := false

	mw := ControlCharHeaderMiddleware("X-Forwarded-For")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called, "next should not be called when header contains non-ASCII byte")
	assert.Equal(http.StatusBadRequest, rw.Code)
}

func TestControlCharHeaderMiddleware_AcceptsExampleToken(t *testing.T) {
	assert := a.New(t)

	example := "abc#f8WlopRw07bXotdcf_PgUw#JtRul2SoMG3pFG8Z_q5tOcvMyzFpFf_BqTmErHtHCXxq3nbziBYngSYt3UFu9xld1KPVpl8hG-0cDes3090S6w"

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Api-Token", example)
	rw := httptest.NewRecorder()
	called := false

	mw := TokenHeaderMiddleware("X-Api-Token")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.True(called, "next should be called for valid token example")
	assert.Equal(200, rw.Code)
}

func TestControlCharHeaderMiddleware_RejectsSpace(t *testing.T) {
	assert := a.New(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Api-Token", "bad token with space")
	rw := httptest.NewRecorder()
	called := false

	mw := TokenHeaderMiddleware("X-Api-Token")
	mw(rw, req, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	assert.False(called, "next should NOT be called when token contains space")
	assert.Equal(http.StatusBadRequest, rw.Code)
}
