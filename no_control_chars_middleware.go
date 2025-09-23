package ratelimit

import (
	"net/http"
	"net/textproto"

	kit "github.com/stfsy/go-api-kit/server/handlers"
)

// ControlCharHeaderMiddleware returns a middleware that rejects requests where
// the named header contains ASCII control characters or non-ASCII bytes.
//
// Implementation notes and policy:
//   - This middleware enforces a strict byte-level rule: any byte with value
//     <= 31 (control characters), == 127 (DEL), or >= 128 (non-ASCII) will
//     cause the request to be rejected with HTTP 400. This is intentional for
//     API token headers where only printable ASCII is allowed.
//   - We use a fast byte-scan (no rune/UTF-8 decoding) for minimal CPU work and
//     deterministic behavior. There is no fallback: non-ASCII bytes are rejected
//     immediately.
//   - If headerName is empty the middleware is a no-op and always calls next.
func ControlCharHeaderMiddleware(headerName string) func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		if headerName == "" {
			next(rw, r)
			return
		}

		// canonicalize the header name to match how net/http stores headers
		canonical := textproto.CanonicalMIMEHeaderKey(headerName)
		vals := r.Header[canonical]

		// Check each header value byte-by-byte. This is intentionally strict:
		// - reject ASCII control bytes (0x00..0x1F), DEL (0x7F)
		// - reject any non-ASCII byte (>= 0x80)
		for _, hv := range vals {
			if hv == "" {
				continue
			}
			for i := 0; i < len(hv); i++ {
				b := hv[i]
				if b <= 31 || b == 127 || b >= 128 {
					kit.SendBadRequest(rw, nil)
					return
				}
			}
		}

		next(rw, r)
	}
}

// TokenHeaderMiddleware enforces a conservative allowlist suitable for API tokens.
// Allowed bytes: letters (A-Z, a-z), digits (0-9), and the punctuation
// characters '-', '_', '.', '#'. Any other byte (including space or non-ASCII)
// will cause the request to be rejected with HTTP 400. Empty values are
// considered invalid for token headers.
func TokenHeaderMiddleware(headerName string) func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		if headerName == "" {
			next(rw, r)
			return
		}

		canonical := textproto.CanonicalMIMEHeaderKey(headerName)
		vals := r.Header[canonical]
		for _, hv := range vals {
			if hv == "" {
				kit.SendBadRequest(rw, nil)
				return
			}
			for i := 0; i < len(hv); i++ {
				b := hv[i]
				switch {
				case b >= '0' && b <= '9':
					// ok
				case b >= 'A' && b <= 'Z':
					// ok
				case b >= 'a' && b <= 'z':
					// ok
				case b == '-' || b == '_' || b == '.' || b == '#':
					// ok
				default:
					kit.SendBadRequest(rw, nil)
					return
				}
			}
		}

		next(rw, r)
	}
}
