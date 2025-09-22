package ratelimit

import (
	"net/http"
	"strings"
	"unicode"

	kit "github.com/stfsy/go-api-kit/server/handlers"
)

// ControlCharHeaderMiddleware returns a middleware that rejects requests where
// the named header contains ASCII control characters. This helps mitigate
// header injection/log forging attacks when headers are user-controlled.
// If headerName is empty the middleware is a no-op and always calls next.
func ControlCharHeaderMiddleware(headerName string) func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		if headerName == "" {
			next(rw, r)
			return
		}
		hv := r.Header.Get(headerName)
		if hv != "" {
			if strings.IndexFunc(hv, unicode.IsControl) != -1 {
				kit.SendBadRequest(rw, nil)
				return
			}
		}
		next(rw, r)
	}
}
