package ratelimit

import (
	"net/http"

	kit "github.com/stfsy/go-api-kit/server/handlers"
)

// MaxHeaderLengthMiddleware returns a middleware that rejects requests where
// the named header's value exceeds maxLen bytes. If headerName is empty or
// maxLen <= 0 the middleware is a no-op.
func MaxHeaderLengthMiddleware(headerName string, maxLen int) func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		if headerName == "" || maxLen <= 0 {
			next(rw, r)
			return
		}
		hv := r.Header.Get(headerName)
		if hv != "" && len(hv) > maxLen {
			// reject oversized header
			kit.SendBadRequest(rw, nil)
			return
		}
		next(rw, r)
	}
}
