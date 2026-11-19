package testdata

import (
	"net/http"
	"sync/atomic"
)

func atomicSafeFixture() http.Handler {
	var hits atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Ok", "1")
	})
}
