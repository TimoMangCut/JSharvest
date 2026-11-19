package testdata

import (
	"net/http"
	"sync"
)

func lockedFixture() http.Handler {
	var mu sync.Mutex
	seen := map[string]int{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = 1
		delete(seen, "/old")
		mu.Unlock()
	})
}
