package testdata

import (
	"net/http"
	"sync"
)

func rlockWriteFixture() http.Handler {
	var mu sync.RWMutex
	seen := map[string]int{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		seen[r.URL.Path] = 1
		mu.RUnlock()
	})
}
