package testdata

import "net/http"

func unlockedFixture() http.Handler {
	seen := map[string]int{}
	var st struct{ n int }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = 1
		st.n++
		delete(seen, "/old")
	})
}
