package resolve

import (
	"slices"
	"testing"
)

func TestRound39SSRBuildManifests(t *testing.T) {
	// 1. Laravel Mix (/mix-manifest.json) with cache-busting ?id=... and .mjs
	mix := []byte(`{
		"/js/app.js": "/js/app.js?id=8f9a12b",
		"/js/admin-orders.mjs": "/js/admin-orders.mjs?id=33cd01",
		"/css/app.css": "/css/app.css?id=9911aa"
	}`)
	if got := Manifest("https://portal.example.test/mix-manifest.json"); got != "mix-manifest" {
		t.Fatalf("Manifest(/mix-manifest.json) = %q, want mix-manifest", got)
	}
	wantMix := []string{
		"https://portal.example.test/js/admin-orders.mjs?id=33cd01",
		"https://portal.example.test/js/app.js?id=8f9a12b",
	}
	if got := ManifestScripts(mix, "https://portal.example.test/mix-manifest.json"); !slices.Equal(got, wantMix) {
		t.Fatalf("mix-manifest scripts = %v, want %v", got, wantMix)
	}

	// 2. Laravel Vite (/build/manifest.json & /build/.vite/manifest.json) resolves relative to /build/
	vite := []byte(`{
		"resources/js/app.js": {"file": "assets/app-D3f8a1.js", "isEntry": true},
		"resources/js/admin.ts": {"file": "assets/admin-99bC2.mjs", "isEntry": true},
		"resources/css/app.css": {"file": "assets/app-1122.css"}
	}`)
	wantVite := []string{
		"https://portal.example.test/build/assets/admin-99bC2.mjs",
		"https://portal.example.test/build/assets/app-D3f8a1.js",
	}
	for _, u := range []string{
		"https://portal.example.test/build/manifest.json",
		"https://portal.example.test/build/.vite/manifest.json",
	} {
		if got := Manifest(u); got != "vite-manifest" {
			t.Fatalf("Manifest(%s) = %q, want vite-manifest", u, got)
		}
		if got := ManifestScripts(vite, u); !slices.Equal(got, wantVite) {
			t.Fatalf("ManifestScripts(%s) = %v, want %v", u, got, wantVite)
		}
	}

	// 3. Symfony Webpack Encore (/build/entrypoints.json)
	encore := []byte(`{
		"entrypoints": {
			"app": {"js": ["/build/runtime.js", "/build/app.js"], "css": ["/build/app.css"]},
			"backoffice": {"js": ["/build/runtime.js", "/build/backoffice.mjs"]}
		}
	}`)
	if got := Manifest("https://portal.example.test/build/entrypoints.json"); got != "encore-entrypoints" {
		t.Fatalf("Manifest(/build/entrypoints.json) = %q, want encore-entrypoints", got)
	}
	wantEncore := []string{
		"https://portal.example.test/build/app.js",
		"https://portal.example.test/build/backoffice.mjs",
		"https://portal.example.test/build/runtime.js",
	}
	if got := ManifestScripts(encore, "https://portal.example.test/build/entrypoints.json"); !slices.Equal(got, wantEncore) {
		t.Fatalf("encore scripts = %v, want %v", got, wantEncore)
	}
}
