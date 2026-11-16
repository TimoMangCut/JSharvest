package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Split Webpack 4 runtimeChunk ("runtime.js" + "app.js"): runtime.js defines
// the unhashed chunk URL template with zero .e() calls of its own, while app.js
// uses webpackAsyncContext to load 0.js and 1.js (and 0.js chains to 2.js).
// Chunk 99.js answers with the SPA HTML fallback shell and must NOT be stored
// as a harvested script; module IDs 1476 and 1477 must never be requested.
func TestCrawlWebpackSplitRuntimeAndAsyncContext(t *testing.T) {
	var mu sync.Mutex
	requested := map[string]int{}
	mux := http.NewServeMux()

	shell := `<!doctype html><html><head><title>Portal</title></head><body>` +
		`<div id="app"></div>` +
		`<script src="/js/runtime.js"></script>` +
		`<script src="/js/app.js"></script>` +
		`</body></html>`

	jsHandler := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requested[r.URL.Path]++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, body)
		}
	}

	mux.HandleFunc("/js/runtime.js", jsHandler(
		`!function(e){var r={};r.p="/js/";r.e=function(e){var c=document.createElement("script");`+
			`c.src=function(e){return r.p + "" + ({}[e]||e) + ".js"}(e);document.head.appendChild(c)}}({});`,
	))
	mux.HandleFunc("/js/app.js", jsHandler(
		`(window.webpackJsonp=window.webpackJsonp||[]).push([[1],{100:function(e,t,r){`+
			`var map={"./en-US.json":[1476,0],"./vi-VN.json":[1477,1]};`+
			`function webpackAsyncContext(req){if(!r.o(map,req))return Promise.reject();`+
			`var ids=map[req],id=ids[0];return Promise.all(ids.slice(1).map(r.e)).then(function(){return r(id)})}`+
			`r.e(99);`+
			`}}]);`,
	))
	mux.HandleFunc("/js/0.js", jsHandler(`(window.webpackJsonp=window.webpackJsonp||[]).push([[0],{1476:function(e,t,r){r.e(2);fetch("/api/v1/locales/en")}}]);`))
	mux.HandleFunc("/js/1.js", jsHandler(`(window.webpackJsonp=window.webpackJsonp||[]).push([[1],{1477:function(e,t){fetch("/api/v1/locales/vi")}}]);`))
	mux.HandleFunc("/js/2.js", jsHandler(`(window.webpackJsonp=window.webpackJsonp||[]).push([[2],{1478:function(e,t){fetch("/api/v1/orders")}}]);`))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.URL.Path]++
		mu.Unlock()
		// Both "/" and any missing chunk like "/js/99.js" answer with the SPA HTML shell.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, shell)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/")

	var scripts []string
	res, err := Crawl(context.Background(), Options{
		Target:  u,
		InScope: func(string) bool { return true },
		Depth:   1,
		Rate:    1000,
		Script: func(s Script) {
			if s.Kind == "file" {
				mu.Lock()
				scripts = append(scripts, strings.TrimPrefix(s.URL, srv.URL))
				mu.Unlock()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	slices.Sort(scripts)
	want := []string{"/js/0.js", "/js/1.js", "/js/2.js", "/js/app.js", "/js/runtime.js"}
	if !slices.Equal(scripts, want) {
		t.Fatalf("harvested scripts:\n got  %v\n want %v", scripts, want)
	}
	if res.Stats.NotScript == 0 {
		t.Errorf("expected SPA HTML fallback on /js/99.js to increment Stats.NotScript, got 0")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, modID := range []string{"/js/1476.js", "/js/1477.js"} {
		if requested[modID] > 0 {
			t.Errorf("moduleId %s was mistakenly requested as a chunk", modID)
		}
	}
}
