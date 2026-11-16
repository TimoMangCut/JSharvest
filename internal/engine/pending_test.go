package engine

import (
	"slices"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/capture"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
)

// Architecture review 2026-11-13: a run that does not resolve (watch,
// -resolve=false) never takes the captured bodies back, so it must not
// keep them: each stayed in the heap until the run ended.
func TestNoteCapturedKeepsBodiesOnlyToResolve(t *testing.T) {
	for _, resolveOn := range []bool{false, true} {
		e := &engine{runState: &runState{cfg: Config{Resolve: resolveOn}, seen: map[string]bool{}, parsed: map[string]bool{}, resolved: map[string]resolve.Candidate{}}}
		s := capture.Script{URL: "https://app.test/main.js", Page: "https://app.test/", Body: []byte(`import("./chunk.js")`)}
		e.noteCaptured(&s)
		if got := len(e.pending); (got == 1) != resolveOn {
			t.Errorf("resolve %v: %d bodies kept", resolveOn, got)
		}
	}
}

func TestNoteCapturedLinksSplitWebpackRuntime(t *testing.T) {
	e := &engine{runState: &runState{cfg: Config{Resolve: true}, seen: map[string]bool{}, parsed: map[string]bool{}, resolved: map[string]resolve.Candidate{}}}
	scripts := []capture.Script{
		{
			URL:  "https://admin.example.com/js/runtime.js",
			Page: "https://admin.example.com/",
			Body: []byte(`!function(){var r={};r.p="/js/";r.e=function(e){var c=document.createElement("script");c.src=function(e){return r.p+""+({}[e]||e)+".js"}(e)}}();`),
		},
		{
			URL:  "https://www.googletagmanager.com/gtm.js",
			Page: "https://admin.example.com/",
			Tags: []string{"third-party"},
			Body: []byte(`r.e(99);`),
		},
		{
			URL:  "https://admin.example.com/js/app.js",
			Page: "https://admin.example.com/",
			Body: []byte(`var map={"./en-US.json":[1476,0],"./vi-VN.json":[1477,1]};function ctx(q){var ids=map[q];return Promise.all(ids.slice(1).map(r.e))}`),
		},
	}
	for i := range scripts {
		e.noteCaptured(&scripts[i])
	}
	var got []string
	for _, r := range e.takePending() {
		for _, c := range resolve.Static(r.body, r.url, r.page) {
			got = append(got, c.URL)
		}
		for _, c := range e.webpack.Add(r.body, r.url, r.page, r.inline, r.thirdParty) {
			got = append(got, c.URL)
		}
	}
	slices.Sort(got)
	want := []string{"https://admin.example.com/js/0.js", "https://admin.example.com/js/1.js"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
