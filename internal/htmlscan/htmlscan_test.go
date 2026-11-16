package htmlscan

import (
	"slices"
	"testing"
)

func TestScan(t *testing.T) {
	const page = `<!doctype html><html><head><title> Admin </title>
<base href="/app/">
<script type="importmap">{"imports":{"vue":"https://cdn.test/vue.js","lib/":"/lib/"}}</script>
<link rel="modulepreload" href="assets/vendor.js">
<link rel="preload" as="script" href="/static/js/runtime.js">
<link rel="preload" as="style" href="/static/css/main.css">
<script src="static/js/main.8f91a2.chunk.js"></script>
<script type="module" src="assets/index.js"></script>
<script type="application/json" id="cfg">{"api":"/api"}</script>
<script type="text/template"><div>{{x}}</div></script>
<script id="__NEXT_DATA__" type="application/json">{"buildId":"Ab-12_x","assetPrefix":""}</script>
<script>window.__INITIAL_STATE__={a:1};fetch('/api/init')</script>
<script src="static/js/main.8f91a2.chunk.js#again"></script>
<script src="data:text/javascript,alert(1)"></script>
</head><body></body></html>`
	p := Scan([]byte(page), "https://h.test/login?next=/")
	if p.Title != "Admin" {
		t.Errorf("title %q", p.Title)
	}
	want := []string{
		"https://cdn.test/vue.js",
		"https://h.test/app/assets/vendor.js",
		"https://h.test/static/js/runtime.js",
		"https://h.test/app/static/js/main.8f91a2.chunk.js",
		"https://h.test/app/assets/index.js",
	}
	if got := p.Files(); !slices.Equal(got, want) {
		t.Errorf("files\n got  %v\n want %v", got, want)
	}
	in := p.Inline()
	if len(in) != 1 || in[0] != "window.__INITIAL_STATE__={a:1};fetch('/api/init')" {
		t.Errorf("inline %q", in)
	}
	if p.NextBuildID != "Ab-12_x" {
		t.Errorf("build id %q", p.NextBuildID)
	}
	if m := p.NextManifests(); len(m) != 2 || m[0] != "https://h.test/_next/static/Ab-12_x/_buildManifest.js" {
		t.Errorf("manifests %v", m)
	}
}

func TestNextBuildIDIsChecked(t *testing.T) {
	p := Scan([]byte(`<script id="__NEXT_DATA__">{"buildId":"../../x"}</script>`), "https://h.test/")
	if p.NextBuildID != "" || p.NextManifests() != nil {
		t.Errorf("an unsafe build id was taken: %q", p.NextBuildID)
	}
}
