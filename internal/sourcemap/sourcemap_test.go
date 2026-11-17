package sourcemap

import (
	"encoding/base64"
	"testing"
)

func TestFind(t *testing.T) {
	const js = "https://h.test/static/js/main.1a2b.js"
	for _, c := range []struct {
		name    string
		headers map[string]string
		body    string
		guess   bool
		url     string
		ok      bool
	}{
		{"header", map[string]string{"sourcemap": "/maps/main.map"}, "x", false, "https://h.test/maps/main.map", true},
		{"x-header", map[string]string{"x-sourcemap": "main.js.map"}, "x", false, "https://h.test/static/js/main.js.map", true},
		{"comment", nil, "var a=1;\n//# sourceMappingURL=main.1a2b.js.map\n", false, "https://h.test/static/js/main.1a2b.js.map", true},
		{"old comment", nil, "var a=1;\n//@ sourceMappingURL=m.map", false, "https://h.test/static/js/m.map", true},
		{"last comment wins", nil, "//# sourceMappingURL=a.map\nx\n//# sourceMappingURL=b.map", false, "https://h.test/static/js/b.map", true},
		{"guess", nil, "var a=1;", true, "https://h.test/static/js/main.1a2b.js.map", true},
		{"no guess", nil, "var a=1;", false, "", false},
		{"javascript: is no map", nil, "//# sourceMappingURL=javascript:alert(1)", false, "", false},
	} {
		r, ok := Find(js, c.headers, []byte(c.body), c.guess)
		if ok != c.ok || r.URL != c.url {
			t.Errorf("%s: %+v %v, want %s %v", c.name, r, ok, c.url, c.ok)
		}
	}
	inline := `{"version":3,"sources":["a.js"],"sourcesContent":["x"]}`
	r, ok := Find(js, nil, []byte("x\n//# sourceMappingURL=data:application/json;base64,"+base64.StdEncoding.EncodeToString([]byte(inline))), false)
	if !ok || string(r.Inline) != inline {
		t.Errorf("inline map: %+v %v", r, ok)
	}
}

func TestParseAndFiles(t *testing.T) {
	m, err := Parse([]byte(`)]}'
{"version":3,"sourceRoot":"","sources":["webpack:///./src/api/user.ts","webpack:///./node_modules/axios/index.js","webpack:///webpack/bootstrap","src/empty.ts"],
 "sourcesContent":["export const u = () => fetch('/api/v1/users');","module.exports={}","(()=>{})",null]}`))
	if err != nil {
		t.Fatal(err)
	}
	fs := m.Files()
	if len(fs) != 3 || fs[0].Path != "src/api/user.ts" || fs[0].Vendor || !fs[1].Vendor || !fs[2].Vendor {
		t.Errorf("files: %+v", fs)
	}
	if _, err := Parse([]byte("<!doctype html><html>")); err != ErrNotMap {
		t.Errorf("an HTML page parsed as a map: %v", err)
	}
	if _, err := Parse([]byte(`{"version":2,"sources":["a"]}`)); err != ErrNotMap {
		t.Errorf("version 2: %v", err)
	}
}

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"webpack:///./src/a.ts?1234": "src/a.ts",
		"../../src/b.tsx":            "src/b.tsx",
		"file:///home/x/src/c.js":    "home/x/src/c.js",
		"/abs/d.js":                  "abs/d.js",
	} {
		if got := Clean("", in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Clean("/app/", "src/x.ts"); got != "app/src/x.ts" {
		t.Errorf("with a root: %q", got)
	}
}

func TestFilesForStandaloneVendorLibraries(t *testing.T) {
	ck, err := Parse([]byte(`{"version":3,"sources":["../../packages/ckeditor5-core/src/plugin.js","../../packages/ckeditor5-utils/src/mix.js"],"sourcesContent":["export class Plugin {}","export function mix() {}"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range ck.FilesFor("https://portal.example.com/themes/custom/js/ckeditor5.js") {
		if !f.Vendor {
			t.Errorf("ckeditor5 source should be marked vendor: %+v", f)
		}
	}

	bs, err := Parse([]byte(`{"version":3,"sources":["js/src/carousel.js","js/src/modal.js"],"sourcesContent":["class Carousel {}","class Modal {}"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range bs.FilesFor("https://portal.example.com/dist/js/bootstrap.bundle.min.js") {
		if !f.Vendor {
			t.Errorf("bootstrap bundle source should be marked vendor: %+v", f)
		}
	}

	lw, err := Parse([]byte(`{"version":3,"sources":["js/features/supportRedirects.js"],"sourcesContent":["export function redirect() {}"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range lw.FilesFor("https://portal.example.com/livewire/livewire.min.js") {
		if !f.Vendor {
			t.Errorf("livewire source should be marked vendor: %+v", f)
		}
	}

	// Hybrid app bundle (app.js.map) must keep app sources non-vendor while marking node_modules vendor.
	app, err := Parse([]byte(`{"version":3,"sources":["resources/js/app.js","node_modules/axios/index.js"],"sourcesContent":["fetch('/api/orders')","module.exports={}"]}`))
	if err != nil {
		t.Fatal(err)
	}
	appFiles := app.FilesFor("https://portal.example.com/build/assets/app.js")
	if len(appFiles) != 2 || appFiles[0].Vendor || !appFiles[1].Vendor {
		t.Errorf("hybrid app.js.map vendor classification wrong: %+v", appFiles)
	}
}
