package roles

import (
	"strings"
	"testing"
)

// The HTTP engine's anon next to a browser's user is the usual pair: one
// note that anon's scripts never ran, no -no-debugger or explore/resolve
// mismatch; two browser roles crawled unalike still warn as before.
func TestCompareConfigsEngines(t *testing.T) {
	anonHTTP := &roleData{name: "anon", configs: []RunConfig{{Known: true, Depth: 1, Resolve: true, Engine: "http"}}}
	user := &roleData{name: "user", configs: []RunConfig{{Known: true, Depth: 1, Resolve: true, Debugger: true, Explore: true}}}
	admin := &roleData{name: "admin", configs: []RunConfig{{Known: true, Depth: 2, Resolve: true, Debugger: true}}}

	w := strings.Join(compareConfigs([]*roleData{anonHTTP, user}), "\n")
	if !strings.Contains(w, "anon was crawled without a browser") || !strings.Contains(w, "client_gated because anon sent nothing") {
		t.Errorf("no engine note:\n%s", w)
	}
	if strings.Contains(w, "-no-debugger") || strings.Contains(w, "not crawled alike") {
		t.Errorf("engine differences reported one by one:\n%s", w)
	}

	w = strings.Join(compareConfigs([]*roleData{user, admin}), "\n")
	if !strings.Contains(w, "user and admin were not crawled alike (depth 1 vs 2, explore true vs false)") {
		t.Errorf("browser roles crawled unalike:\n%s", w)
	}
	if strings.Contains(w, "without a browser") {
		t.Errorf("an engine note between two browser roles:\n%s", w)
	}

	// A depth difference still shows next to the engine note.
	w = strings.Join(compareConfigs([]*roleData{anonHTTP, admin}), "\n")
	if !strings.Contains(w, "depth 1 vs 2") || !strings.Contains(w, "without a browser") {
		t.Errorf("anon (http) and admin, depth unalike:\n%s", w)
	}

	// A browser role run with -no-debugger is still told.
	nodbg := &roleData{name: "user", configs: []RunConfig{{Known: true, Resolve: true}}}
	if w := strings.Join(compareConfigs([]*roleData{nodbg}), "\n"); !strings.Contains(w, "-no-debugger") {
		t.Errorf("-no-debugger not told:\n%s", w)
	}
}
