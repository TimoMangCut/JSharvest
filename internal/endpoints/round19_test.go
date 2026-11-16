package endpoints

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// Each origin's bases for its endpoints; a development server's default
// dropped beside production's; a base the path starts with cut.
func TestBasesByOrigin(t *testing.T) {
	scripts := []Script{
		{SHA256: "inline", URLs: []string{"https://www.example.com"}, Result: jsapi.Result{Bases: []string{"https://api.example.com/hub"}}},
		{SHA256: "bundle", URLs: []string{"https://www.example.com/_vite/index.js"}, Result: jsapi.Result{
			Bases:     []string{"https://api.dev.example.internal/hub"},
			Endpoints: []jsapi.Endpoint{{Method: "GET", URL: "/api/account/v1/me", Kind: "client", Client: true}}}},
		{SHA256: "env", URLs: []string{"https://dev.example.com/env-config.js"}, Result: jsapi.Result{
			Bases: []string{"https://api.example.com", "https://api.example.com/hub/console/v1"}}},
		{SHA256: "console", URLs: []string{"https://dev.example.com/assets/index.js"}, Result: jsapi.Result{
			Endpoints: []jsapi.Endpoint{{Method: "GET", URL: "hub/console/v1/apps", Kind: "wrapper", Client: true}}}},
	}
	in := func(h string) bool { return h == "example.com" || strings.HasSuffix(h, ".example.com") }
	got := map[string][]string{}
	for _, e := range Build(scripts, nil, in) {
		got[e.Path] = e.Bases
	}
	if b := got["/api/account/v1/me"]; !slices.Equal(b, []string{"https://api.example.com/hub"}) {
		t.Errorf("www's endpoint: bases %v", b)
	}
	if b := got["/hub/console/v1/apps"]; len(b) == 0 || b[0] != "https://api.example.com" || slices.Contains(b, "https://api.dev.example.internal/hub") {
		t.Errorf("console's endpoint: bases %v", b)
	}
}
