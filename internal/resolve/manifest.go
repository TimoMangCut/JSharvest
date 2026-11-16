package resolve

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

// AssetManifest lists the scripts of a Create React App / webpack
// asset-manifest.json: its files map and its entrypoints.
func AssetManifest(b []byte, at string) []string {
	var m struct {
		Files       map[string]string `json:"files"`
		Entrypoints []string          `json:"entrypoints"`
	}
	if json.Unmarshal(b, &m) != nil {
		// webpack-manifest-plugin's flat form: {"main.js": "/static/js/main.js"}
		var flat map[string]any
		if json.Unmarshal(b, &flat) != nil {
			return nil
		}
		m.Files = map[string]string{}
		for k, v := range flat {
			if s, ok := v.(string); ok {
				m.Files[k] = s
			}
		}
	}
	base, _ := url.Parse(at)
	var out []string
	addJS := func(s string) {
		if !strings.HasSuffix(strings.SplitN(s, "?", 2)[0], ".js") {
			return
		}
		if u, err := base.Parse(s); err == nil && !slices.Contains(out, u.String()) {
			out = append(out, u.String())
		}
	}
	for _, v := range m.Files {
		addJS(v)
	}
	for _, v := range m.Entrypoints {
		addJS(v)
	}
	slices.Sort(out)
	return out
}

// ViteManifest lists the files of a Vite build manifest, relative to the
// build's base (taken to be the root).
func ViteManifest(b []byte, root string) []string {
	var m map[string]struct {
		File string `json:"file"`
	}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	base, _ := url.Parse(root)
	var out []string
	for _, e := range m {
		if strings.HasSuffix(e.File, ".js") {
			if u, err := base.Parse(e.File); err == nil && !slices.Contains(out, u.String()) {
				out = append(out, u.String())
			}
		}
	}
	slices.Sort(out)
	return out
}

// Manifest is the kind of build manifest a URL is, by its path: one that
// names a build's scripts ("" for none).
func Manifest(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch p := u.Path; {
	case strings.HasSuffix(p, "/asset-manifest.json"):
		return "asset-manifest"
	case strings.HasSuffix(p, "/ngsw.json"):
		return "ngsw"
	case strings.HasSuffix(p, "/.vite/manifest.json"), strings.HasSuffix(p, "/manifest.json") && strings.Contains(p, "/.vite/"):
		return "vite-manifest"
	}
	return ""
}

// ManifestScripts lists the scripts a build manifest names.
func ManifestScripts(body []byte, at string) []string {
	switch Manifest(at) {
	case "asset-manifest":
		return AssetManifest(body, at)
	case "ngsw":
		var out []string
		for _, c := range NgswURLs(body, at) {
			out = append(out, c.URL)
		}
		return out
	case "vite-manifest":
		u, err := url.Parse(at)
		if err != nil {
			return nil
		}
		root := u.Scheme + "://" + u.Host + strings.TrimSuffix(u.Path, ".vite/manifest.json")
		return ViteManifest(body, root)
	}
	return nil
}
