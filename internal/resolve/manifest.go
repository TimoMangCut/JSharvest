package resolve

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

func isJSAssetRef(s string) bool {
	clean := strings.ToLower(strings.SplitN(strings.SplitN(strings.TrimSpace(s), "#", 2)[0], "?", 2)[0])
	return strings.HasSuffix(clean, ".js") || strings.HasSuffix(clean, ".mjs")
}

// AssetManifest lists the scripts of a Create React App / webpack
// asset-manifest.json or Laravel Mix mix-manifest.json: its files map and
// its entrypoints.
func AssetManifest(b []byte, at string) []string {
	var m struct {
		Files       map[string]string `json:"files"`
		Entrypoints []string          `json:"entrypoints"`
	}
	if json.Unmarshal(b, &m) != nil || (len(m.Files) == 0 && len(m.Entrypoints) == 0) {
		// webpack-manifest-plugin / Laravel Mix flat form: {"/js/app.js": "/js/app.js?id=..."}
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
	if base == nil {
		return nil
	}
	var out []string
	addJS := func(s string) {
		if !isJSAssetRef(s) {
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
// build's base directory (e.g. "https://host/" or "https://host/build/").
func ViteManifest(b []byte, root string) []string {
	var m map[string]struct {
		File string `json:"file"`
	}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	if root != "" && !strings.HasSuffix(root, "/") {
		root += "/"
	}
	base, _ := url.Parse(root)
	if base == nil {
		return nil
	}
	var out []string
	for _, e := range m {
		if e.File != "" && isJSAssetRef(e.File) {
			if u, err := base.Parse(e.File); err == nil && !slices.Contains(out, u.String()) {
				out = append(out, u.String())
			}
		}
	}
	slices.Sort(out)
	return out
}

// EncoreEntrypoints lists the scripts of a Symfony Webpack Encore
// entrypoints.json file.
func EncoreEntrypoints(b []byte, at string) []string {
	var doc struct {
		Entrypoints map[string]struct {
			JS []string `json:"js"`
		} `json:"entrypoints"`
	}
	if json.Unmarshal(b, &doc) != nil || len(doc.Entrypoints) == 0 {
		return nil
	}
	base, _ := url.Parse(at)
	if base == nil {
		return nil
	}
	var out []string
	for _, ep := range doc.Entrypoints {
		for _, s := range ep.JS {
			if !isJSAssetRef(s) {
				continue
			}
			if u, err := base.Parse(s); err == nil && !slices.Contains(out, u.String()) {
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
	case strings.HasSuffix(p, "/mix-manifest.json"):
		return "mix-manifest"
	case strings.HasSuffix(p, "/ngsw.json"):
		return "ngsw"
	case strings.HasSuffix(p, "/.vite/manifest.json"),
		strings.HasSuffix(p, "/manifest.json") && strings.Contains(p, "/.vite/"),
		strings.HasSuffix(p, "/build/manifest.json"):
		return "vite-manifest"
	case strings.HasSuffix(p, "/build/entrypoints.json"),
		strings.HasSuffix(p, "/entrypoints.json") && strings.Contains(p, "/build/"):
		return "encore-entrypoints"
	}
	return ""
}

// ManifestScripts lists the scripts a build manifest names.
func ManifestScripts(body []byte, at string) []string {
	switch Manifest(at) {
	case "asset-manifest", "mix-manifest":
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
		var baseDir string
		if idx := strings.Index(u.Path, "/.vite/"); idx >= 0 {
			baseDir = u.Scheme + "://" + u.Host + u.Path[:idx+1]
		} else {
			baseDir = u.Scheme + "://" + u.Host + strings.TrimSuffix(u.Path, "manifest.json")
		}
		return ViteManifest(body, baseDir)
	case "encore-entrypoints":
		return EncoreEntrypoints(body, at)
	}
	return nil
}
