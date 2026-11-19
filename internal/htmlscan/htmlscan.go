// Package htmlscan reads what a page's HTML loads and runs, without a
// browser: its script files (classic and module, an import map's entries,
// modulepreload and preload links), its inline code, and the build id a
// Next.js page names. The archive's old pages and the HTTP engine's live
// ones go through it; the links a crawl follows are frontier.FromHTML's.
package htmlscan

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Script is one script a page names.
type Script struct {
	URL    string `json:"url,omitempty"`    // absolute; empty for inline code
	How    string `json:"how"`              // src, module, importmap, modulepreload, preload, inline
	Module bool   `json:"module,omitempty"` // an ES module
	Inline string `json:"-"`                // the code of an inline script
}

// Page is what a page's HTML names.
type Page struct {
	Base    string   // the URL relative references resolve against (<base href>)
	Title   string   // the document's title
	Scripts []Script // files first seen first, inline code in document order
	// NextBuildID is the build id of a Next.js Pages Router page
	// (__NEXT_DATA__): its /_next/static/<id>/_buildManifest.js lists every
	// page's chunks.
	NextBuildID string
	// NextAssetPrefix is the asset prefix __NEXT_DATA__ names, when set.
	NextAssetPrefix string
	// ManifestURL is the first valid http(s) <link rel="manifest" href="..."> URL on the page.
	ManifestURL string
}

// jsTypes are the type attributes a browser runs as a classic script.
var jsTypes = map[string]bool{
	"": true, "text/javascript": true, "application/javascript": true, "application/x-javascript": true,
	"text/ecmascript": true, "application/ecmascript": true, "text/jscript": true, "text/livescript": true,
	"text/x-javascript": true, "text/x-ecmascript": true, "text/javascript1.0": true, "text/javascript1.5": true,
}

// Scan reads a page's HTML. pageURL is where it was served from.
func Scan(body []byte, pageURL string) Page {
	base, err := url.Parse(pageURL)
	if err != nil {
		return Page{}
	}
	p := Page{Base: base.String()}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return p
	}
	seen := map[string]bool{}
	baseSet := false
	add := func(ref, how string, module bool) {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "javascript:") {
			return
		}
		u, err := base.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		u.Fragment = ""
		s := u.String()
		if seen[s] {
			return
		}
		seen[s] = true
		p.Scripts = append(p.Scripts, Script{URL: s, How: how, Module: module})
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attr := map[string]string{}
			for _, a := range n.Attr {
				attr[strings.ToLower(a.Key)] = a.Val
			}
			switch n.DataAtom {
			case atom.Base:
				if h, ok := attr["href"]; ok && !baseSet {
					if u, err := base.Parse(strings.TrimSpace(h)); err == nil {
						base, baseSet = u, true
						p.Base = u.String()
					}
				}
			case atom.Title:
				if p.Title == "" {
					p.Title = strings.TrimSpace(text(n))
				}
			case atom.Script:
				typ := strings.ToLower(strings.TrimSpace(attr["type"]))
				if i := strings.IndexByte(typ, ';'); i >= 0 {
					typ = strings.TrimSpace(typ[:i])
				}
				code := text(n)
				switch {
				case typ == "importmap":
					p.importMap(code, add)
				case attr["id"] == "__NEXT_DATA__":
					p.nextData(code)
				case typ == "module" || jsTypes[typ]:
					module := typ == "module"
					if src, ok := attr["src"]; ok {
						how := "src"
						if module {
							how = "module"
						}
						add(src, how, module)
					} else if strings.TrimSpace(code) != "" {
						p.Scripts = append(p.Scripts, Script{How: "inline", Module: module, Inline: code})
					}
				}
			case atom.Link:
				rel := strings.ToLower(attr["rel"])
				as := strings.ToLower(attr["as"])
				switch {
				case hasToken(rel, "modulepreload"):
					add(attr["href"], "modulepreload", true)
				case hasToken(rel, "preload") && as == "script", hasToken(rel, "prefetch") && as == "script":
					add(attr["href"], "preload", false)
				case hasToken(rel, "manifest"):
					if p.ManifestURL == "" {
						if u, err := base.Parse(strings.TrimSpace(attr["href"])); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
							u.Fragment = ""
							p.ManifestURL = u.String()
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return p
}

// importMap adds the module URLs an import map names.
func (p *Page) importMap(code string, add func(ref, how string, module bool)) {
	var m struct {
		Imports map[string]string            `json:"imports"`
		Scopes  map[string]map[string]string `json:"scopes"`
	}
	if json.Unmarshal([]byte(code), &m) != nil {
		return
	}
	for _, v := range m.Imports {
		if !strings.HasSuffix(v, "/") {
			add(v, "importmap", true)
		}
	}
	for _, s := range m.Scopes {
		for _, v := range s {
			if !strings.HasSuffix(v, "/") {
				add(v, "importmap", true)
			}
		}
	}
}

func (p *Page) nextData(code string) {
	var d struct {
		BuildID     string `json:"buildId"`
		AssetPrefix string `json:"assetPrefix"`
	}
	if json.Unmarshal([]byte(code), &d) == nil && safeID(d.BuildID) {
		p.NextBuildID, p.NextAssetPrefix = d.BuildID, d.AssetPrefix
	}
}

// NextManifests are the URLs of a Next.js page's build manifests, given its
// build id: _buildManifest.js names every page's chunks.
func (p Page) NextManifests() []string {
	if p.NextBuildID == "" {
		return nil
	}
	base, err := url.Parse(p.Base)
	if err != nil {
		return nil
	}
	prefix := strings.TrimSuffix(p.NextAssetPrefix, "/")
	var out []string
	for _, f := range []string{"_buildManifest.js", "_ssgManifest.js"} {
		if u, err := base.Parse(prefix + "/_next/static/" + p.NextBuildID + "/" + f); err == nil {
			out = append(out, u.String())
		}
	}
	return out
}

// safeID accepts the build ids Next.js writes (letters, digits, - and _),
// so that a page cannot steer the path.
func safeID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func hasToken(list, tok string) bool {
	for _, f := range strings.Fields(list) {
		if f == tok {
			return true
		}
	}
	return false
}

func text(n *html.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	}
	return b.String()
}

// Files returns the URLs of the script files a page names, in order.
func (p Page) Files() []string {
	var out []string
	for _, s := range p.Scripts {
		if s.URL != "" {
			out = append(out, s.URL)
		}
	}
	return out
}

// Inline returns the inline code of a page, in order.
func (p Page) Inline() []string {
	var out []string
	for _, s := range p.Scripts {
		if s.URL == "" && s.Inline != "" {
			out = append(out, s.Inline)
		}
	}
	return out
}
