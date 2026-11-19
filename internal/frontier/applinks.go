package frontier

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

const maxManifestBytes = 1 << 20

// FromWebManifest extracts navigable application routes (start_url, non-root
// scope, shortcuts, and GET share_target actions) from a W3C Web App Manifest.
func FromWebManifest(body []byte, manifestURL string) []Found {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || len(body) > maxManifestBytes || body[0] != '{' {
		return nil
	}
	base, err := url.Parse(manifestURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil
	}
	var doc struct {
		StartURL  string `json:"start_url"`
		Scope     string `json:"scope"`
		Shortcuts []struct {
			URL string `json:"url"`
		} `json:"shortcuts"`
		ShareTarget *struct {
			Action string `json:"action"`
			Method string `json:"method"`
		} `json:"share_target"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var c collector
	if strings.TrimSpace(doc.StartURL) != "" {
		c.add(base, doc.StartURL, Route, true)
	}
	if sc := strings.TrimSpace(doc.Scope); sc != "" {
		if u, err := base.Parse(sc); err == nil && u.Path != "" && u.Path != "/" {
			c.add(base, sc, Route, true)
		}
	}
	for _, sh := range doc.Shortcuts {
		if strings.TrimSpace(sh.URL) != "" {
			c.add(base, sh.URL, Route, true)
		}
	}
	if doc.ShareTarget != nil && strings.TrimSpace(doc.ShareTarget.Action) != "" {
		m := strings.ToUpper(strings.TrimSpace(doc.ShareTarget.Method))
		visit := m == "" || m == "GET"
		c.add(base, doc.ShareTarget.Action, Route, visit)
	}
	return c.out
}

// FromAppleAppSiteAssociation extracts concrete non-wildcard route prefixes
// from an iOS /.well-known/apple-app-site-association document.
func FromAppleAppSiteAssociation(body []byte, origin string) []Found {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || len(body) > maxManifestBytes || body[0] != '{' {
		return nil
	}
	base, err := url.Parse(strings.TrimRight(origin, "/") + "/")
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil
	}
	var doc struct {
		AppLinks struct {
			Details []struct {
				Paths      []string `json:"paths"`
				Components []struct {
					Path    string `json:"/"`
					Exclude bool   `json:"exclude"`
				} `json:"components"`
			} `json:"details"`
		} `json:"applinks"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var c collector
	addPattern := func(raw string) {
		if len(c.out) >= 64 {
			return
		}
		p := strings.TrimSpace(raw)
		if p == "" || strings.HasPrefix(strings.ToUpper(p), "NOT ") {
			return
		}
		if idx := strings.IndexAny(p, "*?"); idx >= 0 {
			p = p[:idx]
		}
		p = strings.TrimRight(p, "/")
		if p == "" || !strings.HasPrefix(p, "/") {
			return
		}
		c.add(base, p, Route, true)
	}
	for _, d := range doc.AppLinks.Details {
		for _, p := range d.Paths {
			addPattern(p)
		}
		for _, comp := range d.Components {
			if !comp.Exclude {
				addPattern(comp.Path)
			}
		}
	}
	return c.out
}

// FromAssetLinks extracts linked web site origins named in an Android Digital
// Asset Links (/.well-known/assetlinks.json) array.
func FromAssetLinks(body []byte) []Found {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || len(body) > maxManifestBytes || body[0] != '[' {
		return nil
	}
	var items []struct {
		Target struct {
			Namespace string `json:"namespace"`
			Site      string `json:"site"`
		} `json:"target"`
	}
	if json.Unmarshal(body, &items) != nil {
		return nil
	}
	var c collector
	for _, it := range items {
		if len(c.out) >= 32 {
			break
		}
		if !strings.EqualFold(strings.TrimSpace(it.Target.Namespace), "web") {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(it.Target.Site))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		u.Fragment = ""
		c.addURL(Found{URL: u.String(), How: Link, Visit: true})
	}
	return c.out
}
