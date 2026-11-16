package export

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
)

// catalog pairs requests with the endpoints the code calls, by template,
// as the role diff does: the code knows a parameter's name, and which
// segments it computes.
type catalog struct {
	eps []catEP
}

type catEP struct {
	ep    endpoints.Endpoint
	paths []string // full templates: base + path
	res   []*regexp.Regexp
	fixed int
}

var placeRe = regexp.MustCompile(`\\\{[^}]*\\\}`)

func newCatalog(eps []endpoints.Endpoint, inScope func(string) bool) *catalog {
	c := &catalog{}
	for _, e := range eps {
		if e.ThirdParty || (e.Host != "" && !inScope(hostname(e.Host))) {
			continue
		}
		var paths []string
		switch {
		case e.Base != "":
			paths = []string{joinBasePath(e.Base, e.Path)}
		case len(e.Bases) > 0:
			for _, b := range e.Bases {
				if u, err := url.Parse(b); err == nil && u.Host != "" && e.Host != "" && !strings.EqualFold(hostname(e.Host), u.Hostname()) {
					continue
				}
				paths = append(paths, joinBasePath(b, e.Path))
			}
			paths = append(paths, strings.TrimPrefix(e.Path, "{}"))
		default:
			paths = []string{strings.TrimPrefix(e.Path, "{}")}
		}
		ce := catEP{ep: e}
		for _, p := range paths {
			p, _, _ = strings.Cut(p, "?")
			p = strings.TrimRight(p, "/")
			if fixedSegments(p) < 2 {
				continue // /api/{} of a wrapper says too little
			}
			ce.paths = append(ce.paths, p)
			ce.res = append(ce.res, regexp.MustCompile("^"+placeRe.ReplaceAllString(regexp.QuoteMeta(p), `[^/]+`)+"/?$"))
			ce.fixed = max(ce.fixed, len(placeholderRe.ReplaceAllString(p, "")))
		}
		if len(ce.res) > 0 {
			c.eps = append(c.eps, ce)
		}
	}
	return c
}

var placeholderRe = regexp.MustCompile(`\{[^}]*\}`)

func joinBasePath(base, path string) string {
	bp := strings.TrimRight(base, "/")
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		bp = strings.TrimRight(u.EscapedPath(), "/")
	}
	p := strings.TrimPrefix(path, "{}")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if bp != "" && (p == bp || strings.HasPrefix(p, bp+"/")) {
		return p
	}
	return bp + p
}

func fixedSegments(p string) int {
	n := 0
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s != "" && !strings.Contains(s, "{") {
			n++
		}
	}
	return n
}

// match returns the code's endpoint for a request, and the template that
// matched; the one with the most fixed text wins.
func (c *catalog) match(method, host, path string) (*endpoints.Endpoint, string) {
	var best *catEP
	bestPath := ""
	for i := range c.eps {
		ce := &c.eps[i]
		e := ce.ep
		if e.Method != "" && !strings.EqualFold(e.Method, method) {
			continue
		}
		if e.Host != "" && !strings.EqualFold(hostname(e.Host), hostname(host)) {
			continue
		}
		for j, re := range ce.res {
			if re.MatchString(path) && (best == nil || ce.fixed > best.fixed || (ce.fixed == best.fixed && e.Method != "" && best.ep.Method == "")) {
				best, bestPath = ce, ce.paths[j]
			}
		}
	}
	if best == nil {
		return nil, ""
	}
	return &best.ep, bestPath
}

// inJS tells whether the code names a param for its endpoint: nil when it
// cannot tell (the code lists no names for that place, or never names a
// path or a cookie).
func inJS(e *endpoints.Endpoint, p Param) *bool {
	if e == nil {
		return nil
	}
	var names []string
	name := p.Name
	switch p.In {
	case "query":
		names = e.Query
	case "header":
		name = strings.ToLower(name)
		for _, h := range e.Headers {
			names = append(names, strings.ToLower(h))
		}
	case "form", "multipart":
		names = e.Body
	case "json":
		names = e.Body
	default:
		return nil
	}
	if len(names) == 0 {
		return nil
	}
	yes := slices.Contains(names, name)
	if p.In == "json" {
		// The code's body names are flat: a top-level key or a leaf.
		top, leaf := jsonTopLeaf(p.Name)
		yes = slices.Contains(names, top) || slices.Contains(names, leaf)
	}
	return &yes
}

var indexRe = regexp.MustCompile(`\[\d+\]`)

func jsonTopLeaf(path string) (top, leaf string) {
	parts := strings.Split(strings.TrimPrefix(indexRe.ReplaceAllString(path, ""), "$."), ".")
	return parts[0], parts[len(parts)-1]
}

func hostname(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}
