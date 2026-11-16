package monitor

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/archive"
	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// Endpoint is an endpoint as monitor compares it: a normalised template,
// what names it, and how the role's requests to it fared.
type Endpoint struct {
	Method string `json:"method,omitempty"`
	Host   string `json:"host"`
	Path   string `json:"path"` // placeholders as {}
	Op     string `json:"op,omitempty"`
	Code   bool   `json:"code,omitempty"`
	// Traffic: the runs sent it.
	Traffic bool            `json:"traffic,omitempty"`
	Params  map[string]bool `json:"params,omitempty"`
	OK      int             `json:"ok,omitempty"`      // 2xx answers
	Refused int             `json:"refused,omitempty"` // 401, 403, a login page
	Scripts []string        `json:"scripts,omitempty"` // canonical keys of the scripts that call it
}

// Key names an endpoint in a report.
func (e *Endpoint) Key() string {
	k := e.Method
	if k == "" {
		k = "*"
	}
	k += " " + e.Host + e.Path
	if e.Op != "" {
		k += " " + e.Op
	}
	return k
}

func (e *Endpoint) catalog() endpoints.Endpoint {
	return endpoints.Endpoint{Method: e.Method, Host: e.Host, Path: e.Path}
}

// same reports whether two endpoints are one: their templates unify, and
// their operations (a GraphQL one, an RPC action) are the same.
func same(a, b *Endpoint) bool {
	return a.Op == b.Op && archive.SameEndpoint(a.catalog(), b.catalog())
}

// Content is what a role's runs saw.
type Content struct {
	Scripts   map[string][]string // canonical key -> SHA-256s, of files
	Endpoints []*Endpoint
	Hosts     map[string]bool
}

var placeRe = regexp.MustCompile(`\{[^}]*\}`)

// normPath writes a template as monitor compares it: by shape, every
// placeholder {}.
func normPath(p string) string {
	p, _, _ = strings.Cut(p, "?")
	return placeRe.ReplaceAllString(flow.ByShape(p), "{}")
}

// apiTypes are the requests that call endpoints.
var apiTypes = map[string]bool{"Fetch": true, "XHR": true, "EventSource": true, "Ping": true, "": true}

// build reads a role's content for some of its runs: their scripts and
// requests, with today's code.
func build(dir string, runs []string, target string, inScope func(string) bool) (*Content, error) {
	c := &Content{Scripts: map[string][]string{}, Hosts: map[string]bool{}}
	shas := map[string]bool{}
	byRun := map[string]bool{}
	for _, r := range runs {
		byRun[r] = true
	}
	for _, r := range readRuns(dir) {
		if byRun[r.RunID] {
			for _, s := range r.Scripts {
				shas[s] = true
			}
		}
	}
	targetHost := ""
	if u, err := url.Parse(target); err == nil {
		targetHost = u.Host
	}

	// Scripts: files only; an inline one changes with every page.
	keyOf := map[string]string{}
	eachLine(filepath.Join(dir, "index.jsonl"), func(b []byte) {
		var e store.Entry
		if json.Unmarshal(b, &e) != nil || !shas[e.SHA256] || ownOrThirdParty(e) {
			return
		}
		if len(e.CanonicalKeys) == 0 {
			return
		}
		keyOf[e.SHA256] = e.CanonicalKeys[0]
		if slices.Contains(e.Kinds, "file") {
			k := e.CanonicalKeys[0]
			c.Scripts[k] = appendNew(c.Scripts[k], e.SHA256)
		}
	})
	for _, v := range c.Scripts {
		sort.Strings(v)
	}

	// Endpoints in the code of those scripts.
	scripts, err := endpoints.Analyze(dir, 0)
	if err != nil {
		return nil, err
	}
	var mine []endpoints.Script
	for _, s := range scripts {
		if shas[s.SHA256] && !s.ThirdParty {
			mine = append(mine, s)
		}
	}
	for _, e := range endpoints.Build(mine, nil, inScope) {
		if e.ThirdParty || archive.Generic(e) {
			continue
		}
		host := e.Host
		if host == "" || host == "{}" {
			host = targetHost
		}
		path := e.Path
		if e.Base != "" {
			path = e.Base + e.Path
		} else if len(e.Bases) == 1 {
			path = e.Bases[0] + e.Path
		}
		ep := &Endpoint{Method: e.Method, Host: host, Path: normPath(path), Code: true, Params: map[string]bool{}}
		for _, n := range append(append(append([]string{}, e.Query...), e.Body...), e.Headers...) {
			if n := paramName(n); n != "" {
				ep.Params[n] = true
			}
		}
		for _, s := range e.Static {
			if k := keyOf[s.SHA256]; k != "" {
				ep.Scripts = appendNew(ep.Scripts, k)
			}
		}
		ops := e.Operations
		if len(ops) == 0 {
			c.add(ep)
			continue
		}
		for _, o := range ops {
			f := strings.Fields(o)
			cp := *ep
			cp.Op = "op=" + f[len(f)-1]
			c.add(&cp)
		}
	}

	// What the runs sent.
	d := results.Open(dir)
	if err := d.Refresh(); err != nil {
		return nil, err
	}
	seen := map[string]int{} // key|param -> requests that had it
	for _, run := range runs {
		for _, q := range d.Requests(run) {
			if q.Internal || !apiTypes[q.ResourceType] {
				continue
			}
			u, err := url.Parse(q.URL)
			if err != nil || !inScope(u.Hostname()) {
				continue
			}
			c.Hosts[u.Host] = true
			e, err := d.Entry(run, q.ID)
			if err != nil {
				continue
			}
			ct := e.Headers["content-type"]
			// A GraphQL batch is one request at many endpoints: each
			// operation is filed with the params of its own element.
			type opBody struct{ op, body string }
			sends := []opBody{{flow.OperationWithHeaders(u, e.Headers, ct, e.Body.Body), e.Body.Body}}
			if parts := flow.SplitBatch(e.Body.Body); parts != nil {
				sends = sends[:0]
				for _, p := range parts {
					sends = append(sends, opBody{p.Op, p.Body})
				}
			}
			for _, sd := range sends {
				ep := &Endpoint{Method: q.Method, Host: u.Host, Path: normPath(u.EscapedPath()), Traffic: true, Params: map[string]bool{},
					Op: sd.op}
				got := c.add(ep)
				switch s := q.Status; {
				case s >= 200 && s < 300:
					got.OK++
				case s == 401 || s == 403:
					got.Refused++
				}
				for _, n := range requestParams(u, ct, sd.body) {
					seen[got.Key()+"|"+n]++
					if seen[got.Key()+"|"+n] >= 2 {
						got.Params[n] = true // a name seen once in traffic is no sign
					}
				}
			}
		}
	}
	return c, nil
}

// add files an endpoint, merged with one already there: the one there.
func (c *Content) add(ep *Endpoint) *Endpoint {
	for _, o := range c.Endpoints {
		if same(o, ep) {
			o.Code = o.Code || ep.Code
			o.Traffic = o.Traffic || ep.Traffic
			for n := range ep.Params {
				o.Params[n] = true
			}
			for _, s := range ep.Scripts {
				o.Scripts = appendNew(o.Scripts, s)
			}
			if o.Method == "" {
				o.Method = ep.Method
			}
			return o
		}
	}
	c.Endpoints = append(c.Endpoints, ep)
	return ep
}

// cacheBusters are parameters that only defeat caches and count visits.
var cacheBusters = map[string]bool{"_": true, "t": true, "ts": true, "v": true, "cb": true, "gclid": true, "fbclid": true, "nocache": true, "rnd": true}

var digitsRe = regexp.MustCompile(`\d+`)

// paramName normalises a parameter's name: digits and indices as #, a
// cache-buster none.
func paramName(n string) string {
	n = strings.TrimSpace(n)
	if n == "" || cacheBusters[strings.ToLower(n)] || strings.HasPrefix(strings.ToLower(n), "utm_") {
		return ""
	}
	return digitsRe.ReplaceAllString(n, "#")
}

// requestParams are a request's parameter names: query, JSON (dotted),
// form.
func requestParams(u *url.URL, ct, body string) []string {
	var out []string
	for k := range u.Query() {
		out = append(out, k)
	}
	body = strings.TrimSpace(body)
	switch {
	case strings.Contains(ct, "json") || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "["):
		var v any
		if json.Unmarshal([]byte(body), &v) == nil {
			jsonNames(v, "", &out, 0)
		}
	case strings.Contains(ct, "x-www-form-urlencoded"):
		if f, err := url.ParseQuery(body); err == nil {
			for k := range f {
				out = append(out, k)
			}
		}
	}
	var norm []string
	for _, n := range out {
		if n := paramName(n); n != "" {
			norm = appendNew(norm, n)
		}
	}
	return norm
}

func jsonNames(v any, prefix string, out *[]string, depth int) {
	if depth > 6 || len(*out) > 200 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			*out = append(*out, prefix+k)
			jsonNames(y, prefix+k+".", out, depth+1)
		}
	case []any:
		for _, y := range x {
			jsonNames(y, prefix, out, depth+1)
		}
	}
}

func ownOrThirdParty(e store.Entry) bool {
	for _, t := range e.Tags {
		if t == "third-party" || strings.Contains(t, "jsharvest") {
			return true
		}
	}
	return false
}

func eachLine(p string, f func([]byte)) {
	file, err := os.Open(p)
	if err != nil {
		return
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		f(sc.Bytes())
	}
}
