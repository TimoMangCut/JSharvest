package export

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// ParamLine is one line of params.jsonl: a parameter of an endpoint.
type ParamLine struct {
	Endpoint    string   `json:"endpoint"`
	In          string   `json:"in"`
	Name        string   `json:"name"`
	Index       int      `json:"index,omitempty"` // a path segment, from 1 after trimming the slashes
	Type        string   `json:"type,omitempty"`
	Samples     []string `json:"samples,omitempty"`
	Count       int      `json:"count"`
	Observed    bool     `json:"observed"`
	InJS        *bool    `json:"in_js"`
	DerivedFrom *Derived `json:"derived_from,omitempty"`
	Sensitive   bool     `json:"sensitive,omitempty"`
	Destructive bool     `json:"destructive,omitempty"`
	Flows       []string `json:"flows,omitempty"`
	Requests    []Ref    `json:"requests,omitempty"`
	File        string   `json:"file,omitempty"`
	Ffuf        string   `json:"ffuf,omitempty"`
	FfufFrom    *Ref     `json:"ffuf_from,omitempty"` // the request the ffuf file is made of
	FfufSkipped string   `json:"ffuf_skipped,omitempty"`
}

// Derived says a value was one an earlier response gave (flow's
// depends_on). Refresh is likely when a replay needs a fresh one: a
// credential's name, or a source that gave other values at other calls;
// unknown when it may be a value that stays (a user's id).
type Derived struct {
	From    string `json:"from"` // METHOD URL of the source, its query left out
	Request Ref    `json:"request"`
	At      string `json:"at"`
	Refresh string `json:"refresh"`
}

type Ref struct {
	Run string `json:"run"`
	ID  int    `json:"id"`
}

const (
	maxSamples = 5
	maxRefs    = 10
)

type paramAgg struct {
	line   ParamLine
	values map[string]bool
	items  []*item // the requests that have it, oldest first
}

// params gathers the params of each endpoint's requests.
func (x *exporter) params(groups map[string][]*item, order []string) []*paramAgg {
	byID := map[string]*item{}
	for _, it := range x.items {
		byID[fmt.Sprint(it.run, "/", it.e.ID)] = it
	}
	var out []*paramAgg
	// Cookies go with every request of a host: one line each, by host.
	cookies := map[string]*paramAgg{}
	var cookieKeys []string
	for _, key := range order {
		group := groups[key]
		aggs := map[string]*paramAgg{}
		var keys []string
		seen := map[string]bool{} // in + name, for the code's names
		for _, it := range group {
			segs := strings.Split(it.tmpl, "/")
			for _, p := range it.params {
				name := p.Name
				if p.In == "cookie" {
					u, _ := url.Parse(it.e.URL)
					k := u.Host + "\x00" + p.Name
					a := cookies[k]
					if a == nil {
						a = &paramAgg{line: ParamLine{Endpoint: "* " + u.Host, In: "cookie", Name: p.Name, Observed: true,
							Sensitive: traffic.Sensitive(p.Name)}, values: map[string]bool{}}
						cookies[k], cookieKeys = a, append(cookieKeys, k)
					}
					a.line.Count++
					if len(a.values) < 50 {
						a.values[p.Value] = true
					}
					if len(a.line.Samples) < maxSamples && !slices.Contains(a.line.Samples, p.Value) {
						a.line.Samples = append(a.line.Samples, p.Value)
					}
					if len(a.line.Requests) < maxRefs {
						a.line.Requests = append(a.line.Requests, Ref{it.run, it.e.ID})
					}
					continue
				}
				if p.In == "path" {
					if p.Index >= len(segs) || !strings.HasPrefix(segs[p.Index], "{") {
						continue // a name, not a value
					}
					name = segs[p.Index]
				}
				k := fmt.Sprint(p.In, "\x00", name, "\x00", p.Index)
				a := aggs[k]
				if a == nil {
					a = &paramAgg{line: ParamLine{Endpoint: key, In: p.In, Name: name, Index: p.Index, Observed: true,
						Sensitive: traffic.Sensitive(p.Name)}, values: map[string]bool{}}
					a.line.InJS = inJS(it.ep, p)
					aggs[k], keys = a, append(keys, k)
				}
				seen[p.In+"\x00"+p.Name] = true
				if top, _ := jsonTopLeaf(p.Name); p.In == "json" {
					seen["json\x00"+top] = true
				}
				a.line.Count++
				a.items = append(a.items, it)
				if len(a.values) < 50 {
					a.values[p.Value] = true
				}
				if len(a.line.Samples) < maxSamples && !slices.Contains(a.line.Samples, p.Value) {
					a.line.Samples = append(a.line.Samples, p.Value)
				}
				if len(a.line.Requests) < maxRefs {
					a.line.Requests = append(a.line.Requests, Ref{it.run, it.e.ID})
				}
				if it.flow != nil && !slices.Contains(a.line.Flows, it.flow.Action) {
					a.line.Flows = append(a.line.Flows, it.flow.Action)
				}
				if it.destr {
					a.line.Destructive = true
				}
				if from, ok := it.derived[p.At()]; ok && a.line.DerivedFrom == nil {
					a.line.DerivedFrom = x.derived(byID[fmt.Sprint(it.run, "/", from.Request)], it.run, from, p.Name)
				}
			}
		}
		for _, k := range keys {
			a := aggs[k]
			a.line.Type = typeOf(a.values, a.line)
			out = append(out, a)
		}
		// Names the code sends to the endpoint that no request carried.
		if ep := group[0].ep; ep != nil {
			hidden := func(in string, names []string) {
				for _, n := range names {
					if n == "" || seen[in+"\x00"+n] || (in == "header" && flow.PlainHeader(n)) {
						continue
					}
					if in == "body" && (seen["form\x00"+n] || seen["json\x00"+n] || seen["multipart\x00"+n]) {
						continue
					}
					yes := true
					seen[in+"\x00"+n] = true
					out = append(out, &paramAgg{line: ParamLine{Endpoint: key, In: in, Name: n, InJS: &yes,
						Sensitive: traffic.Sensitive(n), Destructive: group[0].destr}})
				}
			}
			hidden("query", ep.Query)
			hidden("body", ep.Body)
			hidden("header", lower(ep.Headers))
		}
	}
	for _, k := range cookieKeys {
		a := cookies[k]
		a.line.Type = typeOf(a.values, a.line)
		a.line.FfufSkipped = "a cookie: sent with every request to its host; fuzz it by hand on one endpoint"
		out = append(out, a)
	}
	return out
}

func lower(xs []string) []string {
	out := make([]string, len(xs))
	for i, s := range xs {
		out[i] = strings.ToLower(s)
	}
	return out
}

// derived describes the source of a value: whether a replay needs a fresh
// one.
func (x *exporter) derived(src *item, run string, from flow.LinkEnd, name string) *Derived {
	d := &Derived{Request: Ref{run, from.Request}, At: from.At, Refresh: "unknown"}
	if src == nil {
		return d
	}
	d.From = sourceKey(src.e)
	if traffic.Sensitive(name) || x.varies(d.From, from.At) {
		d.Refresh = "likely"
	}
	return d
}

// varies reports whether the requests of a source gave other values at
// one place on other calls.
func (x *exporter) varies(source, at string) bool {
	return len(x.srcVals[source][at]) > 1
}

// sourceKey names the source of a value: method and URL, its query left
// out.
func sourceKey(e traffic.Entry) string {
	u, err := url.Parse(e.URL)
	if err != nil {
		return e.Method + " " + e.URL
	}
	u.RawQuery, u.Fragment = "", ""
	return e.Method + " " + u.String()
}

var (
	intRe   = regexp.MustCompile(`^-?\d+$`)
	floatRe = regexp.MustCompile(`^-?\d+\.\d+([eE][-+]?\d+)?$`)
	uuidRe  = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	jwtRe   = regexp.MustCompile(`^eyJ[\w-]+\.[\w-]+\.[\w-]*$`)
	emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$`)
	urlRe   = regexp.MustCompile(`^(?i)(https?:)?//\S+$|^/[\w./%-]*$`)
	dateRe  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([T ][\d:.]+(Z|[+-]\d{2}:?\d{2})?)?$`)
	hexRe   = regexp.MustCompile(`^(?i)[0-9a-f]{8,}$`)
	b64Re   = regexp.MustCompile(`^[A-Za-z0-9+/_-]{16,}={0,2}$`)
	gqlRe   = regexp.MustCompile(`^\s*(query|mutation|subscription|fragment)\b|^\s*\{`)
)

// typeOf is the type of a param's values: the one they share, or the
// widest (int and float are float; the rest is string).
func typeOf(values map[string]bool, l ParamLine) string {
	types := map[string]bool{}
	for v := range values {
		types[valueType(v, l)] = true
	}
	delete(types, "empty")
	switch {
	case len(types) == 0:
		return "empty"
	case len(types) == 1:
		for t := range types {
			return t
		}
	case len(types) == 2 && types["int"] && types["float"]:
		return "float"
	}
	return "string"
}

func valueType(v string, l ParamLine) string {
	switch {
	case v == "":
		return "empty"
	case v == "true" || v == "false":
		return "bool"
	case l.In == "json" && v == "null":
		return "empty"
	case intRe.MatchString(v):
		return "int"
	case floatRe.MatchString(v):
		return "float"
	case uuidRe.MatchString(v):
		return "uuid"
	case jwtRe.MatchString(v):
		return "jwt"
	case emailRe.MatchString(v):
		return "email"
	case dateRe.MatchString(v):
		return "date"
	case isQueryName(l.Name) && gqlRe.MatchString(v):
		return "graphql"
	case urlRe.MatchString(v):
		return "url"
	case hexRe.MatchString(v) && strings.ContainsAny(v, "0123456789"):
		return "hex"
	case (strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[")) && json.Valid([]byte(v)):
		return "json"
	case b64Re.MatchString(v) && strings.ContainsAny(v, "0123456789") && strings.ToLower(v) != v && strings.ToUpper(v) != v:
		return "base64"
	}
	return "string"
}

// sortParams orders params.jsonl: by endpoint, then place, then name.
func sortParams(ps []*paramAgg) {
	rank := map[string]int{"path": 0, "query": 1, "json": 2, "form": 3, "multipart": 4, "body": 5, "header": 6, "cookie": 7}
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i].line, ps[j].line
		if a.Endpoint != b.Endpoint {
			return a.Endpoint < b.Endpoint
		}
		if rank[a.In] != rank[b.In] {
			return rank[a.In] < rank[b.In]
		}
		if a.Index != b.Index {
			return a.Index < b.Index
		}
		return a.Name < b.Name
	})
}

// isQueryName tells the "query" of a GraphQL body: $.query, or $[n].query
// in a batch's element.
func isQueryName(name string) bool {
	if name == "$.query" {
		return true
	}
	rest, ok := strings.CutPrefix(name, "$[")
	if !ok || !strings.HasSuffix(rest, "].query") {
		return false
	}
	n := strings.TrimSuffix(rest, "].query")
	return n != "" && strings.Trim(n, "0123456789") == ""
}
