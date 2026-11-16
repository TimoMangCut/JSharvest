package endpoints

// This file: deferred URLs (round 27A). A script's request whose URL calls
// a function another module exports (jsapi.Deferred) is joined with that
// module's URL builder (jsapi.Builder): the module found as linkModules
// finds an import's (ESM URL, source map path, re-exports, a tree-shaken
// barrel's local name), the builder evaluated with the call's arguments in
// the exporting script's own source (jsapi.EvalBuilder), each value put in
// the call's place. What cannot be joined adds nothing: the caller's
// script listed the request already with the call's value unknown.

import (
	"fmt"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// maxDeferredDepth bounds the re-exports followed to a builder.
const maxDeferredDepth = 8

type builderRef struct {
	tid  int
	name string
}

func linkDeferred(scripts []Script, byKey map[string]*Endpoint, order *[]string, origins map[*Endpoint]map[string]bool,
	targetScripts func(int, string) ([]int, bool)) {
	evalMemo := map[string][]string{}
	// Each exporting module is read once (parsed, its definitions read),
	// whatever the number of calls and arguments it serves.
	modMemo := map[int]*jsapi.Module{}
	var find func(curIdx int, spec, name string, depth int, seen map[string]bool) []builderRef
	find = func(curIdx int, spec, name string, depth int, seen map[string]bool) []builderRef {
		if depth > maxDeferredDepth {
			return nil
		}
		var out []builderRef
		tids, allowLocal := targetScripts(curIdx, spec)
		for _, tid := range tids {
			k := fmt.Sprintf("%d\x00%s", tid, name)
			if seen[k] {
				continue
			}
			seen[k] = true
			ts := scripts[tid]
			matched := false
			for _, b := range ts.Builders {
				if b.Name == name {
					out = append(out, builderRef{tid, b.Name})
					matched = true
				}
			}
			for _, re := range ts.ReExports {
				switch {
				case re.All:
					out = append(out, find(tid, re.Module, name, depth+1, seen)...)
				case re.Name == name && re.Target != "" && re.Target != "*":
					out = append(out, find(tid, re.Module, re.Target, depth+1, seen)...)
					matched = true
				}
			}
			if !matched && allowLocal {
				for _, b := range ts.Builders {
					if b.Local == name {
						out = append(out, builderRef{tid, b.Name})
					}
				}
			}
		}
		return out
	}
	for callerIdx, s := range scripts {
		if isTrackerScript(s) || len(s.Deferred) == 0 {
			continue
		}
		scriptURL := ""
		if len(s.URLs) > 0 {
			scriptURL = s.URLs[0]
		}
		for _, d := range s.Deferred {
			for _, ref := range find(callerIdx, d.Module, d.Name, 0, map[string]bool{}) {
				ts := scripts[ref.tid]
				if ts.Load == nil {
					continue
				}
				mk := fmt.Sprintf("%d\x00%s\x00%q", ref.tid, ref.name, d.Args)
				vals, ok := evalMemo[mk]
				if !ok {
					m, have := modMemo[ref.tid]
					if !have {
						if src := ts.Load(); len(src) > 0 {
							m = jsapi.PrepareModule(src)
						}
						modMemo[ref.tid] = m
					}
					if m != nil {
						vals = m.EvalBuilder(ref.name, d.Args)
					}
					evalMemo[mk] = vals
				}
				for _, v := range vals {
					if unknownOrigin(v) {
						// `${base(e)}${e.projectId}/envelope/`: a value led by
						// what the builder does not know (a host, a base)
						// joins a value to the unknown, as withBase(e) does;
						// it says nothing of where the request goes.
						continue
					}
					u := jsapi.CleanURL(strings.Replace(d.URL, jsapi.DeferredSlot, v, 1))
					u, _, _ = strings.Cut(u, "?")
					if !jsapi.NamedPath(u) {
						continue // /{}/{}: a way of the builder that names nothing
					}
					urls := []string{u}
					prefixed := len(d.Pre) > 0 && strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//")
					if prefixed {
						// A path of the page's origin: the client's prefix
						// first (axios.create({baseURL: "/api"})).
						urls = urls[:0]
						for _, p := range d.Pre {
							urls = append(urls, strings.TrimSuffix(p, "/")+u)
						}
					}
					for _, u := range urls {
						// A client's path waits for the client's base; one its
						// prefix made whole (a path of the page's origin, a URL)
						// does not, as jsapi has it (ownPrefix).
						host0, p0 := split(u)
						isClient := !prefixed && d.Kind == "client" && host0 == "" && strings.HasPrefix(p0, "/") || strings.HasPrefix(p0, unknownPrefix)
						host, p := host0, p0
						key := d.Method + " " + host + " " + p
						ep := byKey[key]
						if ep == nil {
							ep = &Endpoint{Method: d.Method, Host: host, Path: p, Status: Static, Kind: "wrapper",
								ThirdParty: isTrackerScript(s), client: isClient}
							byKey[key] = ep
							*order = append(*order, key)
						}
						if ep.Kind == "string" || ep.Kind == "doc" {
							ep.Kind = "wrapper"
						}
						ep.bundleStatic = ep.bundleStatic || !s.Source
						ep.Query = append(ep.Query, d.Query...)
						ep.Body = append(ep.Body, d.Body...)
						ep.Headers = append(ep.Headers, d.Headers...)
						if ep.client {
							if origins[ep] == nil {
								origins[ep] = map[string]bool{}
							}
							for _, cu := range s.URLs {
								origins[ep][originOf(cu)] = true
							}
						}
						if len(ep.Static) < maxSources {
							ep.Static = append(ep.Static, Source{SHA256: s.SHA256, Script: scriptURL, Line: d.Line, Col: d.Col, Kind: "import", Snippet: d.Snippet})
						}
					}
				}
			}
		}
	}
}

// unknownOrigin reports whether a URL is led by what is not known: {} first,
// or a host ("//{}/api/", "https://{}.example") with {} in it.
func unknownOrigin(v string) bool {
	if strings.HasPrefix(v, placeholder) {
		return true
	}
	rest := ""
	switch {
	case strings.HasPrefix(v, "//"):
		rest = v[2:]
	case strings.Contains(v, "://"):
		_, rest, _ = strings.Cut(v, "://")
	default:
		return false
	}
	host, _, _ := strings.Cut(rest, "/")
	return host == "" || strings.Contains(host, placeholder)
}
