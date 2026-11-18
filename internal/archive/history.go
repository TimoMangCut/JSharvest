package archive

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

type curScript struct {
	dir    string
	sha256 string
	url    string
}

// current is what the crawls of the target hold: the scripts' digests,
// their endpoint catalogs, and where their scripts are.
type current struct {
	sha1     map[string]bool
	bySHA1   map[string]curScript
	catalogs [][]endpoints.Endpoint
	jsDirs   []string
	roles    []string // host/role, for the notes
}

// loadCurrent reads every crawl directory of the target's hosts in scope:
// <root>/<host>/<role>, but the archive's own.
func loadCurrent(root string, inScope func(string) bool) *current {
	c := &current{sha1: map[string]bool{}, bySHA1: map[string]curScript{}}
	hosts, _ := os.ReadDir(root)
	for _, h := range hosts {
		if !h.IsDir() || !inScope(hostOnly(h.Name())) {
			continue
		}
		roles, _ := os.ReadDir(filepath.Join(root, h.Name()))
		for _, r := range roles {
			if !r.IsDir() || r.Name() == "archive" {
				continue
			}
			dir := filepath.Join(root, h.Name(), r.Name())
			if _, err := os.Stat(filepath.Join(dir, "index.jsonl")); err != nil {
				continue
			}
			c.roles = append(c.roles, h.Name()+"/"+r.Name())
			c.jsDirs = append(c.jsDirs, filepath.Join(dir, "js"))
			eachLine(filepath.Join(dir, "index.jsonl"), func(b []byte) {
				var e store.Entry
				if json.Unmarshal(b, &e) == nil && e.SHA1B32 != "" {
					c.sha1[e.SHA1B32] = true
					if e.SHA256 != "" {
						if _, exists := c.bySHA1[e.SHA1B32]; !exists {
							u := ""
							if len(e.URLs) > 0 {
								u = e.URLs[0]
							}
							c.bySHA1[e.SHA1B32] = curScript{dir: dir, sha256: e.SHA256, url: u}
						}
					}
				}
			})
			var cat []endpoints.Endpoint
			eachLine(filepath.Join(dir, endpoints.File), func(b []byte) {
				var e endpoints.Endpoint
				if json.Unmarshal(b, &e) == nil {
					cat = append(cat, e)
				}
			})
			// What the crawl sent, path by path: a wrapper's catalog line
			// (/api/v2{}) says nothing of which paths it serves.
			seen := map[string]bool{}
			eachLine(filepath.Join(dir, "requests.jsonl"), func(b []byte) {
				var e struct {
					Method, URL  string
					ResourceType string `json:"resource_type"`
				}
				if json.Unmarshal(b, &e) != nil {
					return
				}
				u, err := url.Parse(e.URL)
				if err != nil || !inScope(u.Hostname()) {
					return
				}
				p := flow.ByShape(u.EscapedPath())
				if k := e.Method + " " + p; !seen[k] {
					seen[k] = true
					cat = append(cat, endpoints.Endpoint{Method: e.Method, Path: p, Status: endpoints.ObservedOnly})
				}
			})
			c.catalogs = append(c.catalogs, cat)
		}
	}
	return c
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

func hostOnly(h string) string { return scope.TargetHost(h) }

// HistLine is a line of historical.jsonl.
type HistLine struct {
	// Class: historical (no crawl's code or traffic has it), version_changed
	// (the same path under another API version now), low (a template too
	// generic, or a bare string, to tell), in_current_code (today's
	// scripts write its path out, but no crawl's catalog calls it: a
	// document's text, code no crawl ran).
	Class  string `json:"class"`
	Method string `json:"method,omitempty"`
	Host   string `json:"host,omitempty"`
	Origin string `json:"origin,omitempty"`
	Path   string `json:"path"`
	Base   string `json:"base,omitempty"`
	// Bases are the clients' bases the old code names (axios's baseURL):
	// an archived script is read, never run, so its base is one of these,
	// never one traffic confirmed (ARC-07).
	Bases   []string `json:"bases,omitempty"`
	Kind    string   `json:"kind,omitempty"`
	Query   []string `json:"query,omitempty"`
	Body    []string `json:"body,omitempty"`
	Headers []string `json:"headers,omitempty"`
	// Params and Confidence are the catalog's (QAL-03, QAL-04).
	Params     []jsapi.ParamSpec `json:"params,omitempty"`
	Confidence string            `json:"confidence,omitempty"`
	Scripts    []HistScript      `json:"scripts"`
}

type HistScript struct {
	SHA256 string    `json:"sha256"`
	URL    string    `json:"url,omitempty"`
	First  time.Time `json:"first,omitzero"`
	Last   time.Time `json:"last,omitzero"`
	Alive  *bool     `json:"alive,omitempty"`
}

var versionRe = regexp.MustCompile(`(?i)/v\d+(\.\d+)?(/|$)`)

// classify sorts the archive's endpoints against the crawls': those the
// crawls have go; one whose fixed text is in a crawl's scripts goes too
// (the crawl did not reach it, but it is today's code).
func classify(archived []endpoints.Endpoint, cur *current, script func(sha string) (store.Entry, bool)) ([]HistLine, int) {
	lines, inCode, _ := classifyCtx(context.Background(), archived, cur, script)
	return lines, inCode
}

const maxLiveJSReadBytes = 32 << 20

type pendingHist struct {
	outIdx   int
	matchers []*pathMatcher
}

func compileEndpointMatchers(a endpoints.Endpoint) []*pathMatcher {
	ps := paths(a)
	var out []*pathMatcher
	for _, p := range ps {
		if m := compilePath(p); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func classifyCtx(ctx context.Context, archived []endpoints.Endpoint, cur *current, script func(sha string) (store.Entry, bool)) ([]HistLine, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	var catalogs [][]endpoints.Endpoint
	var jsDirs []string
	if cur != nil {
		catalogs = cur.catalogs
		jsDirs = cur.jsDirs
	}
	var out []HistLine
	var pending []pendingHist
	inCode := 0
	unverCats := unversionedAll(catalogs)
	for _, a := range archived {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if a.ThirdParty || matches(a, catalogs) {
			continue
		}
		class := "historical"
		var candMatchers []*pathMatcher
		switch {
		case matches(unversioned(a), unverCats):
			class = "version_changed"
		case weak(a):
			class = "low"
		default:
			candMatchers = compileEndpointMatchers(a)
		}
		l := HistLine{Class: class, Method: a.Method, Host: a.Host, Origin: a.Origin, Path: a.Path, Base: a.Base, Bases: a.Bases, Kind: a.Kind, Query: a.Query, Body: a.Body,
			Headers: a.Headers, Params: a.Params, Confidence: a.Confidence}
		seenScripts := map[string]bool{}
		for _, s := range a.Static {
			sk := s.SHA256 + "\x00" + s.Script
			if seenScripts[sk] {
				continue
			}
			seenScripts[sk] = true
			hs := HistScript{SHA256: s.SHA256, URL: s.Script}
			if e, ok := script(s.SHA256); ok {
				hs.Alive = e.Alive
				if e.Archive != nil {
					hs.First, hs.Last = e.Archive.First, e.Archive.Last
				}
			}
			l.Scripts = append(l.Scripts, hs)
		}
		idx := len(out)
		out = append(out, l)
		if len(candMatchers) > 0 {
			pending = append(pending, pendingHist{outIdx: idx, matchers: candMatchers})
		}
	}

	if len(pending) > 0 && len(jsDirs) > 0 {
		seenFiles := map[string]bool{}
		for _, d := range jsDirs {
			ents, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if err := ctx.Err(); err != nil {
					return nil, 0, err
				}
				name := e.Name()
				if len(name) == 67 && strings.HasSuffix(name, ".js") {
					if seenFiles[name] {
						continue
					}
					seenFiles[name] = true
				}
				if info, err := e.Info(); err == nil && (info.IsDir() || info.Size() > maxLiveJSReadBytes) {
					continue
				}
				b, err := os.ReadFile(filepath.Join(d, name))
				if err != nil || len(b) == 0 || len(b) > maxLiveJSReadBytes {
					continue
				}
				kept := pending[:0]
				for _, cand := range pending {
					matched := false
					for _, m := range cand.matchers {
						if m.matches(b) {
							matched = true
							break
						}
					}
					if matched {
						// Today's scripts write its path out, but the crawls' catalog
						// has no call to it (a document's text, code the crawl did not
						// run): kept, under its own class, never dropped (COV-01).
						out[cand.outIdx].Class = "in_current_code"
						inCode++
					} else {
						kept = append(kept, cand)
					}
				}
				pending = kept
				if len(pending) == 0 {
					break
				}
			}
			if len(pending) == 0 {
				break
			}
		}
	}
	return out, inCode, nil
}

// matches reports whether a catalog has an endpoint: a generic one of
// theirs (/api/v2{} of a wrapper) would match anything, and hide the
// history.
func matches(a endpoints.Endpoint, catalogs [][]endpoints.Endpoint) bool {
	for _, cat := range catalogs {
		for _, c := range cat {
			// A document's text naming the path is no call to it: that is
			// in_current_code's to say, as any text of today's scripts.
			if c.Kind == "doc" && c.Observed == nil {
				continue
			}
			if !generic(c) && sameEndpoint(a, c) {
				return true
			}
		}
	}
	return false
}

// unversioned writes an endpoint's API version as one fixed segment, v*:
// /v1.0/scooters/{} and /v2.0/scooters/{} are one. Not "v{}": a segment
// with a brace counts for no fixed one, and /v{}/users would be too
// generic to match by (ARC-08).
func unversioned(e endpoints.Endpoint) endpoints.Endpoint {
	e.Path = versionRe.ReplaceAllString(e.Path, "/v*$2")
	e.Base = versionRe.ReplaceAllString(e.Base, "/v*$2")
	bases := make([]string, len(e.Bases))
	for i, b := range e.Bases {
		bases[i] = versionRe.ReplaceAllString(b, "/v*$2")
	}
	e.Bases = bases
	return e
}

func unversionedAll(cats [][]endpoints.Endpoint) [][]endpoints.Endpoint {
	out := make([][]endpoints.Endpoint, len(cats))
	for i, cat := range cats {
		for _, e := range cat {
			out[i] = append(out[i], unversioned(e))
		}
	}
	return out
}

// files reads the crawls' scripts, for the fixed text of a path.
func (c *current) files() [][]byte {
	var out [][]byte
	for _, d := range c.jsDirs {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if b, err := os.ReadFile(filepath.Join(d, e.Name())); err == nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// inScripts reports whether today's scripts write an endpoint's path out:
// code the crawl did not run. The whole template is looked for, its fixed
// pieces with their slashes and in order: a piece alone (orders, /api/v1)
// is in any bundle (Reviewer round 5, NEW-5.3-03).
func inScripts(a endpoints.Endpoint, files [][]byte) bool {
	ok, _ := inScriptsCtx(context.Background(), a, files)
	return ok
}

func inScriptsCtx(ctx context.Context, a endpoints.Endpoint, files [][]byte) (bool, error) {
	for _, p := range paths(a) {
		m := compilePath(p)
		if m == nil {
			continue
		}
		for _, f := range files {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if m.matches(f) {
				return true, nil
			}
		}
	}
	return false, nil
}

type pathMatcher struct {
	re   *regexp.Regexp
	lits [][]byte
}

func (m *pathMatcher) matches(f []byte) bool {
	for _, lit := range m.lits {
		if !bytes.Contains(f, lit) {
			return false
		}
	}
	return m.re.Match(f)
}

// compilePath builds a matcher for a template's path as code writes it: a
// placeholder is a short run of what a path holds. Leading placeholders
// ({}/x, from an unresolved client base) are stripped so the regex anchors
// at the fixed path rather than running an unanchored wildcard across every
// byte of a bundle. A path a client takes relative to its base is written
// without its first slash, right after the quote ("system-user/v1.0/roles/{id}",
// ARC-09). Nil when its fixed text is too little to tell (8 characters).
func compilePath(p string) *pathMatcher {
	p, _, _ = strings.Cut(p, "?")
	p = leadPlaceRe.ReplaceAllString(p, "")
	pieces := placeRe.Split(p, -1)
	fixed := 0
	quoted := make([]string, len(pieces))
	var lits [][]byte
	for i, piece := range pieces {
		fixed += len(strings.Trim(piece, "/"))
		quoted[i] = regexp.QuoteMeta(piece)
		lit := piece
		if i == 0 {
			if rest, ok := strings.CutPrefix(piece, "/"); ok && rest != "" {
				quoted[0] = "(?:/|[\"'`])" + regexp.QuoteMeta(rest)
				lit = rest
			}
		}
		if lit != "" {
			lits = append(lits, []byte(lit))
		}
	}
	if fixed < 8 {
		return nil
	}
	sort.Slice(lits, func(i, j int) bool { return len(lits[i]) > len(lits[j]) })
	return &pathMatcher{
		re:   regexp.MustCompile(strings.Join(quoted, "[^\"'`\\s]{1,80}?")),
		lits: lits,
	}
}

var (
	placeRe     = regexp.MustCompile(`\{[^}]*\}`)
	leadPlaceRe = regexp.MustCompile(`^(?:/?\{[^}]*\})+`)
)

// weak reports whether an archived endpoint says too little to count: a
// bare string, or a template of fewer than two fixed segments, unless the
// code calls it with a method and a segment of its own name
// (GET /conversations of a client), which /api/{} of a wrapper has not.
func weak(a endpoints.Endpoint) bool {
	if a.Kind == "string" {
		return true
	}
	if !generic(a) {
		return false
	}
	if a.Method == "" || a.Kind == "doc" {
		return true
	}
	for _, seg := range split(a.Path) {
		if !strings.Contains(seg, "{") && !genericSegRe.MatchString(seg) {
			return false
		}
	}
	return true
}

// genericSegRe is a segment every API's paths have.
var genericSegRe = regexp.MustCompile(`(?i)^(?:api|apis|v\d+(?:\.\d+)*|rest|rpc|graphql|gql|services?|_api|json|ajax)$`)
