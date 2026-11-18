// Package verify turns the catalog into draft requests (VER-01) and asks
// the target which of them are alive, against a canary of each gateway
// prefix (VER-02, VER-03): read-only by default, every request through
// replay.Sender (see docs/gd6-waf-design.md, 20).
package verify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/archive"
	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Tiers of a draft.
const (
	Ready         = "ready"         // one URL, a method, every part known
	Parameterized = "parameterized" // one URL, a method, sample values filled in
	Incomplete    = "incomplete"    // no method, or no one URL
)

// Draft is a request the catalog says the target takes, written out.
type Draft struct {
	ID     string `json:"id"`
	Source string `json:"source"` // catalog or historical
	Method string `json:"method"`
	Path   string `json:"path"` // the catalog's, {} kept
	// URL is the one URL it goes to, sample values in; Candidates the
	// URLs it may go to when its base is unknown (a document's line).
	URL        string   `json:"url,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	// CandidateBases are the bases of Candidates, one each.
	CandidateBases []string `json:"candidate_bases,omitempty"`
	Tier           string   `json:"tier"`
	Confidence     string   `json:"confidence,omitempty"`
	Kind           string   `json:"kind,omitempty"`
	ThirdParty     bool     `json:"third_party,omitempty"`
	SourceOnly     bool     `json:"source_only,omitempty"`
	// Filled are the parts given sample values (not the code's own).
	Filled []string          `json:"filled,omitempty"`
	Query  map[string]string `json:"query,omitempty"`
	Body   json.RawMessage   `json:"body,omitempty"`
	// Headers are the client's own (intel.json) and the line's, with
	// the values the code gives, or a sample.
	Headers [][2]string `json:"headers,omitempty"`
	// SampleHeaders are the headers whose value is a sample in place of
	// what the code computes (Authorization: Bearer {}): the identity's.
	// A file keeps them, to be filled by hand; verify sends the role's
	// own, or none (POL-23-2).
	SampleHeaders []string `json:"sample_headers,omitempty"`
	Why           string   `json:"why,omitempty"` // why incomplete
	// Operation is the GraphQL operation or RPC action ("op=Name") of a
	// draft made for one of the many an endpoint serves: one draft each.
	Operation string `json:"operation,omitempty"`
	// GraphQLWrite marks a draft synthesized from a static GraphQL mutation or
	// subscription so verify skips it unless -allow-write is set.
	GraphQLWrite bool `json:"graphql_write,omitempty"`
}

// Raw is the draft as an HTTP/1.1 request (origin-form, Host first, CRLF),
// for url (its URL, or a candidate); http.ReadRequest reads it.
func (d Draft) Raw(target string) ([]byte, error) { return d.raw(target, false) }

func applyGraphQLDoc(d *Draft, gd jsapi.GraphQLDoc) {
	if d.Method == "" {
		d.Method = "POST"
	}
	vars := make(map[string]any, len(gd.Vars))
	for _, v := range gd.Vars {
		vars[v.Name] = sampleGQLVar(v.Name, v.Type)
	}
	payload := map[string]any{
		"operationName": gd.Name,
		"query":         gd.Query,
		"variables":     vars,
	}
	if b, err := json.Marshal(payload); err == nil {
		d.Body = b
	}
	if len(gd.Vars) > 0 {
		d.Filled = slices.Clone(d.Filled)
		if !slices.Contains(d.Filled, "body.variables") {
			d.Filled = append(d.Filled, "body.variables")
		}
		if d.Tier == Ready {
			d.Tier = Parameterized
		}
	}
	if gd.Kind == "mutation" || gd.Kind == "subscription" {
		d.GraphQLWrite = true
	}
}

func sampleGQLVar(name, typ string) any {
	clean := strings.TrimSuffix(strings.TrimSpace(typ), "!")
	if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
		return []any{}
	}
	switch clean {
	case "Int":
		return 1
	case "Float":
		return 1.0
	case "Boolean":
		return false
	case "ID":
		if strings.Contains(strings.ToLower(name), "uuid") || strings.Contains(strings.ToLower(name), "guid") {
			return sampleUUID
		}
		return "1"
	}
	ln := strings.ToLower(name)
	switch {
	case strings.Contains(ln, "uuid") || strings.Contains(ln, "guid"):
		return sampleUUID
	case strings.HasSuffix(ln, "id"):
		return "1"
	case strings.Contains(ln, "date") || strings.Contains(strings.ToLower(clean), "date") || strings.Contains(strings.ToLower(clean), "time"):
		return "2026-01-01T00:00:00Z"
	}
	return "sample"
}

func isValidDraftToken(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

func hasHTTPControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return true
		}
	}
	return false
}

func cleanHTTPField(s string) string {
	if !hasHTTPControlByte(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// raw writes it; bare leaves the sample headers out.
func (d Draft) raw(target string, bare bool) ([]byte, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("draft %s: bad URL %q", d.ID, target)
	}
	method := strings.TrimSpace(d.Method)
	if method == "" || !isValidDraftToken(method) {
		method = "GET"
	}
	reqURI := cleanHTTPField(u.RequestURI())
	host := cleanHTTPField(u.Host)
	var b bytes.Buffer
	b.WriteString(method + " " + reqURI + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	if !slices.ContainsFunc(d.Headers, func(h [2]string) bool { return strings.EqualFold(strings.TrimSpace(h[0]), "accept") }) {
		b.WriteString("Accept: application/json, */*\r\n")
	}
	for _, h := range d.Headers {
		name := strings.TrimSpace(h[0])
		if !isValidDraftToken(name) {
			continue
		}
		if bare && slices.ContainsFunc(d.SampleHeaders, func(n string) bool { return strings.EqualFold(n, name) }) {
			continue
		}
		val := strings.TrimSpace(cleanHTTPField(h[1]))
		if hasHTTPControlByte(h[1]) && val == "" {
			continue
		}
		b.WriteString(name + ": " + val + "\r\n")
	}
	if len(d.Body) > 0 {
		b.WriteString("Content-Type: application/json\r\n")
		b.WriteString("Content-Length: " + strconv.Itoa(len(d.Body)) + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(d.Body)
	return b.Bytes(), nil
}

// Inputs are what drafts are made from.
type Inputs struct {
	Catalog    []endpoints.Endpoint
	Intel      endpoints.Intel
	Historical []archive.HistLine // with -include-historical
	InScope    func(host string) bool
}

// Load reads a role's catalog and intel.json, and the host's
// historical.jsonl when historical is set.
func Load(roleDir, archiveDir string, historical bool) (Inputs, error) {
	var in Inputs
	f, err := os.Open(filepath.Join(roleDir, endpoints.File))
	if err != nil {
		return in, fmt.Errorf("no catalog in %s (jsharvest endpoints writes it): %w", roleDir, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var e endpoints.Endpoint
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			in.Catalog = append(in.Catalog, e)
		}
	}
	if err := sc.Err(); err != nil {
		return in, err
	}
	if b, err := os.ReadFile(filepath.Join(roleDir, endpoints.IntelFile)); err == nil {
		json.Unmarshal(b, &in.Intel)
	}
	if historical {
		if hf, err := os.Open(filepath.Join(archiveDir, "historical.jsonl")); err == nil {
			defer hf.Close()
			hs := bufio.NewScanner(hf)
			hs.Buffer(make([]byte, 1<<20), 64<<20)
			for hs.Scan() {
				var h archive.HistLine
				if json.Unmarshal(hs.Bytes(), &h) == nil {
					in.Historical = append(in.Historical, h)
				}
			}
		}
	}
	return in, nil
}

// maxCandidates bounds the bases a line with none is tried under (0: unlimited).
const maxCandidates = 0

// Drafts writes every line of the catalog (and the historical ones) out.
func Drafts(in Inputs) []Draft {
	var out []Draft
	seen := map[string]bool{}
	add := func(d Draft) {
		k := d.Method + " " + d.URL + " " + strings.Join(d.Candidates, ",") + " " + d.Path
		if d.Operation != "" {
			k += " " + d.Operation
		}
		if seen[k] {
			return
		}
		seen[k] = true
		d.ID = fmt.Sprintf("%04d", len(out)+1)
		out = append(out, d)
	}
	bases := candidateBases(in)
	originLangs := inferOriginLanguages(in.Catalog)
	intelDocs := map[string]jsapi.GraphQLDoc{}
	for _, gd := range in.Intel.GraphQLDocs {
		if _, exists := intelDocs[gd.Name]; !exists {
			intelDocs[gd.Name] = gd
		}
	}
	for _, e := range in.Catalog {
		d := draftOfWithLangs(lineOf(e, in.InScope, in.Intel), "catalog", bases, in, originLangs)
		epDocs := map[string]jsapi.GraphQLDoc{}
		for _, gd := range e.GraphQLDocs {
			epDocs[gd.Name] = gd
		}
		// An endpoint of many operations (a GraphQL batch's, an RPC's):
		// a draft for each, or the dedup key would merge them.
		var ops []string
		for _, o := range e.Operations {
			if strings.HasPrefix(o, "next-action=") {
				if !slices.Contains(ops, o) {
					ops = append(ops, o)
				}
				continue
			}
			if f := strings.Fields(o); len(f) > 0 && !slices.Contains(ops, "op="+f[len(f)-1]) {
				ops = append(ops, "op="+f[len(f)-1])
			}
		}
		if len(ops) == 0 {
			add(d)
			continue
		}
		for _, o := range ops {
			cp := d
			cp.Operation = o
			if actHex, ok := strings.CutPrefix(o, "next-action="); ok {
				cp.Headers = slices.Clone(d.Headers)
				replaced := false
				for hi := range cp.Headers {
					if strings.EqualFold(cp.Headers[hi][0], "next-action") {
						cp.Headers[hi] = [2]string{"Next-Action", actHex}
						replaced = true
					}
				}
				if !replaced {
					cp.Headers = append(cp.Headers, [2]string{"Next-Action", actHex})
				}
				cp.Filled = slices.DeleteFunc(slices.Clone(d.Filled), func(s string) bool {
					return strings.EqualFold(s, "header.next-action")
				})
				if cp.Tier == Parameterized && len(cp.Filled) == 0 {
					cp.Tier = Ready
				}
			} else if opName, ok := strings.CutPrefix(o, "op="); ok {
				gd, hasDoc := epDocs[opName]
				if !hasDoc {
					gd, hasDoc = intelDocs[opName]
				}
				if hasDoc && gd.Query != "" {
					applyGraphQLDoc(&cp, gd)
				}
			}
			add(cp)
		}
	}
	for _, h := range in.Historical {
		if h.Class == "low" {
			continue // a template too generic, or a bare string
		}
		static := make([]endpoints.Source, 0, len(h.Scripts))
		for _, s := range h.Scripts {
			if s.SHA256 != "" || s.URL != "" {
				static = append(static, endpoints.Source{SHA256: s.SHA256, Script: s.URL})
			}
		}
		he := endpoints.Endpoint{
			Method: h.Method, Host: h.Host, Origin: h.Origin, Path: h.Path,
			Base: h.Base, Bases: h.Bases, Kind: h.Kind, Query: h.Query,
			Body: h.Body, Headers: h.Headers, Params: h.Params,
			Confidence: h.Confidence, Static: static,
		}
		if he.Confidence == "" {
			he.Confidence = "code"
		}
		l := lineOf(he, in.InScope, in.Intel)
		add(draftOfWithLangs(l, "historical", bases, in, originLangs))
	}
	return out
}

// line is what a draft takes of a catalog's or historical line.
type line struct {
	Method, Host, Path, Base, Origin, Kind, Confidence string
	// Bases, Query, Body, Headers                        []string
	Bases, Query, Body, Headers []string
	Params                      []jsapi.ParamSpec
	Static                      []endpoints.Source
	ThirdParty                  bool
	SourceOnly                  bool
	Samples                     []string
}

func lineOf(e endpoints.Endpoint, inScope func(string) bool, intel endpoints.Intel) line {
	l := line{Method: e.Method, Host: e.Host, Path: e.Path, Base: e.Base, Origin: e.Origin, Kind: e.Kind, Confidence: e.Confidence,
		Bases: slices.Clone(e.Bases), Query: e.Query, Body: e.Body, Headers: e.Headers, Params: e.Params, Static: e.Static, ThirdParty: e.ThirdParty, SourceOnly: e.SourceOnly}
	if e.Observed != nil {
		l.Samples = e.Observed.Samples
	}
	// ENH-01: when an endpoint has an explicit/observed cross-origin Host,
	// resolve relative Base/Bases against that Host rather than scriptOrigin.
	if e.Host != "" && !strings.Contains(e.Host, "{") {
		ho := hostOriginFor(e.Host, l.Samples, intel.Bases, e.Static)
		for i, b := range l.Bases {
			if strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
				l.Bases[i] = ho + b
			}
		}
		if strings.HasPrefix(l.Base, "/") && !strings.HasPrefix(l.Base, "//") {
			l.Base = ho + l.Base
		}
	} else {
		so := scriptOrigin(e.Static, inScope)
		if so != "" {
			for i, b := range l.Bases {
				if strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
					l.Bases[i] = so + b
				}
			}
		}
		if strings.HasPrefix(l.Base, "/") && !strings.HasPrefix(l.Base, "//") {
			if e.Observed != nil || e.Status == endpoints.Both || so == "" {
				if io := uniqueIntelOriginForBase(l.Base, so, intel.Bases, inScope); io != "" {
					l.Base = io + l.Base
				}
			}
			if strings.HasPrefix(l.Base, "/") && so != "" {
				l.Base = so + l.Base
			}
		}
		if l.Origin == "" && l.Base == "" && len(l.Bases) == 0 && !strings.HasPrefix(l.Path, "{}") && so != "" {
			l.Origin = so
		}
	}
	return l
}

func hostOriginOf(host string) string {
	if strings.HasSuffix(host, ":80") || strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost") {
		return "http://" + host
	}
	return "https://" + host
}

func hostOriginFor(host string, samples, intelBases []string, static []endpoints.Source) string {
	for _, list := range [][]string{samples, intelBases} {
		for _, raw := range list {
			if u, err := url.Parse(raw); err == nil && (u.Scheme == "http" || u.Scheme == "https") && strings.EqualFold(u.Host, host) {
				return u.Scheme + "://" + host
			}
		}
	}
	if !strings.HasSuffix(host, ":443") && len(static) > 0 {
		allHTTP := true
		hasAny := false
		for _, src := range static {
			if strings.HasPrefix(src.Script, "http://") {
				hasAny = true
			} else if strings.HasPrefix(src.Script, "https://") {
				allHTTP = false
				break
			}
		}
		if hasAny && allHTTP {
			return "http://" + host
		}
	}
	return hostOriginOf(host)
}

// uniqueIntelOriginForBase recovers a cross-origin API host from intel.Bases
// for legacy catalogs on disk where Base was saved as a path without Host.
func uniqueIntelOriginForBase(relBase, pageOrigin string, intelBases []string, inScope func(string) bool) string {
	relBase = strings.TrimRight(relBase, "/")
	if relBase == "" {
		return ""
	}
	for _, b := range intelBases {
		if strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") && strings.TrimRight(b, "/") == relBase {
			return ""
		}
	}
	found := ""
	for _, b := range intelBases {
		u, err := url.Parse(b)
		if err != nil || u.Host == "" || strings.Contains(u.Host, "{") {
			continue
		}
		if inScope != nil && !inScope(u.Hostname()) {
			continue
		}
		if strings.TrimRight(u.EscapedPath(), "/") != relBase {
			continue
		}
		orig := u.Scheme + "://" + u.Host
		if pageOrigin != "" && strings.EqualFold(orig, pageOrigin) {
			return ""
		}
		if found != "" && !strings.EqualFold(found, orig) {
			return ""
		}
		found = orig
	}
	return found
}

// candidateBases are the in-scope absolute bases intel.json names, the
// shortest first (a gateway's root before its services'), at most
// maxCandidates.
func candidateBases(in Inputs) []string {
	var out []string
	for _, b := range in.Intel.Bases {
		u, err := url.Parse(b)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || strings.Contains(u.Host, "{") {
			continue
		}
		if in.InScope != nil && !in.InScope(u.Hostname()) {
			continue
		}
		b = strings.TrimRight(b, "/")
		if !slices.Contains(out, b) {
			out = append(out, b)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	if maxCandidates > 0 && len(out) > maxCandidates {
		out = out[:maxCandidates]
	}
	return out
}

func isVersionSeg(s string) bool {
	if len(s) < 2 || (s[0] != 'v' && s[0] != 'V') || s[1] < '0' || s[1] > '9' {
		return false
	}
	for i := 2; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

func apiRootPrefix(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return ""
	}
	if len(segs) >= 2 && strings.EqualFold(segs[0], "api") && isVersionSeg(segs[1]) {
		return "/" + strings.ToLower(segs[0]) + "/" + strings.ToLower(segs[1])
	}
	if isVersionSeg(segs[0]) {
		return "/" + strings.ToLower(segs[0])
	}
	switch strings.ToLower(segs[0]) {
	case "api", "rest", "graphql":
		return "/" + strings.ToLower(segs[0])
	}
	return ""
}

// join puts a path under a base, the base's path not twice (/hub +
// /hub/auth/x is /hub/auth/x, and /api/v1/users + /api/v1/orders is
// /api/v1/orders rather than /api/v1/users/api/v1/orders).
func join(base, path string) string {
	base = strings.TrimRight(base, "/")
	p := strings.TrimPrefix(path, "{}")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if u, err := url.Parse(base); err == nil {
		bp := strings.TrimRight(u.EscapedPath(), "/")
		if bp != "" && (p == bp || strings.HasPrefix(p, bp+"/")) {
			return u.Scheme + "://" + u.Host + p
		}
		if ar := apiRootPrefix(bp); ar != "" && ar == apiRootPrefix(p) {
			return u.Scheme + "://" + u.Host + p
		}
	}
	return base + p
}

func draftOf(l line, source string, bases []string, in Inputs) Draft {
	return draftOfWithLangs(l, source, bases, in, nil)
}

func draftOfWithLangs(l line, source string, bases []string, in Inputs, originLangs map[string]string) Draft {
	d := Draft{Source: source, Method: l.Method, Path: l.Path, Confidence: l.Confidence, Kind: l.Kind, ThirdParty: l.ThirdParty, SourceOnly: l.SourceOnly}
	// The URL: the line's base, its one client base, its host, its page's
	// origin; else the target's bases, each a candidate.
	var target string
	switch {
	case l.Base != "" && strings.Contains(l.Base, "://"):
		target = join(l.Base, l.Path)
	case len(l.Bases) == 1 && strings.Contains(l.Bases[0], "://"):
		target = join(l.Bases[0], l.Path)
	case len(l.Bases) > 1:
		for _, b := range l.Bases {
			if strings.Contains(b, "://") {
				d.Candidates = append(d.Candidates, join(b, l.Path))
				d.CandidateBases = append(d.CandidateBases, b)
			}
		}
	case l.Host != "" && !strings.Contains(l.Host, "{"):
		target = join(hostOriginFor(l.Host, l.Samples, in.Intel.Bases, l.Static), l.Path)
	case l.Origin != "":
		target = strings.TrimRight(l.Origin, "/") + l.Path
	default:
		if !l.ThirdParty {
			sOrigins := allScriptOrigins(l.Static, in.InScope)
			addCand := func(base string) {
				u := join(base, l.Path)
				if !slices.Contains(d.Candidates, u) {
					d.Candidates = append(d.Candidates, u)
					d.CandidateBases = append(d.CandidateBases, base)
				}
			}
			if !strings.HasPrefix(l.Path, "{}") && len(sOrigins) > 0 {
				// Root-relative path shared across multiple script origins: probe each
				// script's own origin rather than gluing onto an unrelated subdomain's base.
				for _, so := range sOrigins {
					addCand(so)
				}
			} else {
				// Unresolved "{}/..." prefix: prioritize bases sharing the script's origin,
				// then the script's own origin(s) (e.g. window.livewire_app_url == ""), then
				// remaining in-scope bases.
				for _, b := range bases {
					if slices.ContainsFunc(sOrigins, func(so string) bool { return strings.HasPrefix(strings.ToLower(b), so) }) {
						addCand(b)
					}
				}
				for _, so := range sOrigins {
					addCand(so)
				}
				for _, b := range bases {
					addCand(b)
				}
			}
		}
	}
	if len(d.Candidates) == 1 {
		target, d.Candidates, d.CandidateBases = d.Candidates[0], nil, nil
	}
	if !d.ThirdParty && target != "" && in.InScope != nil {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" && !in.InScope(u.Hostname()) {
			d.ThirdParty = true
		}
	}
	if strings.HasPrefix(l.Path, "{}") && target == "" && len(d.Candidates) == 0 {
		d.Why = "a client's base the code does not give"
	}
	// A request the target was seen to take gives its values.
	sample := ""
	for _, s := range l.Samples {
		if target != "" && sameShape(s, target) {
			sample = s
			break
		}
	}
	var filledPath bool
	if target != "" {
		if sample != "" {
			target = strings.SplitN(sample, "?", 2)[0]
		} else {
			target, filledPath = fillPathWithLangs(target, l.Path, l.Params, originLangs)
		}
	}
	for i, c := range d.Candidates {
		d.Candidates[i], filledPath = fillPathWithLangs(c, l.Path, l.Params, originLangs)
	}
	if filledPath {
		d.Filled = append(d.Filled, "path")
	}
	specs := map[string]jsapi.ParamSpec{}
	for _, p := range l.Params {
		specs[p.In+" "+p.Name] = p
	}
	// The query: the sample's, else each name with a value.
	if len(l.Query) > 0 {
		d.Query = map[string]string{}
		var sq url.Values
		if i := strings.IndexByte(sample, '?'); i >= 0 {
			sq, _ = url.ParseQuery(sample[i+1:])
		}
		for _, q := range l.Query {
			if v := sq.Get(q); v != "" && endpoints.SampleValueOK(q, v) {
				d.Query[q] = v
				continue
			}
			v, fixed := valueOf(specs["query "+q], q)
			d.Query[q] = fmt.Sprint(v)
			if !fixed {
				d.Filled = append(d.Filled, "query."+q)
			}
		}
		target = withQuery(target, d.Query)
		for i := range d.Candidates {
			d.Candidates[i] = withQuery(d.Candidates[i], d.Query)
		}
	}
	if len(l.Body) > 0 && l.Method != "GET" && l.Method != "HEAD" {
		body, filled := bodyOf(l.Body, specs)
		d.Body = body
		d.Filled = append(d.Filled, filled...)
	}
	// The headers: the client's (intel, scoped to matching script/origin when
	// provenance is present), then the line's own.
	have := map[string]bool{}
	for _, h := range in.Intel.Headers {
		n := strings.ToLower(h.Name)
		if have[n] || n == "cookie" || n == "host" || n == "content-length" || n == "content-type" || noRequestHeader(n) {
			continue // the identity's cookies, the request's own, a response's
		}
		if !headerAppliesToDraft(h, l, target, d.Candidates, in.Intel.Headers) {
			continue
		}
		have[n] = true
		v := h.Value
		if strings.Contains(v, "{}") {
			// What the code computes (a token): a sample in its place. The
			// identity's, not the endpoint's: the tier does not count it.
			v = strings.ReplaceAll(v, "{}", "sample")
			d.SampleHeaders = append(d.SampleHeaders, h.Name)
		}
		d.Headers = append(d.Headers, [2]string{h.Name, v})
	}
	for _, h := range l.Headers {
		n := strings.ToLower(h)
		if have[n] || n == "content-type" || n == "content-length" || n == "host" || n == "cookie" || noRequestHeader(n) {
			continue
		}
		v, fixed := valueOf(specs["header "+h], h)
		if !fixed && browserHeader[n] {
			continue // the browser's own (Accept-Language): no sample of it
		}
		have[n] = true
		d.Headers = append(d.Headers, [2]string{h, fmt.Sprint(v)})
		if !fixed {
			d.Filled = append(d.Filled, "header."+h)
		}
	}
	d.URL = target
	// The tier.
	switch {
	case d.Method == "":
		d.Tier, d.Why = Incomplete, "no method"
	case d.URL == "" && len(d.Candidates) != 1:
		d.Tier = Incomplete
		if d.Why == "" {
			d.Why = fmt.Sprintf("no one URL (%d candidates)", len(d.Candidates))
		}
	case len(d.Filled) > 0:
		d.Tier = Parameterized
	default:
		d.Tier = Ready
	}
	return d
}

// sameShape reports a sample URL of a template (its {} any one segment).
func sameShape(sample, tpl string) bool {
	su, err1 := url.Parse(sample)
	tu, err2 := url.Parse(tpl)
	if err1 != nil || err2 != nil || !strings.EqualFold(su.Host, tu.Host) {
		return false
	}
	a, b := strings.Split(su.EscapedPath(), "/"), strings.Split(tu.EscapedPath(), "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if b[i] != a[i] && !strings.Contains(b[i], "%7B%7D") && !strings.Contains(b[i], "{}") {
			return false
		}
	}
	return true
}

const sampleUUID = "00000000-0000-0000-0000-000000000001"

var (
	idNameRe   = regexp.MustCompile(`(?i)(?:id|uuid|guid)$`)
	slugNameRe = regexp.MustCompile(`(?i)slug|code|name|key`)
	boolNameRe = regexp.MustCompile(`^(?:is|has|can|should)(?:_|[A-Z])`)
	numWords   = map[string]bool{
		"seq": true, "index": true, "num": true, "number": true, "page": true,
		"version": true, "count": true, "limit": true, "size": true, "offset": true,
	}
)

// splitWords splits snake_case, kebab-case and camelCase identifiers into
// lowercase words ("country" -> ["country"], "retryCount" -> ["retry","count"]).
func splitWords(s string) []string {
	var out []string
	var cur []byte
	flush := func() {
		for len(cur) > 0 && cur[len(cur)-1] >= '0' && cur[len(cur)-1] <= '9' {
			cur = cur[:len(cur)-1]
		}
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isUpper := c >= 'A' && c <= 'Z'
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isUpper && !isLower && !isDigit {
			flush()
			continue
		}
		if isUpper && len(cur) > 0 {
			prevLower := s[i-1] >= 'a' && s[i-1] <= 'z'
			nextLower := i+1 < len(s) && s[i+1] >= 'a' && s[i+1] <= 'z'
			if prevLower || nextLower {
				flush()
			}
		}
		cur = append(cur, c)
	}
	flush()
	return out
}

func hasNumWord(s string) bool {
	for _, w := range splitWords(s) {
		if numWords[w] {
			return true
		}
	}
	return false
}

// fillPath puts a sample in each {} of a URL (the base's own {} aside): by
// the path parameter's name, else by the segment before it.
func fillPath(target, path string, params []jsapi.ParamSpec) (string, bool) {
	return fillPathWithLangs(target, path, params, nil)
}

func fillPathWithLangs(target, path string, params []jsapi.ParamSpec, originLangs map[string]string) (string, bool) {
	if !strings.Contains(target, "{}") {
		return target, false
	}
	names := map[int]string{}
	for _, p := range params {
		if p.In == "path" {
			names[p.Position] = p.Name
		}
	}
	scheme, rest, _ := strings.Cut(target, "://")
	host, p, _ := strings.Cut(rest, "/")
	orig := strings.ToLower(scheme + "://" + host)
	langHint := ""
	if originLangs != nil {
		langHint = originLangs[orig]
	}
	if langHint == "" {
		langHint = langFromHost(host)
	}
	segs := strings.Split(p, "/")
	slot := 0
	for i, sg := range segs {
		for strings.Contains(sg, "{}") {
			prev := ""
			if i > 0 {
				prev = segs[i-1]
			}
			sg = strings.Replace(sg, "{}", sampleForWithLang(names[slot], prev, langHint), 1)
			slot++
		}
		segs[i] = sg
	}
	return scheme + "://" + host + "/" + strings.Join(segs, "/"), true
}

// sampleFor is a value for a path's part: a UUID for an id (and for a
// resource's item, /tenants/{}), a word for a slug, a number for a page.
func sampleFor(name, prev string) string {
	return sampleForWithLang(name, prev, "")
}

func sampleForWithLang(name, prev, langHint string) string {
	if isLangParamName(name) {
		if langHint != "" {
			return langHint
		}
		return "en"
	}
	switch {
	case name != "" && idNameRe.MatchString(name):
		return sampleUUID
	case name != "" && slugNameRe.MatchString(name), prev == "by-slug":
		return "sample-item"
	case name != "" && hasNumWord(name):
		return "1"
	case name == "" && strings.HasSuffix(prev, "s") && !hasNumWord(prev):
		return sampleUUID // /tenants/{}: an item of a collection
	}
	return "1"
}

func isLangParamName(name string) bool {
	if name == "" {
		return false
	}
	l := strings.ToLower(name)
	switch l {
	case "lang", "locale", "language", "currentlanguage", "current_language",
		"sitelang", "site_lang", "langcode", "lang_code", "dil":
		return true
	}
	ws := splitWords(name)
	return len(ws) > 0 && (ws[len(ws)-1] == "language" || ws[len(ws)-1] == "locale" || ws[len(ws)-1] == "lang")
}

var (
	knownLangSegs = map[string]bool{
		"tr": true, "en": true, "vi": true, "de": true, "fr": true, "es": true,
		"it": true, "pt": true, "ru": true, "nl": true, "pl": true, "ja": true,
		"ko": true, "zh": true, "ar": true, "id": true, "th": true, "uk": true,
		"cs": true, "sv": true, "da": true, "fi": true, "no": true, "el": true,
		"ro": true, "hu": true, "az": true,
	}
	ccTLDLangs = map[string]string{
		"tr": "tr", "vn": "vi", "de": "de", "fr": "fr", "es": "es", "it": "it",
		"pt": "pt", "br": "pt", "ru": "ru", "nl": "nl", "pl": "pl", "jp": "ja",
		"kr": "ko", "cn": "zh", "tw": "zh", "ua": "uk", "cz": "cs", "se": "sv",
		"dk": "da", "fi": "fi", "no": "no", "gr": "el", "ro": "ro", "hu": "hu",
		"az": "az", "id": "id", "th": "th",
	}
)

// inferOriginLanguages inspects concrete paths in the catalog (e.g.
// "/tr/api/items" on "https://portal.example.tr") so parameterized sibling
// routes ("/{}/api/announcements") pick the exact language prefix active on
// that origin.
func inferOriginLanguages(cat []endpoints.Endpoint) map[string]string {
	counts := map[string]map[string]int{}
	for _, e := range cat {
		orig := strings.ToLower(strings.TrimRight(e.Origin, "/"))
		if orig == "" && e.Host != "" && !strings.Contains(e.Host, "{") {
			orig = strings.ToLower(hostOriginOf(e.Host))
		}
		if orig == "" {
			continue
		}
		segs := strings.Split(strings.Trim(e.Path, "/"), "/")
		if len(segs) >= 2 && knownLangSegs[strings.ToLower(segs[0])] {
			seg := strings.ToLower(segs[0])
			if counts[orig] == nil {
				counts[orig] = map[string]int{}
			}
			counts[orig][seg]++
		}
	}
	out := make(map[string]string, len(counts))
	for orig, m := range counts {
		best, bestN := "", 0
		for seg, n := range m {
			if n > bestN || (n == bestN && (best == "" || seg < best)) {
				best, bestN = seg, n
			}
		}
		if best != "" {
			out[orig] = best
		}
	}
	return out
}

func langFromHost(host string) string {
	h, _, err := strings.Cut(host, ":")
	if err {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "."))
	if idx := strings.LastIndexByte(host, '.'); idx >= 0 {
		if lang := ccTLDLangs[host[idx+1:]]; lang != "" {
			return lang
		}
	}
	return ""
}

// valueOf is a parameter's value: the code's own when there is one (fixed),
// else a sample of its type, else one its name suggests.
func valueOf(p jsapi.ParamSpec, name string) (any, bool) {
	for _, v := range p.Values {
		if endpoints.IsRedactedValue(v) {
			continue
		}
		switch p.Type {
		case "number":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f, true
			}
		case "boolean":
			return v == "true", true
		}
		return v, true
	}
	leaf := name[strings.LastIndexByte(name, '.')+1:]
	if p.Type == "" || p.Type == "string" {
		switch strings.ToLower(leaf) {
		case "lang", "locale", "language":
			return "en", false
		case "country", "region", "country_code", "countrycode":
			return "us", false
		}
	}
	switch p.Type {
	case "number":
		return 1, false
	case "boolean":
		return false, false
	case "array":
		return []any{}, false
	case "object":
		return map[string]any{}, false
	case "string":
		return "sample", false
	}
	switch l := strings.ToLower(leaf); {
	case idNameRe.MatchString(leaf):
		return sampleUUID, false
	case hasNumWord(leaf):
		return 1, false
	case boolNameRe.MatchString(leaf) || strings.HasSuffix(l, "enabled") || strings.HasSuffix(l, "_only"):
		return false, false
	case strings.Contains(l, "email"):
		return marker.SampleEmail, false
	}
	return "sample", false
}

// bodyOf builds a JSON body of the dotted names (files.checksum: an object
// under files, a list's item when files is a list).
func bodyOf(names []string, specs map[string]jsapi.ParamSpec) (json.RawMessage, []string) {
	root := map[string]any{}
	var filled []string
	isArray := func(path string) bool { return specs["body "+path].Type == "array" }
	sorted := slices.Clone(names)
	sort.Strings(sorted)
	for _, n := range sorted {
		parts := strings.Split(n, ".")
		cur := root
		for i, p := range parts[:len(parts)-1] {
			prefix := strings.Join(parts[:i+1], ".")
			next, ok := cur[p]
			switch v := next.(type) {
			case map[string]any:
				cur = v
				continue
			case []any:
				if len(v) > 0 {
					if m, ok := v[0].(map[string]any); ok {
						cur = m
						continue
					}
				}
			}
			_ = ok
			m := map[string]any{}
			if isArray(prefix) {
				cur[p] = []any{m}
			} else {
				cur[p] = m
			}
			cur = m
		}
		leaf := parts[len(parts)-1]
		if _, ok := cur[leaf]; ok {
			continue // a parent of others, already built
		}
		v, fixed := valueOf(specs["body "+n], n)
		if isArray(n) || specs["body "+n].Type == "object" {
			if hasChild(sorted, n) {
				continue // its children make it
			}
		}
		cur[leaf] = v
		if !fixed {
			filled = append(filled, "body."+n)
		}
	}
	b, _ := json.Marshal(root)
	return b, filled
}

func hasChild(names []string, n string) bool {
	return slices.ContainsFunc(names, func(o string) bool { return strings.HasPrefix(o, n+".") })
}

// withQuery adds a query to a URL, its names sorted.
func withQuery(target string, q map[string]string) string {
	if target == "" || len(q) == 0 {
		return target
	}
	v := url.Values{}
	for k, x := range q {
		v.Set(k, x)
	}
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + v.Encode()
}

func allScriptOrigins(srcs []endpoints.Source, inScope func(string) bool) []string {
	var out []string
	for _, s := range srcs {
		u, err := url.Parse(s.Script)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if inScope != nil && !inScope(h) || strings.HasPrefix(h, "cdn.") || strings.HasPrefix(h, "static.") || strings.HasPrefix(h, "assets.") {
			continue
		}
		o := strings.ToLower(u.Scheme + "://" + u.Host)
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

func draftOriginOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// headerAppliesToDraft scopes intel.Headers to drafts sharing either a
// producing script SHA256 (covering cross-origin SPA -> API gateway calls) or
// an origin with the header's sources, preventing cross-subdomain header bleed
// in multi-subdomain (-scope rdn) scans.
func headerAppliesToDraft(h endpoints.IntelHeader, l line, target string, cands []string, all []endpoints.IntelHeader) bool {
	if len(h.Sources) == 0 {
		return true
	}
	if slices.ContainsFunc(l.Headers, func(lh string) bool { return strings.EqualFold(lh, h.Name) }) {
		return true
	}
	shas := map[string]bool{}
	origins := map[string]bool{}
	for _, s := range l.Static {
		if s.SHA256 != "" {
			shas[s.SHA256] = true
		}
		if o := draftOriginOf(s.Script); o != "" {
			origins[o] = true
		}
	}
	if o := draftOriginOf(l.Origin); o != "" {
		origins[o] = true
	}
	if o := draftOriginOf(target); o != "" {
		origins[o] = true
	}
	for _, c := range cands {
		if o := draftOriginOf(c); o != "" {
			origins[o] = true
		}
	}
	if len(shas) == 0 && len(origins) == 0 {
		return true
	}
	for _, src := range h.Sources {
		if src.SHA256 != "" && shas[src.SHA256] {
			return true
		}
		if o := draftOriginOf(src.Script); o != "" && origins[o] {
			return true
		}
	}
	// If the draft has no script provenance of its own (e.g. observed/OpenAPI
	// on api.example.com while the SPA ran on a single origin app.example.com),
	// keep headers when all Intel headers come from one single origin.
	if len(l.Static) == 0 {
		headerOrigins := map[string]bool{}
		for _, ih := range all {
			for _, src := range ih.Sources {
				if o := draftOriginOf(src.Script); o != "" {
					headerOrigins[o] = true
				}
			}
		}
		if len(headerOrigins) <= 1 {
			return true
		}
	}
	return false
}

// scriptOrigin is the one in-scope origin the sources' scripts come from
// (a CDN's that serves many aside), or "".
func scriptOrigin(srcs []endpoints.Source, inScope func(string) bool) string {
	one := ""
	for _, s := range srcs {
		u, err := url.Parse(s.Script)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if inScope != nil && !inScope(h) || strings.HasPrefix(h, "cdn.") || strings.HasPrefix(h, "static.") || strings.HasPrefix(h, "assets.") {
			continue
		}
		o := strings.ToLower(u.Scheme + "://" + u.Host)
		if one != "" && one != o {
			return ""
		}
		one = o
	}
	return one
}

// browserHeader are headers a browser sets itself: a draft keeps the
// code's value of one, never a sample.
var browserHeader = map[string]bool{"accept": true, "accept-language": true, "accept-encoding": true, "user-agent": true,
	"origin": true, "referer": true, "connection": true}

// noRequestHeader is a response's header a client sets by mistake
// (axios headers: {"Access-Control-Allow-Origin": …}): never sent.
func noRequestHeader(n string) bool {
	return strings.HasPrefix(n, "access-control-allow-") || strings.HasPrefix(n, "access-control-expose-") ||
		n == "access-control-max-age"
}

// RedactDrafts masks credentials and PII in drafts (URLs, Candidates, Query,
// Headers and Body) when exporting with -redact.
func RedactDrafts(ds []Draft, r *traffic.Redactor) []Draft {
	if r == nil {
		return ds
	}
	out := make([]Draft, len(ds))
	for i, d := range ds {
		if len(d.Query) > 0 {
			q := make(map[string]string, len(d.Query))
			for k, v := range d.Query {
				if endpoints.SensitiveParam(k) {
					q[k] = r.Value(v)
				} else {
					q[k] = r.Text(v)
				}
			}
			d.Query = q
		}
		if d.URL != "" {
			u := d.URL
			if len(d.Query) > 0 {
				u = withQuery(strings.SplitN(u, "?", 2)[0], d.Query)
			}
			d.URL = r.URL(u)
		}
		if len(d.Candidates) > 0 {
			cands := make([]string, len(d.Candidates))
			for j, c := range d.Candidates {
				if len(d.Query) > 0 {
					c = withQuery(strings.SplitN(c, "?", 2)[0], d.Query)
				}
				cands[j] = r.URL(c)
			}
			d.Candidates = cands
		}
		if len(d.Headers) > 0 {
			hdrs := make([][2]string, len(d.Headers))
			for j, h := range d.Headers {
				rm := r.Headers(map[string]string{h[0]: h[1]})
				hdrs[j] = [2]string{h[0], rm[h[0]]}
			}
			d.Headers = hdrs
		}
		if len(d.Body) > 0 {
			redacted := r.Text(string(d.Body))
			dec := json.NewDecoder(strings.NewReader(redacted))
			dec.UseNumber()
			var obj any
			if dec.Decode(&obj) == nil {
				obj = redactJSONValue(obj, "", r)
				if mb, err := json.Marshal(obj); err == nil {
					d.Body = mb
				} else {
					d.Body = json.RawMessage(redacted)
				}
			} else {
				d.Body = json.RawMessage(redacted)
			}
		}
		out[i] = d
	}
	return out
}

func redactJSONValue(v any, key string, r *traffic.Redactor) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			full := k
			if key != "" {
				full = key + "." + k
			}
			m[k] = redactJSONValue(val, full, r)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, val := range x {
			s[i] = redactJSONValue(val, key, r)
		}
		return s
	default:
		if key != "" && endpoints.SensitiveParam(key) && x != nil {
			return r.Value(fmt.Sprint(x))
		}
		return x
	}
}

// WithUserAgent gives each draft that has none the User-Agent of the run's
// browser (round 25I review): a drafts/*.http file fed to ffuf or sqlmap
// as it is would otherwise go with the tool's own default User-Agent.
func WithUserAgent(ds []Draft, ua string) []Draft {
	if ua == "" {
		return ds
	}
	out := make([]Draft, len(ds))
	for i, d := range ds {
		if !slices.ContainsFunc(d.Headers, func(h [2]string) bool { return strings.EqualFold(h[0], "user-agent") }) {
			d.Headers = append(slices.Clone(d.Headers), [2]string{"User-Agent", ua})
		}
		out[i] = d
	}
	return out
}
