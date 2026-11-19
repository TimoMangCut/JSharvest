// Package endpoints keeps a role's catalog of endpoints, from the code it
// has not run to the traffic it has: what the scripts in the store call
// (found by jsapi without running them, cached per script), merged with
// the requests seen. Each endpoint is static (only in the code), observed
// (only in the traffic) or both.
package endpoints

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/store"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

const (
	CacheDir = "static"          // <dir>/static/<sha256>.json
	File     = "endpoints.jsonl" // the catalog
	// maxScript is the largest script parsed into an AST: bigger monolith
	// bundles (up to maxLooseScript) fall back to the linear loose scanner so
	// endpoints are still recovered without multi-GB AST allocations.
	maxScript      = 16 << 20
	maxLooseScript = 64 << 20
)

// AnalyzeStats summarizes static analysis coverage and parse fallbacks across
// stored scripts so bundle parser failures are never silent.
type AnalyzeStats struct {
	Total                 int      `json:"total"`
	BundleParseErrors     int      `json:"bundle_parse_errors"`
	BundleASTLowered      int      `json:"bundle_ast_lowered,omitempty"`
	SourceParseFallback   int      `json:"source_parse_fallbacks,omitempty"`
	OversizeLooseFallback int      `json:"oversize_loose_fallback,omitempty"`
	OversizeSkipped       int      `json:"oversize_skipped,omitempty"`
	FailedBundles         []string `json:"failed_bundles,omitempty"`

	// StaleCache counts the scripts read from a cache an older extractor
	// made: a reader (Load) cannot analyse again, so it says so.
	StaleCache int `json:"stale_cache,omitempty"`
}

// SummarizeScripts computes AnalyzeStats over a slice of analyzed scripts.
func SummarizeScripts(scripts []Script) AnalyzeStats {
	var st AnalyzeStats
	st.Total = len(scripts)
	for _, s := range scripts {
		if s.Version != 0 && s.Version != jsapi.Version {
			st.StaleCache++
		}
		if strings.HasPrefix(s.Error, "not analysed:") {
			st.OversizeSkipped++
			continue
		}
		if strings.HasPrefix(s.ParseError, "oversize_ast_bypass:") {
			st.OversizeLooseFallback++
			continue
		}
		isParseFallback := s.LooseFallback || strings.HasPrefix(s.Error, "parse")
		if s.Source {
			if isParseFallback {
				st.SourceParseFallback++
			}
			continue
		}
		if s.ASTLowered {
			st.BundleASTLowered++
		}
		if isParseFallback {
			st.BundleParseErrors++
			if len(st.FailedBundles) < 10 {
				label := s.SHA256
				if len(label) > 12 {
					label = label[:12]
				}
				if len(s.URLs) > 0 && s.URLs[0] != "" {
					label = s.URLs[0]
				}
				st.FailedBundles = append(st.FailedBundles, label)
			}
		}
	}
	return st
}

// Script is what the analysis found in one stored script.
type Script struct {
	jsapi.Result
	SHA256     string   `json:"sha256"`
	URLs       []string `json:"urls,omitempty"`
	ThirdParty bool     `json:"third_party,omitempty"`
	Source     bool     `json:"source,omitempty"`
	Inline     bool     `json:"inline,omitempty"`
	// Load reads the script's source, for evaluating a URL builder it
	// exports with another script's arguments (round 27A); nil when the
	// source is not at hand (the deferred URLs are then left).
	Load func() []byte `json:"-"`
}

type scriptInfo struct {
	urls       []string
	thirdParty bool
	// source: an original source out of a source map (TypeScript, JSX…),
	// read loosely when the parser does not take it.
	source bool
	inline bool
	// openapi: an OpenAPI or Swagger document the crawl fetched.
	openapi bool
}

// readIndex reads the store's index.jsonl without opening the store, which
// recovers and may write: a reader (jsharvest mcp) must not.
func readIndex(dir string) (map[string]scriptInfo, error) {
	f, err := os.Open(filepath.Join(dir, "index.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]scriptInfo{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var e store.Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.SHA256 == "" {
			continue
		}
		// A bot challenge's code, or the CDN's helpers, are never the
		// target's endpoints; an output written before capture dropped them
		// may still hold some (Cloudflare's eval blocks, with no tag).
		var inits []string
		for _, in := range e.Initiators {
			inits = append(inits, in.URL)
		}
		if detect.Quarantined(e.Tags, e.URLs, inits) {
			continue
		}
		isInline := slices.Contains(e.Kinds, "inline") && !slices.Contains(e.Kinds, "file")
		out[e.SHA256] = scriptInfo{
			urls:       e.URLs,
			thirdParty: slices.Contains(e.Tags, "third-party"),
			source:     slices.Contains(e.Tags, "sourcemap"),
			inline:     isInline,
			openapi:    slices.Contains(e.Tags, "openapi"),
		}
	}
	return out, sc.Err()
}

// Analyze makes the cache of every script in the store that has none (or
// one from another version of the extractor), with the given number of
// workers, and returns the results of all of them.
func Analyze(dir string, workers int) ([]Script, error) {
	return analyzeDir(dir, workers, nil, false)
}

// AnalyzeExcept is Analyze restricted to scripts whose SHA-256 is not in skip,
// avoiding repeated re-unmarshaling of already-processed scripts across frontier levels.
func AnalyzeExcept(dir string, workers int, skip map[string]bool) ([]Script, error) {
	return analyzeDir(dir, workers, skip, false)
}

// AnalyzeSlim runs Analyze while stripping Paths and Routes on the returned
// in-memory Script structs (after persisting the full result to static/<sha>.json),
// cutting catalog assembly RAM on multi-thousand-script archive stores.
func AnalyzeSlim(dir string, workers int) ([]Script, error) {
	return analyzeDir(dir, workers, nil, true)
}

func analyzeDir(dir string, workers int, skip map[string]bool, slim bool) ([]Script, error) {
	index, err := readIndex(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, CacheDir), 0o700); err != nil {
		return nil, err
	}
	hasMem := atomic.LoadInt64(&globalMem.budgetBytes) > 0
	if workers <= 0 {
		// Small chunks run across all logical CPUs while heavySem (2 when !hasMem)
		// independently bounds concurrent multi-MB AST allocations.
		workers = max(1, runtime.GOMAXPROCS(0))
	}
	shas := make([]string, 0, len(index))
	for sha := range index {
		if skip != nil && skip[sha] {
			continue
		}
		shas = append(shas, sha)
	}
	if len(shas) == 0 {
		return nil, nil
	}
	sort.Strings(shas)
	out := make([]Script, len(shas))
	heavyCap := 2
	if hasMem {
		heavyCap = max(2, min(4, runtime.GOMAXPROCS(0)/2))
	}
	heavySem := make(chan struct{}, heavyCap)
	var wg sync.WaitGroup
	next := make(chan int)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				s := analyzeOne(dir, shas[i], index[shas[i]], heavySem)
				if slim {
					s.Paths = nil
					s.Routes = nil
				}
				out[i] = s
			}
		}()
	}
	for i := range shas {
		next <- i
	}
	close(next)
	wg.Wait()
	return out, nil
}

const heavyScriptBytes = 320 << 10

func extractJS(src []byte, hint string, heavySem chan struct{}) jsapi.Result {
	// Clip slice capacity so tdewolff/parse/v2.NewInputBytes (which appends a
	// NUL sentinel byte) never mutates a shared backing array across workers.
	src = src[:len(src):len(src)]
	if len(src) > maxLooseScript {
		return jsapi.Result{Version: jsapi.Version, Error: fmt.Sprintf("not analysed: %d bytes", len(src))}
	}
	if len(src) > maxScript {
		if heavySem != nil {
			heavySem <- struct{}{}
			defer func() { <-heavySem }()
		}
		res := jsapi.ExtractLoose(src)
		res.LooseFallback = true
		res.ParseError = fmt.Sprintf("oversize_ast_bypass: %d bytes", len(src))
		return res
	}
	if heavySem != nil && len(src) >= heavyScriptBytes {
		heavySem <- struct{}{}
		defer func() { <-heavySem }()
	}
	res := jsapi.ExtractSource(src, hint)
	if strings.HasPrefix(res.Error, "parse") {
		parseErr := res.Error
		res = jsapi.ExtractLoose(src)
		res.LooseFallback = true
		res.ParseError = parseErr
	}
	return res
}

func writeStaticCache(cache string, res jsapi.Result) {
	b, err := json.Marshal(res)
	if err != nil {
		return
	}
	// A temporary file of its own: a watch's background analysis and
	// the one at its end may write the same script's cache.
	f, err := os.CreateTemp(filepath.Dir(cache), filepath.Base(cache)+".*.tmp")
	if err != nil {
		return
	}
	tmpName := f.Name()
	_ = f.Chmod(0o600)
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr == nil && cerr == nil && os.Rename(tmpName, cache) == nil {
		return
	}
	_ = os.Remove(tmpName)
}

// ExtractCached extracts JS/TS/SFC metadata for src using <dir>/static/<sha256>.json
// so HTTP crawls that inspect scripts for frontier routes or Phase-2 spec probing
// warm the exact cache Analyze reads at the end of the run instead of parsing AST twice.
func ExtractCached(dir string, src []byte, hint string) jsapi.Result {
	rawSum := sha256.Sum256(src)
	sum := hex.EncodeToString(rawSum[:])
	if res, ok := memGetResult(sum); ok {
		if dir != "" {
			cache := filepath.Join(dir, CacheDir, sum+".json")
			if _, err := os.Stat(cache); err != nil && os.MkdirAll(filepath.Join(dir, CacheDir), 0o700) == nil {
				writeStaticCache(cache, res)
			}
		}
		return res
	}
	if dir == "" {
		res := extractJS(src, hint, nil)
		memPutResult(sum, res)
		if len(res.Builders) > 0 || len(res.Exports) > 0 {
			CacheScriptBody(sum, src)
		}
		return res
	}
	cacheDir := filepath.Join(dir, CacheDir)
	cache := filepath.Join(cacheDir, sum+".json")
	var res jsapi.Result
	if b, err := os.ReadFile(cache); err == nil && json.Unmarshal(b, &res) == nil && res.Version == jsapi.Version {
		memPutResult(sum, res)
		if len(res.Builders) > 0 || len(res.Exports) > 0 {
			CacheScriptBody(sum, src)
		}
		return res
	}
	res = extractJS(src, hint, nil)
	memPutResult(sum, res)
	if len(res.Builders) > 0 || len(res.Exports) > 0 {
		CacheScriptBody(sum, src)
	}
	if os.MkdirAll(cacheDir, 0o700) == nil {
		writeStaticCache(cache, res)
	}
	return res
}

func analyzeOne(dir, sha string, info scriptInfo, heavySem chan struct{}) Script {
	s := Script{SHA256: sha, URLs: info.urls, ThirdParty: info.thirdParty, Source: info.source, Inline: info.inline, Load: sourceOf(dir, sha)}
	cache := filepath.Join(dir, CacheDir, sha+".json")
	if !info.openapi {
		if res, ok := memGetResult(sha); ok {
			s.Result = res
			if _, err := os.Stat(cache); err != nil {
				writeStaticCache(cache, s.Result)
			}
			return s
		}
	}
	if b, err := os.ReadFile(cache); err == nil && json.Unmarshal(b, &s.Result) == nil && s.Version == jsapi.Version {
		if !info.openapi {
			memPutResult(sha, s.Result)
		}
		return s
	}
	src, ok := memGetBody(sha)
	var err error
	if !ok {
		src, err = os.ReadFile(filepath.Join(dir, "js", sha+".js"))
	}
	switch {
	case err != nil:
		s.Result = jsapi.Result{Version: jsapi.Version, Error: "read: " + err.Error()}
		return s // not cached: the file may come later
	case len(src) > maxLooseScript:
		s.Result = jsapi.Result{Version: jsapi.Version, Error: fmt.Sprintf("not analysed: %d bytes", len(src))}
	case info.openapi && len(src) <= maxScript && jsapi.IsOIDC(src):
		s.Result = jsapi.ExtractOIDC(src) // an OpenID Provider's configuration (PIP-03)
	case info.openapi && len(src) <= maxScript:
		s.Result = jsapi.ExtractOpenAPI(src)
	case info.openapi:
		s.Result = jsapi.Result{Version: jsapi.Version, Error: fmt.Sprintf("not analysed: %d bytes", len(src))}
	default:
		s.Result = extractJS(src, sourceHint(info.urls), heavySem)
		memPutResult(sha, s.Result)
		if len(s.Result.Builders) > 0 || len(s.Result.Exports) > 0 {
			CacheScriptBody(sha, src)
		}
	}
	writeStaticCache(cache, s.Result)
	return s
}

func sourceHint(urls []string) string {
	for _, u := range urls {
		if strings.Contains(u, "#") {
			return u
		}
	}
	if len(urls) > 0 {
		return urls[0]
	}
	return ""
}

// sourceOf reads a stored script's source when asked, hitting the in-memory
// body cache first when available.
func sourceOf(dir, sha string) func() []byte {
	return func() []byte {
		if b, ok := memGetBody(sha); ok {
			return b
		}
		b, _ := os.ReadFile(filepath.Join(dir, "js", sha+".js"))
		return b
	}
}

// Load reads the cached results without analysing anything: what a
// reader can know while a watch fills the cache. A cache an older
// extractor made is read all the same (a reader cannot analyse again) and
// counted in AnalyzeStats.StaleCache.
func Load(dir string) ([]Script, error) {
	return loadDir(dir, false)
}

func loadDir(dir string, slim bool) ([]Script, error) {
	index, err := readIndex(dir)
	if err != nil {
		return nil, err
	}
	var out []Script
	for sha, info := range index {
		b, err := os.ReadFile(filepath.Join(dir, CacheDir, sha+".json"))
		if err != nil {
			continue
		}
		// The source too: a builder another script calls is evaluated in
		// it (linkDeferred), as the analysing catalog does (plan-28 2.1).
		s := Script{SHA256: sha, URLs: info.urls, ThirdParty: info.thirdParty, Source: info.source, Inline: info.inline, Load: sourceOf(dir, sha)}
		if json.Unmarshal(b, &s.Result) == nil {
			if slim {
				s.Paths = nil
				s.Routes = nil
			}
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SHA256 < out[j].SHA256 })
	return out, nil
}

// --- the catalog ---

// Source is where in the code an endpoint is called.
type Source struct {
	SHA256  string `json:"sha256"`
	Script  string `json:"script,omitempty"` // a URL the script was loaded from
	Line    int    `json:"line,omitempty"`
	Col     int    `json:"col,omitempty"`
	Kind    string `json:"kind"`
	Snippet string `json:"snippet,omitempty"`
}

// Observed is what the traffic shows of an endpoint.
type Observed struct {
	Requests int       `json:"requests"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Samples  []string  `json:"samples,omitempty"` // distinct URLs, at most 5
	Outcomes []string  `json:"outcomes,omitempty"`
	// Statuses are the HTTP statuses the server answered with, distinct:
	// an outcome of ok is any answer, a 403 included.
	Statuses []int64 `json:"statuses,omitempty"`
	Runs     int     `json:"runs"`
	// Refs are run and request id of the requests, at most 20.
	Refs []Ref `json:"refs,omitempty"`
}

type Ref struct {
	Run string `json:"run"`
	ID  int    `json:"id"`
}

// Status of an endpoint: in the code only, in the traffic only, or both.
const (
	Static        = "static"
	ObservedOnly  = "observed"
	Both          = "both"
	maxSources    = 10
	maxSamples    = 5
	maxRefs       = 20
	placeholder   = "{}"
	unknownPrefix = "{}/"
)

// Endpoint is one line of endpoints.jsonl.
type Endpoint struct {
	Method string `json:"method,omitempty"`
	// Host is empty for the page's own origin (a relative URL in the code).
	Host string `json:"host,omitempty"`
	// Path is a template: {} for what the code computes, {id} and the like
	// for what the traffic shows varies.
	Path        string             `json:"path"`
	Status      string             `json:"status"`
	Kind        string             `json:"kind"`
	Query       []string           `json:"query,omitempty"`
	Body        []string           `json:"body,omitempty"`
	Headers     []string           `json:"headers,omitempty"`
	Auth        []string           `json:"auth,omitempty"`
	Operations  []string           `json:"operations,omitempty"`
	GraphQLDocs []jsapi.GraphQLDoc `json:"graphql_docs,omitempty"`
	// Base is the prefix a client adds to Path (its baseURL), when the
	// traffic confirmed it; Bases are the candidates the code names.
	Base  string   `json:"base,omitempty"`
	Bases []string `json:"bases,omitempty"`
	// Origin is the origin of the pages a relative call with no base is
	// made on (QAL-05); Bases stays a client's only.
	Origin     string `json:"origin,omitempty"`
	ThirdParty bool   `json:"third_party,omitempty"`
	// SourceOnly marks static endpoints extracted exclusively from sourcemap
	// sources (`sourcemap` tag) with no presence in active JS bundles or traffic.
	SourceOnly bool `json:"source_only,omitempty"`
	// Confidence: confirmed (seen run), spec, code, string or doc.
	Confidence string `json:"confidence,omitempty"`
	// Enriched: where what the line's own sources lack was filled from
	// (archive: an old script's call of the same path, PIP-01).
	Enriched []string          `json:"enriched_from,omitempty"`
	Params   []jsapi.ParamSpec `json:"params,omitempty"`
	Static   []Source          `json:"static,omitempty"`
	Observed *Observed         `json:"observed,omitempty"`

	re     *regexp.Regexp // for matching requests to it
	lit    string         // the longest fixed piece of its path, to skip the regexp
	client bool           // its path is relative to an unknown base
	// collector: an analytics collector's (Snowplow, GA), a third party's
	// whichever script names it.
	collector    bool
	bundleStatic bool
	runs         map[string]bool
	obsHosts     map[string]bool
	// docBases are the bases a document puts it under (export
	// SLINK_HOST=…).
	docBases []string
	baseKeys map[string]bool
}

func (ep *Endpoint) addBaseKey(k string) {
	if k == "" {
		return
	}
	if ep.baseKeys == nil {
		ep.baseKeys = map[string]bool{}
	}
	ep.baseKeys[k] = true
}

func (ep *Endpoint) addBaseKeys(ks map[string]bool) {
	for k := range ks {
		ep.addBaseKey(k)
	}
}

// Request is what the catalog needs of a logged request.
type Request struct {
	Run          string
	ID           int
	Time         time.Time
	Method       string
	URL          string
	Body         string // small JSON object request body (<= 16 KB), for real parameter values
	ResourceType string
	Outcome      string
	Status       int64 // the HTTP status, 0 for none (held back, failed)
	Initiator    string
}

// apiTypes are the resource types of requests that call endpoints; pages,
// scripts, styles, images and fonts do not.
// Requests of type Other (a favicon, a navigation preload) only count when
// the code names them.
var apiTypes = map[string]bool{"Fetch": true, "XHR": true, "EventSource": true, "WebSocket": true, "Ping": true, "": true}

// staticConfigRe is a configuration file right under an unknown root
// ({}/app-config.json, {}/manifest.json): a static file, no API's.
var staticConfigRe = regexp.MustCompile(`^\{\}/[\w.-]*(?:config|manifest|settings|env)[\w.-]*\.json$`)

// Build merges what the scripts call with the requests seen. InScope tells
// the target's hosts from third parties'.
func Build(scripts []Script, reqs []Request, inScope func(host string) bool) []Endpoint {
	// The bases each origin's scripts name: an app's settings (an inline
	// config, env-config.js) are on its pages, its clients in its bundles.
	var bases []string
	byOrigin := map[string][]string{}
	for _, s := range scripts {
		bases = append(bases, s.Bases...)
		if !isTrackerScript(s) {
			for _, u := range s.URLs {
				o := originOf(u)
				byOrigin[o] = append(byOrigin[o], s.Bases...)
			}
		}
	}
	bases = uniq(bases)
	origins := map[*Endpoint]map[string]bool{}

	// A document's $SLINK_HOST another page of the same portal (origin)
	// exports: the value, when the origin's scripts give it one only.
	docVars := map[string]map[string][]string{}
	for _, s := range scripts {
		for _, v := range s.DocVars {
			for _, u := range s.URLs {
				o := originOf(u)
				if docVars[o] == nil {
					docVars[o] = map[string][]string{}
				}
				docVars[o][v.Name] = append(docVars[o][v.Name], v.Value)
			}
		}
	}
	// Production's hosts the origin's tables of environments name, for
	// a variable a page sets to a development host (CMS_HOST).
	prod := map[string][]string{}
	dev := map[string]map[string][]string{}
	settingsBy := map[string][]jsapi.Header{}
	settingsByProp := map[string]map[string][]string{}
	var allSettings []jsapi.Header
	for _, s := range scripts {
		for _, u := range s.URLs {
			o := originOf(u)
			prod[o] = append(prod[o], s.DocProd...)
			for _, d := range s.DocDev {
				if dev[o] == nil {
					dev[o] = map[string][]string{}
				}
				dev[o][d.Name] = append(dev[o][d.Name], d.Value)
			}
			settingsBy[o] = append(settingsBy[o], s.Settings...)
			if !isTrackerScript(s) {
				addProp := func(name, val string) {
					if name == "" || val == "" {
						return
					}
					if settingsByProp[o] == nil {
						settingsByProp[o] = map[string][]string{}
					}
					pk := strings.ToLower(name)
					if !slices.Contains(settingsByProp[o][pk], val) {
						settingsByProp[o][pk] = append(settingsByProp[o][pk], val)
					}
				}
				for _, st := range s.Settings {
					addProp(st.Name, st.Value)
				}
				for _, pb := range s.PropBases {
					addProp(pb.Name, pb.Value)
				}
			}
		}
		allSettings = append(allSettings, s.Settings...)
	}
	docVar := func(s Script, name string) string {
		var vals []string
		for _, u := range s.URLs {
			vals = append(vals, docVars[originOf(u)][name]...)
		}
		if vals = uniq(vals); len(vals) == 1 {
			return vals[0]
		}
		if len(vals) == 0 {
			for _, u := range s.URLs {
				o := originOf(u)
				for _, d := range dev[o][name] {
					if p := jsapi.ProdOf(d, uniq(prod[o])); p != "" {
						vals = append(vals, p)
					}
				}
			}
			if vals = uniq(vals); len(vals) == 1 {
				return vals[0]
			}
		}
		return ""
	}
	hostSetting := func(s Script, mark string) string {
		var own []jsapi.Header
		for _, u := range s.URLs {
			own = append(own, settingsBy[originOf(u)]...)
		}
		if v := settingFor(mark, own); v != "" {
			return v
		}
		return settingFor(mark, allSettings)
	}
	byKey := map[string]*Endpoint{}
	var order []string
	for sIdx, s := range scripts {
		script := ""
		if len(s.URLs) > 0 {
			script = s.URLs[0]
		}
		for _, e := range s.Endpoints {
			host, path := split(e.URL)
			if detect.InfraPath(path) {
				continue // the CDN's own (/cdn-cgi/), on every site it fronts
			}
			// A page the code goes to (location.assign("/home"),
			// window.open("https://chatgpt.com/?q=…")) is the frontier's,
			// not an API's: only one that reads as an API's, in scope
			// (window.open("/api/export/pdf?id=…")), is an endpoint.
			if e.Kind == "navigation" && (host != "" && inScope != nil && !inScope(hostname(host)) || !jsapi.APILike(path)) {
				continue
			}
			// `${e}/app-config.json`: a file the caller's URL holds, no
			// API's (an API description aside).
			if e.NoInheritBase && host == "" && staticConfigRe.MatchString(path) && e.Kind != "openapi" {
				continue
			}
			key := e.Method + " " + host + " " + path
			ep := byKey[key]
			sTracker := isTrackerScript(s)
			if ep == nil {
				ep = &Endpoint{Method: e.Method, Host: host, Path: path, Status: Static, Kind: e.Kind, ThirdParty: sTracker,
					client: e.Client || strings.HasPrefix(path, unknownPrefix)}
				byKey[key] = ep
				order = append(order, key)
			}
			// A page's {}/detail is no API's; a document's endpoint has no base
			// the page's code gives (a portal documents many services).
			// An analytics collector's URL in a bundle (Snowplow's tp2) takes
			// none of the bases the bundle's own client has.
			ep.collector = ep.collector || e.Collector
			if ep.client && e.Kind != "navigation" && e.Kind != "doc" && !e.NoInheritBase {
				if origins[ep] == nil {
					origins[ep] = map[string]bool{}
				}
				for _, u := range s.URLs {
					origins[ep][originOf(u)] = true
				}
			}
			// A call (or a spec) tells more than a document's text, which
			// tells more than a bare string.
			if e.Kind != "string" && (ep.Kind == "string" || ep.Kind == "doc" && e.Kind != "doc") {
				ep.Kind = e.Kind
			}
			ep.ThirdParty = ep.ThirdParty && sTracker
			ep.bundleStatic = ep.bundleStatic || !s.Source
			for _, bk := range e.BaseKeys {
				if strings.HasPrefix(bk, "imp:") {
					ep.addBaseKey(fmt.Sprintf("imp:%d\x00%s", sIdx, strings.TrimPrefix(bk, "imp:")))
				} else {
					ep.addBaseKey(bk)
				}
			}
			ep.Query = append(ep.Query, e.Query...)
			ep.Body = append(ep.Body, e.Body...)
			ep.Headers = append(ep.Headers, e.Headers...)
			ep.Auth = append(ep.Auth, e.Auth...)
			ep.Operations = append(ep.Operations, e.Operations...)
			ep.Params = jsapi.MergeParams(ep.Params, e.Params)
			if e.Kind == "openapi" && host == "" && len(s.Bases) == 0 && e.Base == "" {
				// A description with no servers: its paths are its own
				// origin's (OpenAPI: "/" relative to where it is served), as
				// NestJS's /api-json is (PIP-03).
				for _, u := range s.URLs {
					if o := originOf(u); strings.Contains(o, "://") {
						ep.docBases = append(ep.docBases, o)
					}
				}
			}
			if b := e.Base; strings.HasPrefix(b, "$") {
				if v := docVar(s, b[1:]); v != "" {
					ep.docBases = append(ep.docBases, v)
				}
			} else if strings.HasPrefix(b, "<") {
				if v := hostSetting(s, b); v != "" {
					ep.docBases = append(ep.docBases, v)
				}
			} else if b != "" {
				ep.docBases = append(ep.docBases, b)
			}
			if len(ep.Static) < maxSources {
				ep.Static = append(ep.Static, Source{SHA256: s.SHA256, Script: script, Line: e.Line, Col: e.Col, Kind: e.Kind, Snippet: e.Snippet})
			}
		}
	}
	for _, ep := range byKey {
		if ep.collector {
			ep.ThirdParty = true
		}
	}
	dropped := mergeDocs(order, byKey)
	hints := linkModules(scripts, byKey, &order, origins, inScope)
	for ep, os := range origins {
		if hb := hints[ep]; len(hb) > 0 {
			// The caller names the setting its client is made with
			// (cfg.AUTH_API_URL): that setting's base, and no other.
			ep.Bases = PreferInScope(uniq(hb), inScope)
			continue
		}
		if len(ep.baseKeys) > 0 && !hasBoundClientKey(ep.baseKeys) {
			// Match explicit call-site base expressions (`prop:<name>`) strictly
			// against static base properties defined on the same origin; never fall
			// back to a hardcoded identifier allowlist or untagged origin pool.
			var propMatched []string
			for bk := range ep.baseKeys {
				prop, ok := strings.CutPrefix(bk, "prop:")
				if !ok || prop == "" {
					continue
				}
				pk := strings.ToLower(prop)
				for o := range os {
					propMatched = append(propMatched, settingsByProp[o][pk]...)
				}
			}
			if len(propMatched) > 0 {
				ep.Bases = baseFor(uniq(propMatched), ep.Path, ep.Kind, inScope)
			}
			continue
		}
		var own []string
		for o := range os {
			own = append(own, byOrigin[o]...)
		}
		// An origin whose scripts name no base borrows none of another's
		// (app-chat-core on api. is no client of the SDK's base on
		// cdn.): only scripts of no known origin take every base.
		known := false
		for o := range os {
			known = known || o != ""
		}
		if own = uniq(own); len(own) == 0 && !known {
			own = bases
		}
		ep.Bases = baseFor(own, ep.Path, ep.Kind, inScope)
	}
	for _, ep := range byKey {
		if len(ep.docBases) > 0 && (ep.Kind == "doc" || len(ep.Bases) == 0) {
			// The base the document exports for it, and no other.
			ep.Bases = PreferInScope(uniq(ep.docBases), inScope)
		}
	}
	siblingBases(byKey)
	// A path the code names without a method (a string) is the same
	// endpoint as the calls to it that have one.
	var eps []*Endpoint
	for _, k := range order {
		ep := byKey[k]
		if dropped[k] {
			continue
		}
		if ep.Method == "" {
			// The same with a base before it the code does not know
			// ({}/auth/exchange, a join(e.baseUrl, "/auth/exchange") of the
			// same path), or without one.
			alt := map[string]bool{ep.Path: true}
			if strings.HasPrefix(ep.Path, "/") {
				alt[placeholder+ep.Path] = true
			} else if p := strings.TrimPrefix(ep.Path, placeholder); p != ep.Path && strings.HasPrefix(p, "/") {
				alt[p] = true
			}
			var with []*Endpoint
			for _, o := range order {
				if other := byKey[o]; other.Method != "" && other.Host == ep.Host && alt[other.Path] {
					with = append(with, other)
				}
			}
			if len(with) > 0 {
				for _, w := range with {
					w.Static = append(w.Static, ep.Static...)
					w.Query = append(w.Query, ep.Query...)
					w.bundleStatic = w.bundleStatic || ep.bundleStatic
					w.addBaseKeys(ep.baseKeys)
				}
				continue
			}
		}
		eps = append(eps, ep)
	}
	for _, ep := range eps {
		ep.Origin = pageOrigin(ep, inScope)
	}
	eps = canonicalMerge(eps)
	for _, ep := range eps {
		ep.re = pattern(ep)
		for _, p := range strings.Split(ep.Path, placeholder) {
			if len(p) > len(ep.lit) {
				ep.lit = p
			}
		}
	}

	// Each request to the most specific endpoint of the code it matches;
	// the others are grouped by template.
	idx := newIndex(eps)
	var rest []Request
	for _, r := range reqs {
		other := r.ResourceType == "Other"
		if !apiTypes[r.ResourceType] && !other {
			continue
		}
		host, path, query, ok := parts(r.URL)
		if !ok || detect.InfraPath(path) {
			continue
		}
		if best := match(idx.candidates(path), r.Method, host, path, inScope); best != nil {
			best.observe(r, host, path, query)
			continue
		}
		if !other {
			rest = append(rest, r)
		}
	}
	calls := make([]flow.Call, len(rest))
	for i, r := range rest {
		calls[i] = flow.Call{Method: r.Method, URL: r.URL, Frame: r.Initiator}
	}
	templates := flow.Templates(calls)
	seen := map[string]*Endpoint{}
	for i, r := range rest {
		host, path, query, _ := parts(r.URL)
		key := r.Method + " " + host + " " + templates[i]
		ep := seen[key]
		if ep == nil {
			ep = &Endpoint{Method: r.Method, Host: host, Path: templates[i], Status: ObservedOnly, Kind: kindOf(r.ResourceType),
				ThirdParty: !inScope(hostname(host))}
			seen[key] = ep
			eps = append(eps, ep)
		}
		ep.observe(r, host, path, query)
	}

	// ENH-01: preserve the observed host when a cross-origin client endpoint
	// was matched to traffic (same-origin endpoints keep Host == "" per
	// Invariant #16).
	for _, ep := range eps {
		if ep.Host == "" && len(ep.obsHosts) == 1 {
			var oh string
			for h := range ep.obsHosts {
				oh = h
			}
			so := ep.Origin
			if so == "" {
				so = epScriptOrigin(ep, inScope)
			}
			hasScriptURL := false
			for _, src := range ep.Static {
				if src.Script != "" {
					hasScriptURL = true
					break
				}
			}
			pageHost := ""
			if so != "" {
				_, rawH, _ := strings.Cut(so, "://")
				pageHost = canonHost(rawH)
			}
			if oh != "" && hasScriptURL && !strings.EqualFold(oh, pageHost) {
				ep.Host = oh
				ep.Bases = nil
			}
		}
	}

	// ENH-10 (provenance-scoped): propagate a confirmed same-origin client base
	// (/rest) only to sibling client endpoints of the same origin that share its
	// BaseKey provenance (e.g. `prop:baseUrl`), never onto distinct host settings
	// (`prop:templatesHost`) or unbound wrapper parameters (`param:...`).
	obsBaseByOriginKey := map[string]map[string]bool{}
	obsBaseUntagged := map[string]map[string]bool{}
	obsOriginHasKeyed := map[string]bool{}
	for _, ep := range eps {
		if !ep.client || ep.Host != "" || hasStaticAssetExt(ep.Path) {
			continue
		}
		candBase := ""
		if ep.Base != "" && isAPIPropagatableBase(ep.Base) {
			candBase = ep.Base
		} else if ep.Base == "" && ep.Observed != nil && len(ep.baseKeys) > 0 && !strings.HasPrefix(ep.Path, placeholder) {
			// When a boot call's base (e.g. JSON.parse('{"baseUrl":"/rest"}')) already
			// resolved statically into ep.Path AND traffic confirmed it at runtime,
			// record that leading API root segment for sibling calls sharing ep.baseKeys.
			seg, restPath, ok := strings.Cut(strings.TrimPrefix(ep.Path, "/"), "/")
			if ok && seg != "" && restPath != "" && !strings.Contains(seg, placeholder) && obsAPIRootSegRe.MatchString(seg) {
				candBase = "/" + seg
			}
		}
		if candBase == "" {
			continue
		}
		so := epScriptOrigin(ep, inScope)
		if so == "" {
			continue
		}
		if len(ep.baseKeys) > 0 {
			obsOriginHasKeyed[so] = true
			for bk := range ep.baseKeys {
				ok := so + "\x00" + canonBaseKey(bk)
				if obsBaseByOriginKey[ok] == nil {
					obsBaseByOriginKey[ok] = map[string]bool{}
				}
				obsBaseByOriginKey[ok][candBase] = true
			}
		} else {
			if obsBaseUntagged[so] == nil {
				obsBaseUntagged[so] = map[string]bool{}
			}
			obsBaseUntagged[so][candBase] = true
		}
	}
	obsSegByHost := map[string]map[string]bool{}
	for _, ep := range eps {
		if ep.Observed != nil && !ep.ThirdParty && !detect.InfraPath(ep.Path) {
			rawPaths := []string{ep.Path}
			if ep.Base != "" && strings.HasPrefix(ep.Base, "/") {
				rawPaths = []string{ep.Base + "/" + strings.TrimPrefix(strings.TrimPrefix(ep.Path, placeholder), "/")}
			}
			rawPaths = append(rawPaths, ep.Observed.Samples...)
			for _, rp := range rawPaths {
				if u, err := url.Parse(rp); err == nil && u.Path != "" {
					rp = u.Path
				}
				if hasStaticAssetExt(rp) {
					continue
				}
				p := strings.TrimPrefix(strings.TrimPrefix(rp, placeholder), "/")
				seg, restPath, ok := strings.Cut(p, "/")
				if ok && seg != "" && restPath != "" && !strings.Contains(seg, placeholder) && obsAPIRootSegRe.MatchString(seg) {
					addHost := func(h string) {
						if ch := canonHost(h); ch != "" {
							if obsSegByHost[ch] == nil {
								obsSegByHost[ch] = map[string]bool{}
							}
							obsSegByHost[ch]["/"+seg] = true
						}
					}
					if ep.Host != "" {
						addHost(ep.Host)
					}
					for h := range ep.obsHosts {
						addHost(h)
					}
					break
				}
			}
		}
	}
	for _, ep := range eps {
		if !ep.client || ep.Base != "" || ep.Host != "" || ep.ThirdParty || ep.collector || ep.Kind == "doc" || hasInScopeBase(ep.Bases, inScope) {
			continue
		}
		so := epScriptOrigin(ep, inScope)
		if so == "" {
			continue
		}
		var cands map[string]bool
		if len(ep.baseKeys) > 0 {
			merged := map[string]bool{}
			for bk := range ep.baseKeys {
				for ob := range obsBaseByOriginKey[so+"\x00"+canonBaseKey(bk)] {
					merged[ob] = true
				}
			}
			if len(merged) > 0 {
				cands = merged
			} else if !obsOriginHasKeyed[so] && hasBoundClientKey(ep.baseKeys) {
				cands = obsBaseUntagged[so]
				if len(cands) == 0 {
					_, rawH, _ := strings.Cut(so, "://")
					cands = obsSegByHost[canonHost(rawH)]
				}
			}
		} else if !obsOriginHasKeyed[so] {
			cands = obsBaseUntagged[so]
			if len(cands) == 0 {
				_, rawH, _ := strings.Cut(so, "://")
				cands = obsSegByHost[canonHost(rawH)]
			}
		}
		if len(cands) == 1 {
			for ob := range cands {
				ep.Bases = []string{so + ob}
			}
		}
	}
	rebindDevLoopbackEndpoints(scripts, eps, inScope)
	eps = canonicalMerge(eps)

	attachGraphQLDocs(scripts, eps, inScope)
	out := make([]Endpoint, 0, len(eps))
	for _, ep := range eps {
		ep.Query, ep.Body, ep.Headers, ep.Auth, ep.Operations = uniq(ep.Query), uniq(ep.Body), uniq(ep.Headers), uniq(ep.Auth), uniq(ep.Operations)
		if ep.Observed != nil {
			ep.Observed.Outcomes = uniq(ep.Observed.Outcomes)
			ep.Observed.Runs = len(ep.runs)
			if ep.Static != nil {
				ep.Status = Both
			}
		}
		if ep.Base != "" {
			ep.Bases = nil
		}
		if ep.Host != "" && !ep.client {
			ep.ThirdParty = ep.ThirdParty || !inScope(hostname(ep.Host))
		} else if ep.Host == "" && len(ep.Bases) > 0 && inScope != nil && allOutOfScopeBases(ep.Bases, inScope) {
			ep.ThirdParty = true
		}
		ep.SourceOnly = !ep.bundleStatic && ep.Observed == nil && len(ep.Static) > 0
		ep.Confidence = confidence(ep)
		out = append(out, *ep)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Method < b.Method
	})
	return out
}

// linkModules joins the calls to an imported function with the request
// the module exporting it makes (COV-04): the caller's object is the
// body, the setting it names (cfg.AUTH_API_URL) the base. A setting given
// to a client factory, through an export or by a call in its own script
// (a(e.CLIENT_API_URL)), is the base of every request its methods make,
// exported or not. It returns those bases by endpoint.
func linkModules(scripts []Script, byKey map[string]*Endpoint, order *[]string, origins map[*Endpoint]map[string]bool, inScope func(host string) bool) map[*Endpoint][]string {
	settings := map[string][]string{}
	type indexedExport struct {
		jsapi.Export
		si int
	}
	bundlerExports := map[string][]indexedExport{}
	esmScripts := map[string][]int{}
	esmByBase := map[string][]int{}
	baseCount := map[string]int{}
	smapExact := map[string][]int{}
	smapSuffix := map[string][]int{}
	smapPkg := map[string][]int{}
	scriptSmapPaths := make([][]string, len(scripts))
	scriptOrigins := make([][]string, len(scripts))

	cleanModURL := func(raw string) string {
		if strings.Contains(raw, "#") {
			return ""
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return ""
		}
		return strings.ToLower(u.Scheme+"://"+u.Host) + u.EscapedPath()
	}
	appendUniqInt := func(m map[string][]int, k string, v int) {
		if !slices.Contains(m[k], v) {
			m[k] = append(m[k], v)
		}
	}

	for si, s := range scripts {
		if isTrackerScript(s) {
			continue
		}
		seenBases := map[string]bool{}
		for _, raw := range s.URLs {
			baseRaw, frag, hasFrag := strings.Cut(raw, "#")
			orig := originOf(baseRaw)
			if !slices.Contains(scriptOrigins[si], orig) {
				scriptOrigins[si] = append(scriptOrigins[si], orig)
			}
			if hasFrag {
				np := normSourcePath(frag)
				if np == "" {
					continue
				}
				if !slices.Contains(scriptSmapPaths[si], np) {
					scriptSmapPaths[si] = append(scriptSmapPaths[si], np)
				}
				noExt := stripSourceExt(np)
				appendUniqInt(smapExact, orig+"\x00"+noExt, si)
				if path.Base(noExt) == "index" && path.Dir(noExt) != "." {
					appendUniqInt(smapExact, orig+"\x00"+path.Dir(noExt), si)
				}
				segs := strings.Split(noExt, "/")
				for n := 2; n <= min(5, len(segs)); n++ {
					sfx := strings.Join(segs[len(segs)-n:], "/")
					appendUniqInt(smapSuffix, orig+"\x00"+sfx, si)
					if segs[len(segs)-1] == "index" && n >= 3 {
						dirSfx := strings.Join(segs[len(segs)-n:len(segs)-1], "/")
						appendUniqInt(smapSuffix, orig+"\x00"+dirSfx, si)
					}
				}
				if pkg := extractSmapPkg(noExt); pkg != "" {
					appendUniqInt(smapPkg, orig+"\x00"+pkg, si)
				}
				continue
			}
			if cu := cleanModURL(raw); cu != "" {
				appendUniqInt(esmScripts, cu, si)
			}
			if u, err := url.Parse(raw); err == nil && u.Path != "" {
				if b := path.Base(u.Path); b != "" && b != "." && b != "/" && !seenBases[b] {
					seenBases[b] = true
					baseCount[b]++
					appendUniqInt(esmByBase, b, si)
				}
			}
		}
	}

	factories := map[string]jsapi.Factory{} // by sha and id
	given := map[string][]string{}          // the settings each factory is given
	for si, s := range scripts {
		if isTrackerScript(s) {
			continue
		}
		for _, st := range s.Settings {
			if !slices.Contains(settings[st.Name], st.Value) {
				settings[st.Name] = append(settings[st.Name], st.Value)
			}
		}
		for _, pb := range s.PropBases {
			if !slices.Contains(settings[pb.Name], pb.Value) {
				settings[pb.Name] = append(settings[pb.Name], pb.Value)
			}
		}
		for _, ex := range s.Exports {
			if ex.Module != "" {
				k := ex.Module + "\x00" + ex.Name
				bundlerExports[k] = append(bundlerExports[k], indexedExport{ex, si})
			}
		}
		for _, f := range s.Factories {
			k := s.SHA256 + "\x00" + f.ID
			factories[k] = f
			given[k] = append(given[k], f.Settings...)
		}
	}

	lookup := func(methodURL string) *Endpoint {
		method, u, _ := strings.Cut(methodURL, " ")
		host, p := split(u)
		if ep := byKey[method+" "+host+" "+p]; ep != nil {
			return ep
		}
		if host == "" && strings.HasPrefix(p, "/") {
			return byKey[method+"  "+placeholder+p]
		}
		return nil
	}

	// targetScripts finds candidate module scripts for (callerIdx, spec) across
	// HTTP ESM URLs and SourceMap virtual paths (`#<sourcePath>`).
	targetScripts := func(callerIdx int, spec string) (targets []int, allowLocalFallback bool) {
		cs := scripts[callerIdx]
		addAll := func(ids []int) {
			for _, id := range ids {
				if !slices.Contains(targets, id) {
					targets = append(targets, id)
				}
			}
		}
		// 1. SourceMap virtual path namespace (when caller has `#<sourcePath>`)
		if len(scriptSmapPaths[callerIdx]) > 0 {
			origs := scriptOrigins[callerIdx]
			if len(origs) == 0 {
				origs = []string{""}
			}
			switch {
			case strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../"):
				for _, cp := range scriptSmapPaths[callerIdx] {
					joined := stripSourceExt(normSourcePath(path.Dir(cp) + "/" + spec))
					for _, orig := range origs {
						addAll(smapExact[orig+"\x00"+joined])
					}
					if len(targets) == 0 {
						segs := strings.Split(joined, "/")
						if len(segs) >= 2 {
							sfx := strings.Join(segs[max(0, len(segs)-3):], "/")
							for _, orig := range origs {
								addAll(smapSuffix[orig+"\x00"+sfx])
							}
						}
					}
				}
				return targets, false
			case strings.HasPrefix(spec, "@/") || strings.HasPrefix(spec, "~/"):
				sub := stripSourceExt(strings.TrimPrefix(strings.TrimPrefix(spec, "@/"), "~/"))
				for _, orig := range origs {
					addAll(smapSuffix[orig+"\x00src/"+sub])
					addAll(smapSuffix[orig+"\x00"+sub])
				}
				return targets, false
			default:
				cleanSpec := stripSourceExt(strings.TrimPrefix(spec, "/"))
				for _, orig := range origs {
					addAll(smapExact[orig+"\x00"+cleanSpec])
					addAll(smapSuffix[orig+"\x00"+cleanSpec])
				}
				if len(targets) > 0 {
					return targets, false
				}
				pkg := specPkgRoot(spec)
				if pkg != "" {
					for _, orig := range origs {
						addAll(smapPkg[orig+"\x00"+pkg])
					}
					if len(targets) > 0 {
						return targets, true
					}
				}
			}
		}
		// 2. HTTP ESM URL namespace
		if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") {
			if rel, err := url.Parse(spec); err == nil {
				for _, raw := range cs.URLs {
					if strings.Contains(raw, "#") {
						continue
					}
					bu, berr := url.Parse(raw)
					if berr != nil {
						continue
					}
					if cu := cleanModURL(bu.ResolveReference(rel).String()); cu != "" {
						addAll(esmScripts[cu])
					}
				}
			}
			if len(targets) == 0 {
				if b := path.Base(spec); b != "" && baseCount[b] == 1 {
					addAll(esmByBase[b])
				}
			}
		}
		return targets, false
	}

	hints := map[*Endpoint][]string{}
	validHTTPMethod := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}

	extractExportKeys := func(ex jsapi.Export, args []jsapi.ImportArg) (qOut, bOut []string) {
		getK := func(idx int, prop string) []string {
			if idx < 0 || idx >= len(args) {
				return nil
			}
			if prop != "" {
				return args[idx].PropKeys[prop]
			}
			return args[idx].Keys
		}
		same := ex.BodyArg >= 0 && ex.BodyArg == ex.QueryArg && ex.BodyProp == ex.QueryProp
		if same {
			if ex.Method == "GET" || ex.Method == "HEAD" || ex.Method == "DELETE" {
				qOut = append(qOut, getK(ex.QueryArg, ex.QueryProp)...)
			} else if ex.Method != "" {
				bOut = append(bOut, getK(ex.BodyArg, ex.BodyProp)...)
			}
			return qOut, bOut
		}
		qOut = append(qOut, getK(ex.QueryArg, ex.QueryProp)...)
		bOut = append(bOut, getK(ex.BodyArg, ex.BodyProp)...)
		if (ex.Method == "GET" || ex.Method == "HEAD") && len(bOut) > 0 {
			qOut = append(qOut, bOut...)
			bOut = nil
		}
		return qOut, bOut
	}

	type constKey struct {
		mod, exp, key string
	}
	scriptConsts := make([]map[constKey]constSlot, len(scripts))
	bundlerConsts := map[[4]string]constSlot{}
	putSlot := func(m map[constKey]constSlot, ck constKey, val string) {
		if val == "" {
			return
		}
		if cur, ok := m[ck]; ok {
			if cur.val != val {
				cur.clashed = true
				m[ck] = cur
			}
			return
		}
		m[ck] = constSlot{val: val}
	}
	putBundlerConst := func(orig, mod, exp, key, val string) {
		if val == "" {
			return
		}
		bk := [4]string{orig, mod, exp, key}
		if cur, ok := bundlerConsts[bk]; ok {
			if cur.val != val {
				cur.clashed = true
				bundlerConsts[bk] = cur
			}
			return
		}
		bundlerConsts[bk] = constSlot{val: val}
	}
	for si, s := range scripts {
		if len(s.ConstExports) == 0 || isTrackerScript(s) {
			continue
		}
		sm := map[constKey]constSlot{}
		origs := scriptOrigins[si]
		if len(origs) == 0 {
			origs = []string{""}
		}
		for _, cd := range s.ConstExports {
			for k, v := range cd.Values {
				putSlot(sm, constKey{cd.Module, cd.Export, k}, v)
				if cd.Module != "" {
					for _, orig := range origs {
						putBundlerConst(orig, cd.Module, cd.Export, k, v)
					}
				}
			}
			if cd.Scalar != "" {
				putSlot(sm, constKey{cd.Module, cd.Export, ""}, cd.Scalar)
				if cd.Module != "" {
					for _, orig := range origs {
						putBundlerConst(orig, cd.Module, cd.Export, "", cd.Scalar)
					}
				}
			}
		}
		scriptConsts[si] = sm
	}

	lookupSlotInMap := func(sm map[constKey]constSlot, mod, exp, key string) (string, bool) {
		if len(sm) == 0 {
			return "", false
		}
		if sl, ok := sm[constKey{mod, exp, key}]; ok && !sl.clashed {
			return sl.val, true
		}
		if exp == "a" || exp == "default" {
			if sl, ok := sm[constKey{mod, "*", key}]; ok && !sl.clashed {
				return sl.val, true
			}
		}
		if exp != "*" && exp != "" && key != "" {
			if sl, ok := sm[constKey{mod, "*", exp + "." + key}]; ok && !sl.clashed {
				return sl.val, true
			}
		}
		return "", false
	}

	lookupBundlerSlot := func(orig, mod, exp, key string) (string, bool) {
		if sl, ok := bundlerConsts[[4]string{orig, mod, exp, key}]; ok && !sl.clashed {
			return sl.val, true
		}
		if exp == "a" || exp == "default" {
			if sl, ok := bundlerConsts[[4]string{orig, mod, "*", key}]; ok && !sl.clashed {
				return sl.val, true
			}
		}
		if exp != "*" && exp != "" && key != "" {
			if sl, ok := bundlerConsts[[4]string{orig, mod, "*", exp + "." + key}]; ok && !sl.clashed {
				return sl.val, true
			}
		}
		return "", false
	}

	var resolveConstAt func(curIdx int, modSpec, expName, key string, hop int) (string, bool)
	resolveConstAt = func(curIdx int, modSpec, expName, key string, hop int) (string, bool) {
		if hop > 4 || modSpec == "" || expName == "" {
			return "", false
		}
		tids, _ := targetScripts(curIdx, modSpec)
		if len(tids) > 0 {
			resolved := ""
			for _, tid := range tids {
				if v, ok := lookupSlotInMap(scriptConsts[tid], "", expName, key); ok {
					if resolved != "" && resolved != v {
						return "", false
					}
					resolved = v
					continue
				}
				for _, re := range scripts[tid].ReExports {
					var sub string
					var rok bool
					if re.All {
						sub, rok = resolveConstAt(tid, re.Module, expName, key, hop+1)
					} else if re.Name == expName && re.Target != "" && re.Target != "*" {
						sub, rok = resolveConstAt(tid, re.Module, re.Target, key, hop+1)
					}
					if rok {
						if resolved != "" && resolved != sub {
							return "", false
						}
						resolved = sub
					}
				}
			}
			if resolved != "" {
				return resolved, true
			}
		}
		if !strings.HasPrefix(modSpec, ".") && !strings.HasPrefix(modSpec, "/") {
			origs := scriptOrigins[curIdx]
			if len(origs) == 0 {
				origs = []string{""}
			}
			resolved := ""
			for _, orig := range origs {
				if v, ok := lookupBundlerSlot(orig, modSpec, expName, key); ok {
					if resolved != "" && resolved != v {
						return "", false
					}
					resolved = v
				}
			}
			if resolved != "" {
				return resolved, true
			}
		}
		return "", false
	}

	isValidConstEndpointVal := func(v string, hasBasePrefix bool) bool {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 512 || strings.ContainsAny(v, " \t\r\n<>\"'`\\") {
			return false
		}
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "//") || (strings.HasPrefix(v, "/") && len(v) > 1) {
			return true
		}
		if strings.Contains(v, "/") {
			return !hasStaticAssetExt(v)
		}
		if !hasBasePrefix {
			return false
		}
		hasAlpha := false
		for i := 0; i < len(v); i++ {
			c := v[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
				hasAlpha = true
			case c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			default:
				return false
			}
		}
		return hasAlpha && len(v) >= 2 && !hasStaticAssetExt(v)
	}

	applyLeaf := func(callerIdx int, caller Script, im jsapi.Import, ex indexedExport, effArgs []jsapi.ImportArg, viaQ, viaB []string) {
		exScript := scripts[ex.si]
		if !ex.ParamURL {
			ep := lookup(ex.Method + " " + ex.URL)
			if ep != nil {
				ep.Query = append(ep.Query, viaQ...)
				if ex.QueryArg >= 0 && ex.QueryArg < len(effArgs) {
					ep.Query = append(ep.Query, effArgs[ex.QueryArg].Keys...)
				}
				ep.Body = append(ep.Body, viaB...)
				if ex.BodyArg >= 0 && ex.BodyArg < len(effArgs) {
					ep.Body = append(ep.Body, effArgs[ex.BodyArg].Keys...)
				}
				ep.bundleStatic = ep.bundleStatic || !caller.Source
			}
			if ex.BaseArg < 0 || ex.BaseArg >= len(effArgs) {
				return
			}
			name := effArgs[ex.BaseArg].Setting
			if name == "" {
				name, _ = strings.CutPrefix(effArgs[ex.BaseArg].BaseKey, "prop:")
			}
			if name == "" {
				return
			}
			if ex.Factory != "" {
				k := exScript.SHA256 + "\x00" + ex.Factory
				if !slices.Contains(given[k], name) {
					given[k] = append(given[k], name)
				}
			} else if ep != nil {
				hints[ep] = append(hints[ep], settings[name]...)
			}
			return
		}

		// Parameterized wrapper Export (ParamURL == true)
		if ex.URLArg < 0 || ex.URLArg >= len(effArgs) {
			return
		}
		hasBasePrefix := ex.URLPrefix != "" || ex.HasDynBase || ex.BaseArg >= 0
		var rawURLs []string
		if ex.URLProp != "" {
			rawURLs = effArgs[ex.URLArg].PropValues[ex.URLProp]
			if len(rawURLs) == 0 && ex.URLProp == "endpoint" {
				rawURLs = effArgs[ex.URLArg].PropValues["url"]
			} else if len(rawURLs) == 0 && ex.URLProp == "url" {
				rawURLs = effArgs[ex.URLArg].PropValues["endpoint"]
			}
		} else {
			ua := effArgs[ex.URLArg]
			if ua.ConstRef != nil {
				if cv, cok := resolveConstAt(callerIdx, ua.ConstRef.Module, ua.ConstRef.Export, ua.ConstRef.Key, 0); cok {
					joinedConst := cv
					if ua.ConstSuffix != "" {
						if strings.HasSuffix(joinedConst, "/") && strings.HasPrefix(ua.ConstSuffix, "/") {
							joinedConst += strings.TrimPrefix(ua.ConstSuffix, "/")
						} else {
							joinedConst += ua.ConstSuffix
						}
					}
					if isValidConstEndpointVal(joinedConst, hasBasePrefix) {
						rawURLs = []string{joinedConst}
					}
				}
			}
			if len(rawURLs) == 0 {
				rawURLs = ua.Values
			}
			if len(rawURLs) == 0 && hasBasePrefix && len(ua.RelValues) > 0 {
				rawURLs = ua.RelValues
			}
		}
		if len(rawURLs) == 0 {
			return
		}

		var concreteBases []string
		if ex.BaseArg >= 0 && ex.BaseArg < len(effArgs) {
			var bCands []string
			if ex.BaseProp != "" {
				bCands = effArgs[ex.BaseArg].PropValues[ex.BaseProp]
				if len(bCands) == 0 && ex.BaseProp == "baseURL" {
					bCands = effArgs[ex.BaseArg].PropValues["baseUrl"]
				} else if len(bCands) == 0 && ex.BaseProp == "baseUrl" {
					bCands = effArgs[ex.BaseArg].PropValues["baseURL"]
				}
			} else {
				bCands = effArgs[ex.BaseArg].Values
			}
			for _, bv := range bCands {
				bv = strings.TrimSpace(bv)
				if bv == "" || strings.Contains(bv, placeholder) || validHTTPMethod[strings.ToUpper(bv)] {
					continue
				}
				if strings.HasPrefix(bv, "http://") || strings.HasPrefix(bv, "https://") || strings.HasPrefix(bv, "//") || (strings.HasPrefix(bv, "/") && len(bv) > 1) {
					if !slices.Contains(concreteBases, bv) {
						concreteBases = append(concreteBases, bv)
					}
				}
			}
		}
		if len(concreteBases) > 0 {
			var joined []string
			for _, rawU := range rawURLs {
				uTrim := strings.TrimSpace(rawU)
				if strings.Contains(uTrim, "://") || strings.HasPrefix(uTrim, "//") {
					joined = append(joined, uTrim)
					continue
				}
				for _, cb := range concreteBases {
					joined = append(joined, strings.TrimRight(cb, "/")+"/"+strings.TrimLeft(uTrim, "/"))
				}
			}
			rawURLs = joined
		}

		var methods []string
		if ex.Method != "" {
			methods = []string{ex.Method}
		} else if ex.ParamMethod {
			if ex.MethodArg < 0 || ex.MethodArg >= len(effArgs) {
				return
			}
			var mCands []string
			if ex.MethodProp != "" {
				mCands = effArgs[ex.MethodArg].PropValues[ex.MethodProp]
			} else {
				mCands = effArgs[ex.MethodArg].Values
			}
			for _, m := range mCands {
				um := strings.ToUpper(strings.TrimSpace(m))
				if validHTTPMethod[um] && !slices.Contains(methods, um) {
					methods = append(methods, um)
				}
			}
			if len(methods) == 0 {
				return
			}
		} else {
			methods = []string{""}
		}

		argKeys := func(idx int, prop string) []string {
			if idx < 0 || idx >= len(effArgs) {
				return nil
			}
			if prop != "" {
				return effArgs[idx].PropKeys[prop]
			}
			return effArgs[idx].Keys
		}
		sameDataSlot := ex.BodyArg >= 0 && ex.BodyArg == ex.QueryArg && ex.BodyProp == ex.QueryProp

		scriptURL := ""
		if len(caller.URLs) > 0 {
			scriptURL = caller.URLs[0]
		}
		var headerList []string
		if ex.HeaderNames != "" {
			headerList = strings.Split(ex.HeaderNames, ",")
		}

		var leafBaseKeys []string
		if ex.BaseArg >= 0 && ex.BaseArg < len(effArgs) {
			ba := effArgs[ex.BaseArg]
			if ex.BaseProp != "" {
				pbk := ba.PropBaseKeys[ex.BaseProp]
				if pbk == "" && ex.BaseProp == "baseURL" {
					pbk = ba.PropBaseKeys["baseUrl"]
				} else if pbk == "" && ex.BaseProp == "baseUrl" {
					pbk = ba.PropBaseKeys["baseURL"]
				}
				if pbk != "" {
					leafBaseKeys = append(leafBaseKeys, pbk)
				} else {
					leafBaseKeys = append(leafBaseKeys, "prop:"+ex.BaseProp)
				}
			} else if ba.BaseKey != "" {
				leafBaseKeys = append(leafBaseKeys, ba.BaseKey)
			} else if ba.Setting != "" {
				leafBaseKeys = append(leafBaseKeys, "prop:"+ba.Setting)
			}
		} else if ex.BaseProp != "" {
			leafBaseKeys = append(leafBaseKeys, "prop:"+ex.BaseProp)
		} else if ex.BaseArg < 0 && ex.HasDynBase && ex.Name != "" {
			leafBaseKeys = append(leafBaseKeys, "exp:"+exScript.SHA256+"\x00"+ex.Name)
		}

		for _, method := range methods {
			qKeys := slices.Clone(viaQ)
			bKeys := slices.Clone(viaB)
			if sameDataSlot {
				if method == "GET" || method == "HEAD" || method == "DELETE" {
					qKeys = append(qKeys, argKeys(ex.QueryArg, ex.QueryProp)...)
				} else {
					bKeys = append(bKeys, argKeys(ex.BodyArg, ex.BodyProp)...)
				}
			} else {
				qKeys = append(qKeys, argKeys(ex.QueryArg, ex.QueryProp)...)
				bKeys = append(bKeys, argKeys(ex.BodyArg, ex.BodyProp)...)
				if (method == "GET" || method == "HEAD") && len(bKeys) > 0 {
					qKeys = append(qKeys, bKeys...)
					bKeys = nil
				}
			}
			if (method == "GET" || method == "HEAD") && len(bKeys) > 0 {
				qKeys = append(qKeys, bKeys...)
				bKeys = nil
			}
			qKeys = append(qKeys, effArgs[ex.URLArg].Query...)

			for _, rawU := range rawURLs {
				uStr := strings.TrimSpace(rawU)
				if ex.URLPrefix != "" && !strings.Contains(uStr, "://") && !strings.HasPrefix(uStr, "//") && !strings.HasPrefix(uStr, ex.URLPrefix+"/") && uStr != ex.URLPrefix {
					if strings.HasPrefix(uStr, "/") {
						uStr = ex.URLPrefix + uStr
					} else {
						uStr = ex.URLPrefix + "/" + uStr
					}
				}
				if ex.URLSuffix != "" {
					uBasePath, uBaseQ, hasBaseQ := strings.Cut(uStr, "?")
					sfxPath, sfxQ, hasSfxQ := strings.Cut(ex.URLSuffix, "?")
					if sfxPath != "" {
						if strings.HasSuffix(uBasePath, "/") && strings.HasPrefix(sfxPath, "/") {
							uBasePath += strings.TrimPrefix(sfxPath, "/")
						} else {
							uBasePath += sfxPath
						}
					}
					switch {
					case hasBaseQ && uBaseQ != "" && hasSfxQ && sfxQ != "":
						uStr = uBasePath + "?" + uBaseQ + "&" + sfxQ
					case hasBaseQ && uBaseQ != "":
						uStr = uBasePath + "?" + uBaseQ
					case hasSfxQ && sfxQ != "":
						uStr = uBasePath + "?" + sfxQ
					default:
						uStr = uBasePath
					}
				}
				uPath, uQuery, _ := strings.Cut(uStr, "?")
				if uPath == "" || strings.Trim(strings.ReplaceAll(uPath, placeholder, ""), "/") == "" {
					continue
				}
				host, p := split(uPath)
				if p == "" || detect.InfraPath(p) {
					continue
				}
				if host == "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, placeholder+"/") {
					continue
				}
				outOfScope := host != "" && inScope != nil && !inScope(hostname(host))
				callerTracker := isTrackerScript(caller)
				if outOfScope && callerTracker {
					continue
				}
				isClient := (ex.HasDynBase || ex.BaseArg >= 0) && host == ""
				if isClient && strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
					p = placeholder + p
				}
				if host == "" && staticConfigRe.MatchString(p) {
					continue
				}
				localQ := slices.Clone(qKeys)
				for _, kv := range strings.Split(uQuery, "&") {
					if k, _, _ := strings.Cut(kv, "="); k != "" && k != placeholder && !strings.Contains(k, "{") {
						localQ = append(localQ, k)
					}
				}
				epThirdParty := callerTracker || outOfScope
				key := method + " " + host + " " + p
				ep := byKey[key]
				if ep == nil {
					ep = &Endpoint{Method: method, Host: host, Path: p, Status: Static, Kind: "wrapper",
						ThirdParty: epThirdParty, client: isClient || strings.HasPrefix(p, unknownPrefix)}
					byKey[key] = ep
					*order = append(*order, key)
				}
				if ep.Kind == "string" || ep.Kind == "doc" {
					ep.Kind = "wrapper"
				}
				ep.ThirdParty = ep.ThirdParty && epThirdParty
				ep.bundleStatic = ep.bundleStatic || !caller.Source
				if ep.client {
					for _, bk := range leafBaseKeys {
						ep.addBaseKey(bk)
					}
				}
				ep.Query = append(ep.Query, localQ...)
				ep.Body = append(ep.Body, bKeys...)
				ep.Headers = append(ep.Headers, headerList...)
				if ep.client {
					if origins[ep] == nil {
						origins[ep] = map[string]bool{}
					}
					for _, cu := range caller.URLs {
						origins[ep][originOf(cu)] = true
					}
				}
				if len(ep.Static) < maxSources {
					ep.Static = append(ep.Static, Source{SHA256: caller.SHA256, Script: scriptURL, Line: im.Line, Col: im.Col, Kind: "wrapper", Snippet: im.Snippet})
				}
				if ex.BaseArg >= 0 && ex.BaseArg < len(effArgs) {
					if stName := effArgs[ex.BaseArg].Setting; stName != "" {
						hints[ep] = append(hints[ep], settings[stName]...)
					}
				}
			}
		}
	}

	const maxModuleDepth = 8
	for callerIdx, s := range scripts {
		if isTrackerScript(s) || len(s.Imports) == 0 {
			continue
		}
		for _, im := range s.Imports {
			applied := map[string]bool{}
			visited := map[string]bool{}
			var resolveChain func(curIdx int, modSpec, expName string, curArgs []jsapi.ImportArg, viaQ, viaB []string, depth int) bool
			resolveChain = func(curIdx int, modSpec, expName string, curArgs []jsapi.ImportArg, viaQ, viaB []string, depth int) bool {
				if depth > maxModuleDepth {
					return false
				}
				extendKeys := func(ex jsapi.Export) (nq, nb []string) {
					hq, hb := extractExportKeys(ex, curArgs)
					nq = uniq(append(slices.Clone(viaQ), hq...))
					nb = uniq(append(slices.Clone(viaB), hb...))
					return nq, nb
				}
				// 1. Bundler numeric/string ID namespace
				if bes := bundlerExports[modSpec+"\x00"+expName]; len(bes) > 0 {
					found := false
					for bi, be := range bes {
						vk := fmt.Sprintf("b:%s\x00%s\x00%d\x00%d", modSpec, expName, be.si, bi)
						if visited[vk] {
							found = true
							continue
						}
						visited[vk] = true
						found = true
						if be.Via != nil {
							nq, nb := extendKeys(be.Export)
							if !resolveChain(be.si, be.Via.Module, be.Via.Name, composeViaArgs(be.Via.Args, curArgs), nq, nb, depth+1) && (be.ParamURL || be.URL != "") && !applied[vk] {
								applied[vk] = true
								applyLeaf(callerIdx, s, im, be, curArgs, viaQ, viaB)
							}
						} else if !applied[vk] {
							applied[vk] = true
							applyLeaf(callerIdx, s, im, be, curArgs, viaQ, viaB)
						}
						delete(visited, vk)
					}
					return found
				}

				// 2. HTTP ESM URL & SourceMap Virtual Path namespaces
				tids, allowLocal := targetScripts(curIdx, modSpec)
				foundAny := false
				for _, tid := range tids {
					vkMod := fmt.Sprintf("m:%d\x00%s", tid, expName)
					if visited[vkMod] {
						foundAny = true
						continue
					}
					visited[vkMod] = true
					ts := scripts[tid]
					matchedDirect := false
					for ei, ex := range ts.Exports {
						if ex.Module != "" || ex.Name != expName {
							continue
						}
						matchedDirect = true
						foundAny = true
						lk := fmt.Sprintf("e:%d\x00%d", tid, ei)
						if ex.Via != nil {
							nq, nb := extendKeys(ex)
							if !resolveChain(tid, ex.Via.Module, ex.Via.Name, composeViaArgs(ex.Via.Args, curArgs), nq, nb, depth+1) && (ex.ParamURL || ex.URL != "") && !applied[lk] {
								applied[lk] = true
								applyLeaf(callerIdx, s, im, indexedExport{ex, tid}, curArgs, viaQ, viaB)
							}
						} else if !applied[lk] {
							applied[lk] = true
							applyLeaf(callerIdx, s, im, indexedExport{ex, tid}, curArgs, viaQ, viaB)
						}
					}
					// Follow ES module re-exports (`export { a as b } from "./x"`, `export * from "./x"`)
					clsPart, methodPart, hasMethodDot := strings.Cut(expName, ".")
					for _, re := range ts.ReExports {
						if re.All {
							if resolveChain(tid, re.Module, expName, curArgs, viaQ, viaB, depth+1) {
								foundAny = true
							}
						} else if re.Name == expName && re.Target != "*" && re.Target != "" {
							if resolveChain(tid, re.Module, re.Target, curArgs, viaQ, viaB, depth+1) {
								foundAny = true
							}
							matchedDirect = true
						} else if hasMethodDot && re.Name == clsPart && re.Target != "*" && re.Target != "" {
							if resolveChain(tid, re.Module, re.Target+"."+methodPart, curArgs, viaQ, viaB, depth+1) {
								foundAny = true
							}
							matchedDirect = true
						}
					}
					// Fallback to Export.Local when importing a monorepo package whose barrel index was tree-shaken
					if !matchedDirect && allowLocal {
						for ei, ex := range ts.Exports {
							if ex.Module != "" || ex.Local != expName {
								continue
							}
							foundAny = true
							lk := fmt.Sprintf("el:%d\x00%d", tid, ei)
							if ex.Via != nil {
								nq, nb := extendKeys(ex)
								if !resolveChain(tid, ex.Via.Module, ex.Via.Name, composeViaArgs(ex.Via.Args, curArgs), nq, nb, depth+1) && (ex.ParamURL || ex.URL != "") && !applied[lk] {
									applied[lk] = true
									applyLeaf(callerIdx, s, im, indexedExport{ex, tid}, curArgs, viaQ, viaB)
								}
							} else if !applied[lk] {
								applied[lk] = true
								applyLeaf(callerIdx, s, im, indexedExport{ex, tid}, curArgs, viaQ, viaB)
							}
						}
					}
					delete(visited, vkMod)
				}
				return foundAny
			}
			resolveChain(callerIdx, im.Module, im.Name, im.Args, nil, nil, 0)
		}
	}

	for k, names := range given {
		for _, me := range factories[k].Endpoints {
			ep := lookup(me)
			if ep == nil {
				continue
			}
			for _, name := range names {
				hints[ep] = append(hints[ep], settings[name]...)
			}
		}
	}

	resolveExportBaseProps := func(startIdx int, modSpec, expName string) []string {
		var props []string
		visited := map[string]bool{}
		var walk func(curIdx int, ms, en string, depth int)
		walk = func(curIdx int, ms, en string, depth int) {
			if depth > maxModuleDepth {
				return
			}
			addProp := func(bp string) {
				if bp != "" {
					k := "prop:" + bp
					if !slices.Contains(props, k) {
						props = append(props, k)
					}
				}
			}
			if bes := bundlerExports[ms+"\x00"+en]; len(bes) > 0 {
				for bi, be := range bes {
					vk := fmt.Sprintf("b:%s\x00%s\x00%d\x00%d", ms, en, be.si, bi)
					if visited[vk] {
						continue
					}
					visited[vk] = true
					if be.Via != nil {
						walk(be.si, be.Via.Module, be.Via.Name, depth+1)
					}
					addProp(be.BaseProp)
					delete(visited, vk)
				}
				return
			}
			tids, allowLocal := targetScripts(curIdx, ms)
			for _, tid := range tids {
				vkMod := fmt.Sprintf("m:%d\x00%s", tid, en)
				if visited[vkMod] {
					continue
				}
				visited[vkMod] = true
				ts := scripts[tid]
				matchedDirect := false
				for _, ex := range ts.Exports {
					if ex.Module != "" || ex.Name != en {
						continue
					}
					matchedDirect = true
					if ex.Via != nil {
						walk(tid, ex.Via.Module, ex.Via.Name, depth+1)
					}
					addProp(ex.BaseProp)
				}
				clsPart, methodPart, hasMethodDot := strings.Cut(en, ".")
				for _, re := range ts.ReExports {
					if re.All {
						walk(tid, re.Module, en, depth+1)
					} else if re.Name == en && re.Target != "*" && re.Target != "" {
						walk(tid, re.Module, re.Target, depth+1)
						matchedDirect = true
					} else if hasMethodDot && re.Name == clsPart && re.Target != "*" && re.Target != "" {
						walk(tid, re.Module, re.Target+"."+methodPart, depth+1)
						matchedDirect = true
					}
				}
				if !matchedDirect && allowLocal {
					for _, ex := range ts.Exports {
						if ex.Module != "" || ex.Local != en {
							continue
						}
						if ex.Via != nil {
							walk(tid, ex.Via.Module, ex.Via.Name, depth+1)
						}
						addProp(ex.BaseProp)
					}
				}
				delete(visited, vkMod)
			}
		}
		walk(startIdx, modSpec, expName, 0)
		return props
	}

	for _, ep := range byKey {
		if len(ep.baseKeys) == 0 {
			continue
		}
		var impKeys []string
		for bk := range ep.baseKeys {
			if strings.HasPrefix(bk, "imp:") {
				impKeys = append(impKeys, bk)
			}
		}
		for _, bk := range impKeys {
			delete(ep.baseKeys, bk)
			parts := strings.SplitN(strings.TrimPrefix(bk, "imp:"), "\x00", 3)
			if len(parts) != 3 {
				continue
			}
			sIdx, err := strconv.Atoi(parts[0])
			if err != nil || sIdx < 0 || sIdx >= len(scripts) {
				continue
			}
			for _, rk := range resolveExportBaseProps(sIdx, parts[1], parts[2]) {
				ep.addBaseKey(rk)
			}
		}
	}
	linkDeferred(scripts, byKey, order, origins, targetScripts)
	return hints
}

func normSourcePath(frag string) string {
	s := strings.ReplaceAll(strings.TrimSpace(frag), "\\", "/")
	for _, pfx := range []string{"webpack:///", "webpack://", "vite://", "rollup://", "file://"} {
		if strings.HasPrefix(s, pfx) {
			s = strings.TrimPrefix(s, pfx)
			break
		}
	}
	s, _, _ = strings.Cut(s, "?")
	var stack []string
	for _, seg := range strings.Split(s, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, seg)
		}
	}
	return strings.Join(stack, "/")
}

func stripSourceExt(p string) string {
	if strings.HasSuffix(p, ".d.ts") {
		return strings.TrimSuffix(p, ".d.ts")
	}
	for _, ext := range []string{".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"} {
		if strings.HasSuffix(p, ext) {
			return strings.TrimSuffix(p, ext)
		}
	}
	return p
}

func extractSmapPkg(noExt string) string {
	segs := strings.Split(noExt, "/")
	for i := 0; i < len(segs); i++ {
		if (segs[i] == "packages" || segs[i] == "node_modules") && i+1 < len(segs) {
			if strings.HasPrefix(segs[i+1], "@") && i+2 < len(segs) {
				return segs[i+1] + "/" + segs[i+2]
			}
			return segs[i+1]
		}
		if strings.HasPrefix(segs[i], "@") && i+1 < len(segs) {
			return segs[i] + "/" + segs[i+1]
		}
	}
	return ""
}

func specPkgRoot(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}
	segs := strings.Split(spec, "/")
	if strings.HasPrefix(segs[0], "@") {
		if len(segs) >= 2 {
			return segs[0] + "/" + segs[1]
		}
		return ""
	}
	return segs[0]
}

func joinViaAffix(pfx, val, sfx string) string {
	if pfx != "" && strings.HasSuffix(pfx, "/") && strings.HasPrefix(val, "/") {
		val = strings.TrimPrefix(val, "/")
	}
	return pfx + val + sfx
}

func evalSingleViaArg(va jsapi.ViaArg, callerArgs []jsapi.ImportArg) jsapi.ImportArg {
	if len(va.ObjProps) > 0 {
		out := jsapi.ImportArg{
			PropValues:   map[string][]string{},
			PropKeys:     map[string][]string{},
			PropBaseKeys: map[string]string{},
		}
		for k, sub := range va.ObjProps {
			ev := evalSingleViaArg(sub, callerArgs)
			if len(ev.Values) > 0 {
				out.PropValues[k] = ev.Values
			}
			if len(ev.Keys) > 0 {
				out.PropKeys[k] = ev.Keys
			}
			if ev.BaseKey != "" {
				out.PropBaseKeys[k] = ev.BaseKey
			}
			if len(ev.Query) > 0 {
				out.Query = uniq(append(out.Query, ev.Query...))
			}
		}
		return out
	}
	if va.Param >= 0 {
		var ca jsapi.ImportArg
		if va.Param < len(callerArgs) {
			ca = callerArgs[va.Param]
		}
		if va.Prop != "" {
			bk := ca.PropBaseKeys[va.Prop]
			if bk == "" {
				bk = "prop:" + va.Prop
			}
			return jsapi.ImportArg{
				Values:  ca.PropValues[va.Prop],
				Keys:    ca.PropKeys[va.Prop],
				Query:   ca.Query,
				Setting: ca.Setting,
				BaseKey: bk,
			}
		}
		if va.Prefix != "" || va.Suffix != "" {
			var vals []string
			if len(ca.Values) > 0 {
				for _, v := range ca.Values {
					vals = append(vals, joinViaAffix(va.Prefix, v, va.Suffix))
				}
			} else if len(ca.RelValues) > 0 && va.Prefix != "" {
				for _, v := range ca.RelValues {
					vals = append(vals, joinViaAffix(va.Prefix, v, va.Suffix))
				}
			} else if strings.HasSuffix(va.Prefix, "/") || strings.HasPrefix(va.Suffix, "/") {
				vals = []string{va.Prefix + placeholder + va.Suffix}
			}
			out := jsapi.ImportArg{Values: uniq(vals), Query: ca.Query, BaseKey: ca.BaseKey}
			if ca.ConstRef != nil && va.Prefix == "" {
				out.ConstRef = ca.ConstRef
				out.ConstSuffix = ca.ConstSuffix + va.Suffix
			}
			return out
		}
		return ca
	}
	return jsapi.ImportArg{Values: va.Values, Keys: va.Keys, BaseKey: va.BaseKey}
}

func composeViaArgs(viaArgs []jsapi.ViaArg, callerArgs []jsapi.ImportArg) []jsapi.ImportArg {
	out := make([]jsapi.ImportArg, len(viaArgs))
	for i, va := range viaArgs {
		out[i] = evalSingleViaArg(va, callerArgs)
	}
	return out
}

// mergeDocs folds what a document names into what the code calls: the
// same method and path (or the path with a base the code does not know
// before it), and a path a page abbreviates (/v1/public/feed/items/batch
// in its table) into the whole one it gives elsewhere
// (https://api…/open/product-catalog/v1/public/feed/items/batch in a curl
// command), when two named segments at least end both. It returns the
// keys folded.
func mergeDocs(order []string, byKey map[string]*Endpoint) map[string]bool {
	dropped := map[string]bool{}
	into := func(k string, to *Endpoint) {
		from := byKey[k]
		for _, src := range from.Static {
			if len(to.Static) < maxSources {
				to.Static = append(to.Static, src)
			}
		}
		to.Query = append(to.Query, from.Query...)
		to.Body = append(to.Body, from.Body...)
		to.Headers = append(to.Headers, from.Headers...)
		to.Auth = append(to.Auth, from.Auth...)
		to.Params = jsapi.MergeParams(to.Params, nonPath(from.Params))
		to.docBases = append(to.docBases, from.docBases...)
		to.bundleStatic = to.bundleStatic || from.bundleStatic
		to.addBaseKeys(from.baseKeys)
		dropped[k] = true
	}
	named := func(p string) int {
		n := 0
		for _, sg := range strings.Split(strings.Trim(p, "/"), "/") {
			if sg != "" && !strings.Contains(sg, placeholder) {
				n++
			}
		}
		return n
	}
	for _, k := range order {
		ep := byKey[k]
		if ep.Kind != "doc" {
			continue
		}
		for _, o := range order {
			other := byKey[o]
			if o == k || dropped[o] || other.Kind == "doc" || other.Kind == "string" || other.Method != ep.Method {
				continue
			}
			if (other.Path == ep.Path || other.Path == placeholder+ep.Path) && (ep.Host == "" || other.Host == ep.Host) {
				into(k, other)
				break
			}
		}
	}
	// An example's call (curl …/content_types/page/entries/$ID) is the
	// template the document names (/content_types/{content_type}/…).
	for _, k := range order {
		ep := byKey[k]
		if ep.Kind != "doc" || dropped[k] {
			continue
		}
		for _, o := range order {
			other := byKey[o]
			if o != k && !dropped[o] && other.Kind == "doc" && other.Method == ep.Method && other.Host == ep.Host && instance(ep.Path, other.Path) {
				into(k, other)
				break
			}
		}
	}
	for _, k := range order {
		ep := byKey[k]
		if ep.Kind != "doc" || dropped[k] || ep.Host != "" || named(ep.Path) < 2 {
			continue
		}
		var best *Endpoint
		for _, o := range order {
			other := byKey[o]
			if o == k || dropped[o] || other.Kind != "doc" || other.Method != ep.Method {
				continue
			}
			if len(other.Path) > len(ep.Path) && strings.HasSuffix(other.Path, ep.Path) && (best == nil || len(other.Path) > len(best.Path)) {
				best = other
			}
		}
		if best != nil {
			into(k, best)
		}
	}
	return dropped
}

// instance reports whether a path is one of a template's, with fewer
// placeholders: /a/page/b/{} of /a/{}/b/{}.
func instance(path, template string) bool {
	ps, ts := strings.Split(path, "/"), strings.Split(template, "/")
	if len(ps) != len(ts) || strings.Count(template, placeholder) <= strings.Count(path, placeholder) {
		return false
	}
	for i := range ps {
		if ps[i] != ts[i] && ts[i] != placeholder {
			return false
		}
	}
	return true
}

// originOf is the scheme and host of a URL, or "" when it has none.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// PreferInScope drops the absolute bases on hosts out of scope when one
// in scope is among them: the code's defaults for a development server
// (https://api.dev.example.internal) beside production's settings.
func PreferInScope(bases []string, inScope func(host string) bool) []string {
	if inScope == nil {
		return bases
	}
	in := func(b string) (abs, ok bool) {
		u, err := url.Parse(b)
		if err != nil || u.Host == "" {
			return false, false
		}
		return true, inScope(u.Hostname())
	}
	some := false
	for _, b := range bases {
		if abs, ok := in(b); abs && ok || (!abs && strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//")) {
			some = true
		}
	}
	if !some {
		return bases
	}
	var out []string
	for _, b := range bases {
		if abs, ok := in(b); !abs || ok {
			out = append(out, b)
		}
	}
	return out
}

// baseFor is an endpoint's base, or its candidates in order. A spec's
// paths go under the base named for it (…/openapi). A base the endpoint's
// path starts with (https://api.x/hub/console/v1 for
// /hub/console/v1/apps), or whose first segment it shares (a gateway's
// prefix: https://api.x/hub/auth for /hub/api/account/v1/me), says the
// path is from that origin's root: that origin, and no other. Otherwise
// the candidates: absolute ones before relative ones (a setting's
// default), the shortest (an origin) first.
func baseFor(bases []string, path, kind string, inScope func(host string) bool) []string {
	bases = PreferInScope(bases, inScope)
	if kind == "openapi" {
		var spec []string
		for _, b := range bases {
			if bp := basePath(b); strings.HasSuffix(bp, "/openapi") || strings.Contains(bp, "/openapi/") {
				spec = append(spec, b)
			}
		}
		if len(spec) > 0 {
			return uniq(spec)
		}
	}
	var first, rest []string
	own := false
	for _, b := range bases {
		head, bp := "", strings.TrimRight(b, "/")
		if u, err := url.Parse(b); err == nil && u.Host != "" {
			head, bp = u.Scheme+"://"+u.Host, strings.TrimRight(u.EscapedPath(), "/")
		}
		switch {
		case head != "" && bp != "" && (path == bp || strings.HasPrefix(path, bp+"/")):
			first = append(first, head)
		case head != "" && bp != "" && gatewaySeg(bp) != "" && gatewaySeg(bp) == gatewaySeg(path):
			first = append(first, head)
		case bp != "" && head == "" && strings.HasPrefix(path, bp+"/"):
			// A relative base the path starts with (a proxy of the page's
			// origin: /console-api): the page's own origin, and no other.
			own = true
		default:
			rest = append(rest, b)
		}
	}
	if len(first) > 0 {
		return uniq(first)
	}
	if own {
		return nil
	}
	out := uniq(rest)
	rank := func(b string) (int, int) {
		if strings.Contains(b, "://") {
			return 1, len(b)
		}
		return 2, len(b)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, li := rank(out[i])
		rj, lj := rank(out[j])
		if ri != rj {
			return ri < rj
		}
		return li < lj
	})
	return slices.DeleteFunc(out, func(b string) bool { return b == "" })
}

// basePath is a base's path, without its last slash.
func basePath(b string) string {
	if u, err := url.Parse(b); err == nil && u.Host != "" {
		return strings.TrimRight(u.EscapedPath(), "/")
	}
	return strings.TrimRight(b, "/")
}

// gatewaySeg is a path's first segment when it names a gateway's prefix
// (/hub/…): three letters at least, and none of the words every API's
// paths start with (/api, /v1, /rest).
func gatewaySeg(p string) string {
	seg, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	if len(seg) < 3 || strings.Contains(seg, "{") || genericSegRe.MatchString(seg) {
		return ""
	}
	return seg
}

var genericSegRe = regexp.MustCompile(`(?i)^(?:api|apis|v\d+(?:\.\d+)*|rest|public|internal|graphql|gql|rpc|service|services|svc|gateway|backend|server|app|web|ajax|json|data|auth|oauth|admin|static|assets)$`)

func kindOf(resourceType string) string {
	switch resourceType {
	case "EventSource":
		return "sse"
	case "WebSocket":
		return "websocket"
	case "Ping":
		return "beacon"
	case "XHR":
		return "xhr"
	}
	return "fetch"
}

func (ep *Endpoint) observe(r Request, host, path string, query []string) {
	o := ep.Observed
	if o == nil {
		o = &Observed{First: r.Time, Last: r.Time}
		ep.Observed = o
		ep.runs = map[string]bool{}
		ep.obsHosts = map[string]bool{}
	}
	if host != "" {
		ep.obsHosts[canonHost(host)] = true
	}
	o.Requests++
	if r.Time.Before(o.First) {
		o.First = r.Time
	}
	if r.Time.After(o.Last) {
		o.Last = r.Time
	}
	if sample := path; len(o.Samples) < maxSamples && !slices.Contains(o.Samples, sample) {
		o.Samples = append(o.Samples, sample)
	}
	if out, _, _ := strings.Cut(r.Outcome, ":"); out != "" {
		o.Outcomes = append(o.Outcomes, r.Outcome)
	}
	if r.Status > 0 && !slices.Contains(o.Statuses, r.Status) && !strings.HasPrefix(r.Outcome, "held_back") {
		o.Statuses = append(o.Statuses, r.Status)
		slices.Sort(o.Statuses)
	}
	if len(o.Refs) < maxRefs {
		o.Refs = append(o.Refs, Ref{Run: r.Run, ID: r.ID})
	}
	ep.runs[r.Run] = true
	ep.Query = append(ep.Query, query...)
	ep.observeParamValues(r.URL, r.Body)
	if ep.client && ep.Base == "" && ep.re != nil {
		if m := ep.re.FindStringSubmatch(path); len(m) > 1 && m[1] != "" {
			ep.Base = m[1]
		}
	}
}

var (
	obsAPIRootSegRe  = regexp.MustCompile(`(?i)^(?:api|apis|rest|graphql|gql|rpc|v\d+(?:\.\d+)*|gateway|backend|service|services|svc|[a-z0-9_]+[-_.]?(?:api|apis|gateway|backend|service))$`)
	staticAssetExtRe = regexp.MustCompile(`(?i)\.(?:json|xml|txt|webmanifest|html?|css|m?js|cjs|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|wasm)$`)
	sampleJWTRe      = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.`)
	piiSampleWords   = map[string]bool{
		"pin": true, "pincode": true, "email": true, "mail": true, "phone": true,
		"mobile": true, "tel": true, "msisdn": true, "nonce": true, "card": true,
		"pan": true, "iban": true, "dob": true, "taxid": true,
	}
)

func isAPIPropagatableBase(b string) bool {
	for _, seg := range strings.Split(strings.Trim(b, "/"), "/") {
		if seg != "" && !strings.Contains(seg, placeholder) && obsAPIRootSegRe.MatchString(seg) {
			return true
		}
	}
	return false
}

// hasBoundClientKey reports whether the endpoint comes from a method call on a
// bound HTTP client instance (`client:<var>`, e.g. `sr.get("/path")`), as
// opposed to a generic wrapper receiving an explicit base expression argument.
func hasBoundClientKey(ks map[string]bool) bool {
	for k := range ks {
		if strings.HasPrefix(k, "client:") {
			return true
		}
	}
	return false
}

func allOutOfScopeBases(bases []string, inScope func(host string) bool) bool {
	if len(bases) == 0 || inScope == nil {
		return false
	}
	for _, b := range bases {
		u, err := url.Parse(b)
		if err != nil || u.Host == "" || inScope(hostname(u.Host)) {
			return false
		}
	}
	return true
}

// canonBaseKey normalizes `prop:<name>` case-insensitively (`baseURL` ==
// `baseUrl`) while keeping distinct property, variable, parameter, and export
// expressions strictly separate.
func canonBaseKey(k string) string {
	if prop, ok := strings.CutPrefix(k, "prop:"); ok {
		return "prop:" + strings.ToLower(prop)
	}
	return k
}

func hasStaticAssetExt(p string) bool {
	p, _, _ = strings.Cut(p, "?")
	return staticAssetExtRe.MatchString(p)
}

func splitParamWords(s string) []string {
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

// SensitiveParam reports whether a query or body parameter name holds a
// credential or PII that must not be harvested from observed traffic.
func SensitiveParam(name string) bool {
	if name == "" {
		return true
	}
	leaf := name[strings.LastIndexByte(name, '.')+1:]
	if traffic.Sensitive(name) || traffic.Sensitive(leaf) {
		return true
	}
	for _, w := range splitParamWords(name) {
		if piiSampleWords[w] {
			return true
		}
	}
	return false
}

// IsRedactedValue reports whether val is a placeholder written by the redactor.
func IsRedactedValue(val string) bool {
	lv := strings.ToLower(strings.TrimSpace(val))
	return lv == "redacted" || strings.HasPrefix(lv, "redacted_") || strings.Contains(lv, "[redacted]") || strings.Contains(val, "***")
}

// SampleValueOK reports whether an observed parameter value is safe to store
// in the catalog and replay in drafts.
func SampleValueOK(name, val string) bool {
	if SensitiveParam(name) {
		return false
	}
	if val == "" || len(val) > 64 || strings.ContainsAny(val, "\r\n\x00") {
		return false
	}
	if IsRedactedValue(val) || sampleJWTRe.MatchString(val) {
		return false
	}
	return true
}

func sampleParamOK(name, val string) bool {
	return SampleValueOK(name, val)
}

func mergeObservedParam(params []jsapi.ParamSpec, in, name, typ string, vals []string) []jsapi.ParamSpec {
	var clean []string
	for _, v := range vals {
		if sampleParamOK(name, v) && !slices.Contains(clean, v) {
			clean = append(clean, v)
		}
	}
	if len(clean) == 0 {
		return params
	}
	for i := range params {
		if params[i].In == in && params[i].Name == name {
			if params[i].Type == "" && typ != "" {
				params[i].Type = typ
			}
			for _, v := range clean {
				if len(params[i].Values) >= 4 {
					break
				}
				if !slices.Contains(params[i].Values, v) {
					params[i].Values = append(params[i].Values, v)
				}
			}
			return params
		}
	}
	if len(clean) > 4 {
		clean = clean[:4]
	}
	return append(params, jsapi.ParamSpec{Name: name, In: in, Type: typ, Values: clean})
}

func (ep *Endpoint) observeParamValues(rawURL, rawBody string) {
	if u, err := url.Parse(rawURL); err == nil && u.RawQuery != "" {
		qv := u.Query()
		keys := make([]string, 0, len(qv))
		for k := range qv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ep.Params = mergeObservedParam(ep.Params, "query", k, "", qv[k])
		}
	}
	if rawBody != "" && len(rawBody) <= 16<<10 && strings.HasPrefix(strings.TrimSpace(rawBody), "{") {
		dec := json.NewDecoder(strings.NewReader(rawBody))
		dec.UseNumber()
		var m map[string]any
		if dec.Decode(&m) == nil && len(m) > 0 {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				var typ, val string
				switch v := m[k].(type) {
				case string:
					typ, val = "string", v
				case json.Number:
					typ, val = "number", v.String()
				case bool:
					typ, val = "boolean", strconv.FormatBool(v)
				default:
					continue
				}
				ep.Params = mergeObservedParam(ep.Params, "body", k, typ, []string{val})
			}
		}
	}
}

// split cuts a URL of the code into its host (empty for a relative one)
// and its path.
func split(u string) (host, path string) {
	// https://{}/x: a host the code does not know is a base it does not
	// know, not a third party's.
	unknownHost := func(host, path string) (string, string) {
		if strings.Contains(host, placeholder) {
			return "", unknownPrefix + strings.TrimLeft(path, "/")
		}
		return host, "/" + path
	}
	if i := strings.Index(u, "://"); i > 0 && !strings.Contains(u[:i], "/") {
		rest := u[i+3:]
		host, path, _ = strings.Cut(rest, "/")
		return unknownHost(host, path)
	}
	if strings.HasPrefix(u, "//") {
		host, path, _ = strings.Cut(u[2:], "/")
		return unknownHost(host, path)
	}
	if !strings.HasPrefix(u, "/") && !strings.HasPrefix(u, placeholder) {
		return "", "/" + u // relative to the page: under its directory, which is mostly /
	}
	return "", u
}

// parts reads a request URL: its host, its path and its query names.
func parts(raw string) (host, path string, query []string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ws" && u.Scheme != "wss") {
		return "", "", nil, false
	}
	for k := range u.Query() {
		query = append(query, k)
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	return u.Host, p, query, true
}

func hostname(host string) string {
	h, _, _ := strings.Cut(host, ":")
	return h
}

// pattern turns an endpoint's path into a regexp for request paths: {}
// stands for one segment or more. A client's path, or one that starts
// with {}, may follow any prefix (its base URL), which the first group
// captures.
func pattern(ep *Endpoint) *regexp.Regexp {
	path := ep.Path
	prefix := ""
	if ep.client {
		path = strings.TrimPrefix(path, placeholder)
		prefix = `(/[^?#]*?)?`
	}
	var b strings.Builder
	b.WriteString("^" + prefix)
	for i, part := range strings.Split(path, placeholder) {
		if i > 0 {
			b.WriteString(`[^?#]+?`)
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString("/?$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// index finds the endpoints a request path may match without trying them
// all: each endpoint is filed under the rarest whole segment of its path
// ("r1" rather than "api"), and a path is only tried against those filed
// under its own segments, and those with no whole segment.
type index struct {
	bySeg map[string][]*Endpoint
	any   []*Endpoint
}

func newIndex(eps []*Endpoint) *index {
	segsOf := func(ep *Endpoint) []string {
		var out []string
		for _, sg := range strings.Split(ep.Path, "/") {
			if sg != "" && !strings.Contains(sg, placeholder) {
				out = append(out, sg)
			}
		}
		return out
	}
	freq := map[string]int{}
	for _, ep := range eps {
		for _, sg := range segsOf(ep) {
			freq[sg]++
		}
	}
	x := &index{bySeg: map[string][]*Endpoint{}}
	for _, ep := range eps {
		key := ""
		for _, sg := range segsOf(ep) {
			if key == "" || freq[sg] < freq[key] {
				key = sg
			}
		}
		if key == "" {
			x.any = append(x.any, ep)
		} else {
			x.bySeg[key] = append(x.bySeg[key], ep)
		}
	}
	return x
}

func (x *index) candidates(path string) []*Endpoint {
	out := x.any
	seen := map[string]bool{}
	for _, sg := range strings.Split(path, "/") {
		if eps, ok := x.bySeg[sg]; ok && !seen[sg] {
			seen[sg] = true
			out = append(out[:len(out):len(out)], eps...)
		}
	}
	return out
}

// match finds the endpoint of the code a request calls: same host (or a
// relative URL and a host of the target), a compatible method, and the
// path that matches with the most fixed text, so that /api/articles/{}
// does not take /api/articles/x/comments from /api/articles/{}/comments.
func match(eps []*Endpoint, method, host, path string, inScope func(string) bool) *Endpoint {
	var best *Endpoint
	bestScore := -1
	for _, ep := range eps {
		if ep.re == nil || (ep.Method != "" && ep.Method != method && !(ep.Kind == "websocket")) || !strings.Contains(path, ep.lit) {
			continue
		}
		if ep.Host != "" && ep.Host != host && ep.Host != placeholder {
			continue
		}
		if ep.Host == "" && !inScope(hostname(host)) {
			continue
		}
		if !ep.re.MatchString(path) {
			continue
		}
		score := len(strings.ReplaceAll(ep.Path, placeholder, ""))*4 - strings.Count(ep.Path, placeholder)
		if ep.Method != "" {
			score += 2
		}
		if ep.client {
			score--
		}
		if score > bestScore {
			best, bestScore = ep, score
		}
	}
	return best
}

func uniq(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(s))
	for _, v := range s {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Write replaces dir's endpoints.jsonl. It is 0600 like the request log:
// its samples are real paths.
func Write(dir string, eps []Endpoint) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, e := range eps {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	tmp := filepath.Join(dir, File+".tmp")
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, File))
}

// Requests lists the requests of every run in a directory's log, but those
// jsharvest made itself (the resolver's).
func Requests(d *results.Dir) []Request {
	var out []Request
	for _, run := range d.Runs() {
		for _, q := range d.Requests(run) {
			if q.Internal || q.Challenge {
				continue
			}
			out = append(out, Request{Run: q.Run, ID: q.ID, Time: q.Time, Method: q.Method, URL: q.URL, Body: q.Body,
				ResourceType: q.ResourceType, Outcome: q.Outcome, Status: q.Status, Initiator: q.Initiator})
		}
	}
	return out
}

// Catalog builds the catalog of a directory: analysing the scripts that
// have no cache yet when analyze is set (a writer), reading the cache
// only otherwise (a reader, while a watch fills it).
func Catalog(dir string, inScope func(host string) bool, analyze bool) ([]Endpoint, error) {
	eps, _, err := CatalogWithStats(dir, inScope, analyze)
	return eps, err
}

// CatalogWithStats builds the catalog and also returns static script analysis
// statistics (including bundle/source parse fallbacks).
func CatalogWithStats(dir string, inScope func(host string) bool, analyze bool) ([]Endpoint, AnalyzeStats, error) {
	eps, _, stats, err := CatalogScriptsWithStats(dir, inScope, analyze)
	return eps, stats, err
}

// CatalogScriptsWithStats builds the catalog and returns the loaded slim Script
// slice alongside statistics so callers that also write intel.json can pass
// scripts straight to SaveIntelFromScripts without re-reading static/*.json.
func CatalogScriptsWithStats(dir string, inScope func(host string) bool, analyze bool) ([]Endpoint, []Script, AnalyzeStats, error) {
	var scripts []Script
	var err error
	if analyze {
		scripts, err = analyzeDir(dir, 0, nil, true)
	} else {
		scripts, err = loadDir(dir, true)
	}
	if err != nil {
		return nil, nil, AnalyzeStats{}, err
	}
	stats := SummarizeScripts(scripts)
	d := results.Open(dir)
	if err := d.Refresh(); err != nil {
		return nil, scripts, stats, err
	}
	return Assemble(dir, scripts, Requests(d), inScope), scripts, stats, nil
}

// Assemble builds a directory's catalog out of its analysed scripts and
// observed requests, enriched from the target's archive catalog: what
// CatalogWithStats does, for a reader that keeps its own request index
// (the MCP server reads requests.jsonl as it grows).
func Assemble(dir string, scripts []Script, reqs []Request, inScope func(host string) bool) []Endpoint {
	return EnrichFromArchive(Build(scripts, reqs, inScope), archiveCatalog(dir))
}

// Stamp says whether what the catalog is made of changed: the script
// index, the analysis cache (written by rename, so the directory's time
// moves) and the archive catalog. Requests are the caller's to add.
func Stamp(dir string) string {
	var b strings.Builder
	for _, p := range []string{filepath.Join(dir, "index.jsonl"), filepath.Join(dir, CacheDir), archiveFile(dir)} {
		if st, err := os.Stat(p); err == nil && p != "" {
			fmt.Fprintf(&b, "%d.%d;", st.Size(), st.ModTime().UnixNano())
		} else {
			b.WriteString("-;")
		}
	}
	fmt.Fprintf(&b, "v%d", jsapi.Version)
	return b.String()
}

// pageOrigin is the origin a relative call with no base goes to: that of
// the pages whose scripts make it, when they are one origin of the
// target's (a CDN's that serves the bundle to many aside).
func pageOrigin(ep *Endpoint, inScope func(string) bool) string {
	if ep.Host != "" || ep.Base != "" || len(ep.Bases) > 0 || ep.Kind == "doc" || strings.HasPrefix(ep.Path, placeholder) || !strings.HasPrefix(ep.Path, "/") {
		return ""
	}
	return epScriptOrigin(ep, inScope)
}

func epScriptOrigin(ep *Endpoint, inScope func(string) bool) string {
	one := ""
	for _, src := range ep.Static {
		o := originOf(src.Script)
		if o == "" {
			continue
		}
		_, host, _ := strings.Cut(o, "://")
		h := hostname(host)
		if inScope != nil && !inScope(h) || strings.HasPrefix(h, "cdn.") || strings.HasPrefix(h, "static.") || strings.HasPrefix(h, "assets.") {
			continue
		}
		if one != "" && one != o {
			return ""
		}
		one = o
	}
	return one
}

func hasInScopeBase(bases []string, inScope func(string) bool) bool {
	for _, b := range bases {
		if strings.Contains(b, placeholder) {
			continue
		}
		if strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
			return true
		}
		if u, err := url.Parse(b); err == nil && u.Host != "" && (inScope == nil || inScope(u.Hostname())) {
			return true
		}
	}
	return false
}

// canonicalURL is where an endpoint with one known target goes: its host
// and the whole path, its base's path included once (the same rule as
// baseFor's), or "" when that is not known.
func canonicalURL(ep *Endpoint) string {
	switch {
	case ep.Host != "" && len(ep.Bases) == 0:
		if strings.Contains(ep.Host, placeholder[:2]) {
			return ""
		}
		return canonHost(ep.Host) + ep.Path
	case len(ep.Bases) == 1 && strings.Contains(ep.Bases[0], "://"):
		u, err := url.Parse(ep.Bases[0])
		if err != nil || u.Host == "" {
			return ""
		}
		bp := strings.TrimRight(u.EscapedPath(), "/")
		p := strings.TrimPrefix(ep.Path, placeholder[:2])
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if !(bp != "" && (p == bp || strings.HasPrefix(p, bp+"/"))) {
			p = bp + p
		}
		return canonHost(u.Host) + p
	case ep.Origin != "" && ep.Host == "" && len(ep.Bases) == 0:
		u, err := url.Parse(ep.Origin)
		if err != nil {
			return ""
		}
		return canonHost(u.Host) + ep.Path
	}
	return ""
}

// canonHost is a host:port with its port when it is not a default one:
// api.x:8443 and api.x are two servers.
func canonHost(h string) string {
	h = strings.ToLower(h)
	return strings.TrimSuffix(strings.TrimSuffix(h, ":443"), ":80")
}

// kindRank orders how much a source says: a spec's or a call's more than
// a document's text, which says more than a bare string.
func kindRank(k string) int {
	switch k {
	case "openapi":
		return 4
	case "string":
		return 1
	case "doc":
		return 0
	case "navigation":
		return 2
	}
	return 3
}

// canonicalMerge merges the endpoints that go to one URL once their bases
// are known (GET /api/account/v1/me/tenants under …/hub, /v1/me/tenants
// under …/hub/api/account): one line, with what each knows. The one kept
// is the one under the most specific base, from code or a spec.
func canonicalMerge(eps []*Endpoint) []*Endpoint {
	groups := map[string][]*Endpoint{}
	var keys []string
	for _, ep := range eps {
		if ep.Method == "" || ep.collector {
			continue
		}
		c := canonicalURL(ep)
		if c == "" {
			continue
		}
		k := ep.Method + " " + c
		if groups[k] == nil {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], ep)
	}
	gone := map[*Endpoint]bool{}
	for _, k := range keys {
		g := groups[k]
		if len(g) < 2 {
			continue
		}
		best := g[0]
		for _, ep := range g[1:] {
			if better(ep, best) {
				best = ep
			}
		}
		for _, ep := range g {
			if ep == best {
				continue
			}
			best.Query = append(best.Query, ep.Query...)
			best.Body = append(best.Body, ep.Body...)
			best.Headers = append(best.Headers, ep.Headers...)
			best.Auth = append(best.Auth, ep.Auth...)
			best.Operations = append(best.Operations, ep.Operations...)
			best.GraphQLDocs = mergeGQLDocs(best.GraphQLDocs, ep.GraphQLDocs)
			best.Params = jsapi.MergeParams(best.Params, ep.Params)
			for _, src := range ep.Static {
				if len(best.Static) < maxSources {
					best.Static = append(best.Static, src)
				}
			}
			if kindRank(ep.Kind) > kindRank(best.Kind) {
				best.Kind = ep.Kind
			}
			if best.Observed == nil && ep.Observed != nil {
				best.Observed = ep.Observed
				best.runs = ep.runs
				best.obsHosts = ep.obsHosts
			}
			best.ThirdParty = best.ThirdParty && ep.ThirdParty
			best.bundleStatic = best.bundleStatic || ep.bundleStatic
			best.addBaseKeys(ep.baseKeys)
			gone[ep] = true
		}
	}
	if len(gone) == 0 {
		return eps
	}
	out := eps[:0]
	for _, ep := range eps {
		if !gone[ep] {
			out = append(out, ep)
		}
	}
	return out
}

// better reports whether a is the line to keep over b: one base (a host
// otherwise), the more specific the better (…/hub/auth + /v1/oauth/token
// over …/hub + /auth/v1/oauth/token), then one from code or a spec.
func better(a, b *Endpoint) bool {
	if (a.Observed != nil) != (b.Observed != nil) {
		return a.Observed != nil
	}
	if (len(a.Bases) == 1) != (len(b.Bases) == 1) {
		return len(a.Bases) == 1
	}
	if len(a.Bases) == 1 && len(b.Bases) == 1 && len(a.Bases[0]) != len(b.Bases[0]) {
		return len(a.Bases[0]) > len(b.Bases[0])
	}
	// The merged line takes the strongest kind whichever is kept.
	if ra, rb := kindRank(a.Kind), kindRank(b.Kind); (ra >= 3) != (rb >= 3) {
		return ra >= 3
	}
	return a.client && !b.client
}

// confidence is how sure the catalog is of an endpoint: seen run
// (confirmed), in an API description (spec), called by code (code), named
// as a string (string), or only in a document's text (doc).
func confidence(ep *Endpoint) string {
	if ep.Observed != nil {
		return "confirmed"
	}
	best := -1
	for _, src := range ep.Static {
		r := kindRank(src.Kind)
		if src.Kind == "navigation" {
			r = 3 // a call to an API's URL
		}
		best = max(best, r)
	}
	best = max(best, kindRank(ep.Kind))
	switch {
	case best >= 4:
		return "spec"
	case best >= 2:
		return "code"
	case best == 1:
		return "string"
	}
	return "doc"
}

// settingNorm is a setting's or a placeholder's name reduced to what it
// names: VITE_OPENAPI_BASE_URL is openapi, <auth-host> auth, {agentHub}
// agenthub.
func settingNorm(n string) string {
	n = strings.ToLower(strings.Trim(n, "<>{}"))
	for _, p := range []string{"vite_", "next_public_", "react_app_", "nuxt_public_", "public_"} {
		n = strings.TrimPrefix(n, p)
	}
	n = strings.NewReplacer("_", "", "-", "", ".", "").Replace(n)
	for _, sfx := range []string{"baseurl", "apiurl", "url", "host", "base", "endpoint", "uri"} {
		if t := strings.TrimSuffix(n, sfx); t != n && t != "" {
			n = t
			break
		}
	}
	switch n {
	case "openplatform", "openplatformapi":
		return "openapi"
	}
	return n
}

// settingFor is the base a placeholder host of a document names
// (<auth-host>, <open-platform-host>): the value of the setting of that
// name (VITE_OAUTH_TOKEN_BASE_URL), or of those containing it, when they
// give one value only.
func settingFor(mark string, settings []jsapi.Header) string {
	want := settingNorm(mark)
	if len(want) < 3 {
		return ""
	}
	var exact, near []string
	for _, h := range settings {
		got := settingNorm(h.Name)
		switch {
		case got == want:
			exact = append(exact, h.Value)
		case strings.Contains(got, want):
			near = append(near, h.Value)
		}
	}
	for _, vals := range [][]string{exact, near} {
		if vals = uniq(vals); len(vals) == 1 {
			return vals[0]
		}
		if len(vals) > 1 {
			return ""
		}
	}
	return ""
}

// nonPath are the parameters but the path's: an example's path (…/page/…)
// has its slots elsewhere than the template it is merged into.
func nonPath(ps []jsapi.ParamSpec) []jsapi.ParamSpec {
	var out []jsapi.ParamSpec
	for _, p := range ps {
		if p.In != "path" {
			out = append(out, p)
		}
	}
	return out
}

// siblingBases gives a document's endpoint with no base the one base the
// documents put its siblings under (GET /cms/delivery/…/categories, written
// alone, beside $CMS_HOST/cms/delivery/…): those of the same first two
// segments, two at least, all of one base.
func siblingBases(byKey map[string]*Endpoint) {
	prefix := func(p string) string {
		segs := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
		if len(segs) < 3 || strings.Contains(segs[0]+segs[1], "{") {
			return ""
		}
		return segs[0] + "/" + segs[1]
	}
	bases := map[string][]string{}
	count := map[string]int{}
	for _, ep := range byKey {
		if ep.Kind != "doc" || ep.Host != "" || len(ep.Bases) != 1 {
			continue
		}
		if pf := prefix(ep.Path); pf != "" {
			bases[pf] = append(bases[pf], ep.Bases[0])
			count[pf]++
		}
	}
	for _, ep := range byKey {
		if ep.Kind != "doc" || ep.Host != "" || len(ep.Bases) != 0 || ep.client && strings.HasPrefix(ep.Path, placeholder) {
			continue
		}
		pf := prefix(ep.Path)
		if b := uniq(bases[pf]); pf != "" && count[pf] >= 2 && len(b) == 1 {
			ep.Bases = b
		}
	}
}

var gqlEndpointPathRe = regexp.MustCompile(`(?i)(?:^|/)(?:graphql|gql)/?$`)

func isGraphQLPath(p string) bool {
	p, _, _ = strings.Cut(p, "?")
	return gqlEndpointPathRe.MatchString(p)
}

func mergeGQLDocs(a, b []jsapi.GraphQLDoc) []jsapi.GraphQLDoc {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]jsapi.GraphQLDoc, 0, len(a)+len(b))
	for _, d := range a {
		k := d.Kind + " " + d.Name
		if !seen[k] {
			seen[k] = true
			out = append(out, d)
		}
	}
	for _, d := range b {
		k := d.Kind + " " + d.Name
		if !seen[k] {
			seen[k] = true
			out = append(out, d)
		}
	}
	return out
}

func attachGraphQLDocs(scripts []Script, eps []*Endpoint, inScope func(host string) bool) {
	byOrigin := map[string][]jsapi.GraphQLDoc{}
	var all []jsapi.GraphQLDoc
	byName := map[string]jsapi.GraphQLDoc{}
	for _, s := range scripts {
		if isTrackerScript(s) || len(s.GraphQLDocs) == 0 {
			continue
		}
		all = mergeGQLDocs(all, s.GraphQLDocs)
		for _, d := range s.GraphQLDocs {
			if _, exists := byName[d.Name]; !exists {
				byName[d.Name] = d
			}
		}
		if len(s.URLs) == 0 {
			byOrigin[""] = mergeGQLDocs(byOrigin[""], s.GraphQLDocs)
			continue
		}
		for _, u := range s.URLs {
			o := originOf(u)
			byOrigin[o] = mergeGQLDocs(byOrigin[o], s.GraphQLDocs)
		}
	}
	if len(all) == 0 {
		return
	}
	for _, ep := range eps {
		if ep.Method == "POST" && isGraphQLPath(ep.Path) {
			so := pageOrigin(ep, inScope)
			cands := byOrigin[so]
			if len(cands) == 0 && (so == "" || len(byOrigin) == 1) {
				cands = all
			}
			for _, d := range cands {
				ep.Operations = append(ep.Operations, d.Kind+" "+d.Name)
			}
			ep.GraphQLDocs = mergeGQLDocs(ep.GraphQLDocs, cands)
		}
		for _, op := range ep.Operations {
			if f := strings.Fields(op); len(f) > 0 {
				if d, ok := byName[f[len(f)-1]]; ok {
					ep.GraphQLDocs = mergeGQLDocs(ep.GraphQLDocs, []jsapi.GraphQLDoc{d})
				}
			}
		}
	}
}

func isLoopbackHost(rawHost string) bool {
	h := strings.TrimSpace(strings.ToLower(rawHost))
	if h == "" {
		return false
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			h = h[1:i]
		}
	} else if strings.Count(h, ":") == 1 {
		h, _, _ = strings.Cut(h, ":")
	}
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return false
}

// rebindDevLoopbackEndpoints safely re-anchors static developer loopback URLs
// (e.g. http://localhost:8081/realms/x/...) left inside first-party in-scope
// bundles onto the matching in-scope gateway/origin before canonicalMerge runs.
// When the target scope itself includes loopback (local testbeds), it is a no-op.
func rebindDevLoopbackEndpoints(scripts []Script, eps []*Endpoint, inScope func(host string) bool) {
	if inScope == nil || inScope("localhost") || inScope("127.0.0.1") || inScope("::1") {
		return
	}
	hasLoopback := false
	for _, ep := range eps {
		if ep.Observed == nil && ep.Host != "" && !ep.collector && isLoopbackHost(ep.Host) {
			hasLoopback = true
			break
		}
	}
	if !hasLoopback {
		return
	}

	type scopedBase struct {
		host string
		path string
	}
	parseScopedBases := func(s Script) []scopedBase {
		var out []scopedBase
		addRaw := func(raw string) {
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || u.Host == "" || isLoopbackHost(u.Host) || !inScope(u.Hostname()) {
				return
			}
			bp := strings.TrimRight(u.EscapedPath(), "/")
			if bp == "" || strings.Contains(bp, placeholder) {
				return
			}
			sb := scopedBase{host: canonHost(u.Host), path: bp}
			if !slices.Contains(out, sb) {
				out = append(out, sb)
			}
		}
		for _, b := range s.Bases {
			addRaw(b)
		}
		for _, st := range s.Settings {
			addRaw(st.Value)
		}
		return out
	}

	bySHA := map[string][]scopedBase{}
	var allBases []scopedBase
	for _, s := range scripts {
		if isTrackerScript(s) {
			continue
		}
		sbs := parseScopedBases(s)
		if len(sbs) == 0 {
			continue
		}
		bySHA[s.SHA256] = sbs
		for _, sb := range sbs {
			if !slices.Contains(allBases, sb) {
				allBases = append(allBases, sb)
			}
		}
	}

	matchPrefixHost := func(epPath string, pool []scopedBase) string {
		bestLen := 0
		bestHost := ""
		ambig := false
		for _, sb := range pool {
			if epPath != sb.path && !strings.HasPrefix(epPath, sb.path+"/") {
				continue
			}
			if len(sb.path) > bestLen {
				bestLen = len(sb.path)
				bestHost = sb.host
				ambig = false
			} else if len(sb.path) == bestLen && sb.host != bestHost {
				ambig = true
			}
		}
		if ambig {
			return ""
		}
		return bestHost
	}

	firstPartyHost := func(ep *Endpoint) string {
		if so := epScriptOrigin(ep, inScope); so != "" {
			if u, err := url.Parse(so); err == nil && u.Host != "" && !isLoopbackHost(u.Host) {
				return canonHost(u.Host)
			}
		}
		one := ""
		for _, src := range ep.Static {
			u, err := url.Parse(src.Script)
			if err != nil || u.Host == "" || isLoopbackHost(u.Host) || !inScope(u.Hostname()) {
				continue
			}
			ch := canonHost(u.Host)
			if one != "" && one != ch {
				return ""
			}
			one = ch
		}
		return one
	}

	for _, ep := range eps {
		if ep.Observed != nil || ep.Host == "" || ep.collector || !isLoopbackHost(ep.Host) {
			continue
		}
		fpHost := firstPartyHost(ep)
		if fpHost == "" {
			continue
		}
		var ownPool []scopedBase
		for _, src := range ep.Static {
			for _, sb := range bySHA[src.SHA256] {
				if !slices.Contains(ownPool, sb) {
					ownPool = append(ownPool, sb)
				}
			}
		}
		targetHost := matchPrefixHost(ep.Path, ownPool)
		if targetHost == "" {
			targetHost = matchPrefixHost(ep.Path, allBases)
		}
		if targetHost == "" {
			targetHost = fpHost
		}
		ep.Host = targetHost
		ep.ThirdParty = false
		ep.Bases = nil
	}
}
