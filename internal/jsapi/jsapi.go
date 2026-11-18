// Package jsapi finds the API calls in a script without running it: the
// URL each call builds (as a template, {} for what the code computes), its
// method, and the names of its query, body and header parameters. It reads
// minified bundles, where library names are gone, so it goes by the shape
// of a call rather than by its name. It is pure: source in, results out.
package jsapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"

	"github.com/TimoMangCut/JSharvest/internal/secretsig"
)

// Version changes when what Extract finds changes, so that cached results
// are made again.
const Version = 41

// Endpoint is one call to a URL that a script makes.
type Endpoint struct {
	Method string `json:"method,omitempty"` // empty when the code does not say
	// URL is the path (or absolute URL) without its query, with {} for each
	// part the code computes.
	URL  string `json:"url"`
	Kind string `json:"kind"` // fetch, xhr, client, wrapper, options, websocket, sse, beacon, navigation, string
	// Client is a client's path relative to a base URL set elsewhere, as
	// an axios instance or an Angular service builds it.
	Client     bool     `json:"client,omitempty"`
	BaseKeys   []string `json:"base_keys,omitempty"`
	Query      []string `json:"query,omitempty"`
	Body       []string `json:"body,omitempty"`
	Headers    []string `json:"headers,omitempty"`
	Auth       []string `json:"auth,omitempty"`
	Operations []string `json:"operations,omitempty"` // GraphQL: "mutation Name"
	// NoInheritBase: the URL's root is none of the app's bases (an
	// analytics collector's, a file under a URL the caller gives);
	// Collector, an analytics collector's (Snowplow, GA).
	NoInheritBase bool `json:"no_inherit_base,omitempty"`
	// Params are what is known of the parameters: type, values, place.
	Params    []ParamSpec `json:"params,omitempty"`
	Collector bool        `json:"collector,omitempty"`
	// Base is the base a document puts the path under: the URL it exports
	// (export SLINK_HOST="https://…/api/v1"; curl "$SLINK_HOST/x"), or
	// "$SLINK_HOST" when another script of the portal exports it.
	Base    string `json:"base,omitempty"`
	Line    int    `json:"line,omitempty"`
	Col     int    `json:"col,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

// Result is what one script holds.
type Result struct {
	Version   int        `json:"version"`
	Endpoints []Endpoint `json:"endpoints"`
	// Routes are client-side paths (a router's table, history.pushState):
	// pages to visit rather than API calls.
	Routes       []string     `json:"routes,omitempty"`
	RouteEntries []RouteEntry `json:"route_entries,omitempty"`
	// Bases are the base URLs clients are given (baseURL: "/api").
	Bases []string `json:"bases,omitempty"`
	// Operations are the GraphQL operations not tied to a call.
	Operations []string `json:"operations,omitempty"`
	// Paths are the other strings that read as a URL: "/a/b", an absolute
	// URL, or an href, src or action inside a string of HTML. They are
	// pages to visit as often as anything (a.href = "/x"), which a
	// crawler's frontier tries; they are not endpoints.
	Paths []string `json:"paths,omitempty"`
	// ClientHeaders are the headers a client sets on every request
	// (config.headers.client_id = "…" in an interceptor, axios.create's
	// headers), with their value when the code has it: what a request made
	// by hand needs to get past the API's gateway.
	ClientHeaders []Header `json:"client_headers,omitempty"`
	// Cloud are the URLs of cloud storage (S3, GCS, Azure blobs…) the
	// script names.
	Cloud []string `json:"cloud,omitempty"`
	// Keys are the settings that name a key, an id or a secret
	// (firebase's apiKey, a client_id, a Sentry dsn) with their value,
	// from the code or from a config it decodes at run time (a base64
	// JSON string): what a request made by hand may need.
	Keys []Header `json:"keys,omitempty"`
	// Exports and Imports are the request helpers a module exports, and
	// the calls to another module's: the catalog joins them (COV-04).
	Exports   []Export   `json:"exports,omitempty"`
	Imports   []Import   `json:"imports,omitempty"`
	ReExports []ReExport `json:"re_exports,omitempty"`
	// Builders are the functions this module exports that make a URL
	// (function MT(e){ return … `/items/${e}` }); Deferred the requests
	// whose URL calls one another module exports (Sf.patch(`${Qi(c)}/${k}`)),
	// joined by the catalog (round 27A, deferred.go).
	Builders []Builder  `json:"builders,omitempty"`
	Deferred []Deferred `json:"deferred,omitempty"`
	// Settings are the base URLs named by a setting (AUTH_API_URL), by
	// that name: the base an import's call names picks one.
	Settings []Header `json:"settings,omitempty"`
	// PropBases are static property-to-base bindings ({authServer: "https://…"},
	// {baseUrl: y.value}, obj.customGw = "/api-gw") resolved by AST dataflow
	// without relying on property-name heuristics.
	PropBases []Header `json:"prop_bases,omitempty"`
	// DocVars are the variables the script's documents set to a URL
	// (export SLINK_HOST=https://…), for an endpoint another page of the
	// portal documents under one ($SLINK_HOST/x, its Base "$SLINK_HOST").
	DocVars []Header `json:"doc_vars,omitempty"`
	// DocProd are the production hosts the documents' tables of
	// environments name; DocDev the variables they set to a development
	// host: production's (ProdOf) stands for those.
	DocProd []string `json:"doc_prod,omitempty"`
	DocDev  []Header `json:"doc_dev,omitempty"`
	// Factories are the client factories exports call, or this script
	// gives a setting's base.
	Factories            []Factory             `json:"factories,omitempty"`
	GraphQLDocs          []GraphQLDoc          `json:"graphql_docs,omitempty"`
	ClientAuthz          *ClientAuthz          `json:"client_authz,omitempty"`
	ConstExports         []ConstDict           `json:"const_exports,omitempty"`
	UnresolvedRoutePerms []UnresolvedRoutePerm `json:"unresolved_route_perms,omitempty"`
	UnresolvedAuthzRules []UnresolvedAuthzRule `json:"unresolved_authz_rules,omitempty"`
	ASTLowered           bool                  `json:"ast_lowered,omitempty"`
	LooseFallback bool         `json:"loose_fallback,omitempty"`
	ParseError    string       `json:"parse_error,omitempty"`
	Error         string       `json:"error,omitempty"`
}

// Header is a header a client sets, and its value as a template ({} for
// what the code computes).
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Line  int    `json:"line,omitempty"`
}

const unknown = "{}"

var httpMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}

// clientMethods are the methods of an HTTP client object, whose name is
// kept by minifiers (it is a property).
var clientMethods = map[string]string{"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "head": "HEAD", "options": "OPTIONS"}

var baseNames = map[string]bool{"baseURL": true, "baseUrl": true, "apiUrl": true, "apiURL": true, "apiBase": true, "apiBaseUrl": true,
	"apiBaseURL": true, "API_URL": true, "API_BASE": true, "basePath": true, "apiRoot": true, "apiEndpoint": true}

// isBaseName reports whether a key or property names an API's base URL:
// baseURL and the like, VITE_CONSOLE_API_BASE_URL, AUTH_API_URL,
// customerProfileBaseUrl, OAUTH_AUTH_BASE; not a page's (LOGIN_URL,
// APP_BASE_URL, HOME_PAGE_URL) nor a CDN's.
func isBaseName(name string) bool {
	if baseNames[name] {
		return true
	}
	if len(name) > 64 || len(name) < 4 {
		return false
	}
	n := strings.ToLower(sepCutter.Replace(name))
	if !strings.Contains(n, "url") && !strings.Contains(n, "base") && !strings.Contains(n, "uri") && !strings.Contains(n, "api") &&
		!strings.Contains(n, "endpoint") {
		return false
	}
	for _, w := range []string{"cdn", "asset", "static", "image", "media", "login", "logout", "home", "page", "web", "site", "redirect", "callback", "return", "app", "docs", "help", "socket"} {
		if strings.Contains(n, w) {
			return false
		}
	}
	has := func(suffixes ...string) bool {
		for _, x := range suffixes {
			if strings.HasSuffix(n, x) {
				return true
			}
		}
		return false
	}
	switch {
	case strings.Contains(n, "api") && has("url", "base", "uri", "endpoint", "root", "host", "path", "prefix"):
		return true
	case has("baseurl", "baseuri", "authbase", "serviceurl", "gatewayurl", "backendurl", "graphqlurl", "graphqlendpoint", "serverurl", "resturl", "restendpoint"):
		return true
	}
	return false
}

var sepCutter = strings.NewReplacer("_", "", "-", "")

// headerValue reports whether a value may be a header's: not a number, a
// boolean, null or undefined.
func headerValue(e js.IExpr) bool {
	switch v := e.(type) {
	case *js.LiteralExpr:
		switch v.TokenType {
		case js.DecimalToken, js.IntegerToken, js.HexadecimalToken, js.OctalToken, js.BinaryToken,
			js.TrueToken, js.FalseToken, js.NullToken:
			return false
		}
	case *js.UnaryExpr:
		// -48, !0, void 0
		return v.Op != js.NegToken && v.Op != js.NotToken && v.Op != js.VoidToken
	case *js.Var:
		return string(v.Data) != "undefined"
	}
	return true
}

// headerNameRe is a header's name only a client sets: an X- header, or
// Authorization. Content-Type and the like say nothing of the API.
var headerNameRe = regexp.MustCompile(`^(?:X-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*|Authorization)$`)

// keyWords are in every name keyNameRe takes: a cheap test before it.
var keyWords = []string{"key", "secret", "id", "domain", "bucket", "dsn", "url", "token"}

func keyName(name string) bool {
	if len(name) < 3 || len(name) > 64 {
		return false
	}
	n := strings.ToLower(name)
	for _, w := range keyWords {
		if strings.Contains(n, w) {
			return keyNameRe.MatchString(name)
		}
	}
	return false
}

// envKeyRe is the name of a build's environment variable, which code reads
// with a default: env("VITE_AUTH_API_BASE_URL", "/hub/auth").
var envKeyRe = regexp.MustCompile(`^(?:VITE|NEXT_PUBLIC|REACT_APP|VUE_APP|NUXT|PUBLIC|NG|EXPO_PUBLIC)_[A-Z0-9_]+$|^[A-Z][A-Z0-9]*_[A-Z0-9_]*(?:URL|URI|BASE|HOST|ENDPOINT|API|PATH)[A-Z0-9_]*$`)

// Extract finds the endpoints of a script. A script that does not parse
// gives none, and says why. When tdewolff/parse rejects valid ES2015+
// arrow destructuring (e.g. `({ a: b = 1 } = { a: 1 }) => b`), esbuild's
// pure-Go JS loader lowers arrow syntax while preserving VLQ line maps.
func Extract(src []byte) Result {
	r := extractWithMap(src, nil, nil, false)
	if strings.HasPrefix(r.Error, "parse") {
		if code, lm, ok := transformJSLower(src); ok {
			if r2 := extractWithMap(code, src, lm, false); !strings.HasPrefix(r2.Error, "parse") {
				r2.ASTLowered = true
				return r2
			}
		}
	}
	return r
}

// extract reads a script; nested, the code a document shows, whose own
// documents' code is not read again.
func extract(src []byte, nested bool) Result { return extractWithMap(src, nil, nil, nested) }

func extractWithMap(src, origSrc []byte, lm *esbuildLineMap, nested bool) (res Result) {
	res.Version = Version
	defer func() {
		if r := recover(); r != nil {
			res = Result{Version: Version, Error: fmt.Sprintf("parse: %v", r)}
		}
	}()
	ast, err := js.Parse(parse.NewInputBytes(src), js.Options{})
	if err != nil {
		res.Error = "parse: " + firstLine(err.Error())
		return res
	}
	x := newExtractor(src, origSrc, lm, nested)
	x.prepare(ast)
	js.Walk(callVisitor{x}, ast)
	if len(x.reqBases) > 0 {
		x.cursor = 0
		js.Walk(urlReturnVisitor{x}, ast)
	}
	x.cursor = 0
	js.Walk(moduleVisitor{x}, ast)
	x.cursor = 0
	extractModernRPC(ast, x)
	x.cursor = 0
	js.Walk(stringVisitor{x: x}, ast)
	res = x.result()
	res.GraphQLDocs = extractGraphQLDocs(ast, x)
	res.ClientAuthz = extractClientAuthz(ast, x)
	res.UnresolvedAuthzRules = x.unresolvedAuthzRules
	return res
}

// collectorRe is the path of an analytics collector's endpoint.
var collectorRe = regexp.MustCompile(`(?i)/com\.snowplowanalytics\.snowplow/|/(?:g|j|mp)/collect$|^https://(?:www\.)?google-analytics\.com/`)

// staticJSONRe is a JSON file right under an unknown root ({}/app-config.json);
// specNameRe an API description's name, which stays an API's.
var (
	staticJSONRe = regexp.MustCompile(`^\{\}/[\w.-]+\.json$`)
	specNameRe   = regexp.MustCompile(`(?i)(openapi|swagger|api-docs|asyncapi)`)
)

// keyNameRe names a setting whose value is a key, an id or a secret.
var keyNameRe = regexp.MustCompile(`(?i)(?:^|[_-]|[a-z])(?:api[_-]?key|secret|access[_-]?key|client[_-]?id|app[_-]?id|project[_-]?id|sender[_-]?id|measurement[_-]?id|auth[_-]?domain|storage[_-]?bucket|dsn|site[_-]?key|tenant[_-]?id|database[_-]?url|vapid[_-]?key|public[_-]?key|token)$|^(?:apiKey|appId|projectId|dsn)$`)

// keyValue reports whether a value reads as a key's: one word, not a path
// nor a word of a sentence.
func keyValue(v string) bool {
	if len(v) < 6 || len(v) > 512 || strings.ContainsAny(v, " \t\n<>{}`") || strings.HasPrefix(v, "/") {
		return false
	}
	switch strings.ToLower(v) {
	case "true", "false", "null", "undefined":
		return false
	}
	return true
}

func (x *extractor) key(name, value string, line int) {
	if name == "" || !keyName(name) || !keyValue(value) || strings.EqualFold(sepCutter.Replace(name), sepCutter.Replace(value)) {
		return
	}
	x.recordKey(name, value, line)
}

func (x *extractor) keyExpr(name string, val js.IExpr) {
	v, ok := literalString(val)
	if !ok {
		return
	}
	line := 0
	if l, ok := ungroup(val).(*js.LiteralExpr); ok && len(l.Data) > 2 {
		if i := bytes.Index(x.src, l.Data); i >= 0 {
			line, _ = x.mappedLineCol(i)
		}
	}
	x.key(name, v, line)
}

func (x *extractor) recordKey(name, value string, line int) {
	k := name + "\x00" + value
	if x.keysSeen[k] {
		if line > 0 {
			for i := range x.keys2 {
				if x.keys2[i].Name == name && x.keys2[i].Value == value && x.keys2[i].Line == 0 {
					x.keys2[i].Line = line
				}
			}
		}
		return
	}
	x.keysSeen[k] = true
	x.secretVals[value] = true
	x.keys2 = append(x.keys2, Header{Name: name, Value: value, Line: line})
}

func (x *extractor) secretKeys(prop, s string, line int) {
	for _, m := range secretsig.FindAll(s) {
		name := prop
		if name == "" {
			if x.secretVals[m.Value] {
				continue
			}
			name = m.Kind
		}
		x.recordKey(name, m.Value, line)
	}
}

func (x *extractor) litLine(raw []byte) int {
	if len(raw) == 0 || len(x.src) == 0 {
		return 0
	}
	i := bytes.Index(x.src[x.cursor:], raw)
	if i >= 0 {
		i += x.cursor
	} else if i = bytes.Index(x.src, raw); i < 0 {
		return 0
	}
	line, _ := x.mappedLineCol(i)
	return line
}

// configPairRe is a "key":"value" pair of JSON, in a string the code
// holds: a Next.js RSC payload's {"config":{"API_URL":"https://…"}}.
var configPairRe = regexp.MustCompile(`"([A-Za-z_$][A-Za-z0-9_$.-]{0,63})"\s*:\s*"((?:[^"\\]|\\.){1,1000})"`)

// configPairs reads the settings in JSON a string holds: base URLs, keys,
// the URLs the app links to.
func (x *extractor) configPairs(text string, raw []byte) {
	if len(text) > 4<<20 || !strings.Contains(text, `":`) || (!configHint(text) && !secretsig.HasHint(text)) {
		return
	}
	line := 0
	lineOf := func() int {
		if line == 0 && len(raw) > 0 {
			line = x.litLine(raw)
		}
		return line
	}
	for _, m := range configPairRe.FindAllStringSubmatch(text, 5000) {
		var v string
		if json.Unmarshal([]byte(`"`+m[2]+`"`), &v) != nil {
			continue
		}
		switch {
		case isBaseName(m[1]) && (strings.HasPrefix(v, "/") || schemeRe.MatchString(v)):
			x.addBase(v)
			x.settings[m[1]+"\x00"+strings.TrimRight(v, "/")] = true
			if b, ok := cleanPropBase(v); ok {
				x.propBases[m[1]+"\x00"+b] = true
			}
		case schemeRe.MatchString(v):
			if b, ok := cleanPropBase(v); ok && m[1] != "path" && m[1] != "redirect" {
				x.propBases[m[1]+"\x00"+b] = true
			}
			if keyName(m[1]) {
				x.key(m[1], v, lineOf())
			} else if secretsig.HasHint(v) {
				x.secretKeys(m[1], v, lineOf())
			}
			x.path(v)
			x.cloudURLs(v)
		default:
			if b, ok := cleanPropBase(v); ok && m[1] != "path" && m[1] != "redirect" {
				x.propBases[m[1]+"\x00"+b] = true
			}
			if keyName(m[1]) {
				x.key(m[1], v, lineOf())
			} else if secretsig.HasHint(v) {
				x.secretKeys(m[1], v, lineOf())
			}
		}
	}
}

// configHints end the keys configPairs reads; a text with none of them
// is not read with the regexp.
var configHints = []string{`URL":`, `Url":`, `url":`, `URI":`, `Uri":`, `BASE":`, `Base":`, `base":`, `KEY":`, `Key":`, `key":`,
	`ID":`, `Id":`, `id":`, `SECRET":`, `Secret":`, `secret":`, `Domain":`, `DOMAIN":`, `domain":`, `Bucket":`, `bucket":`, `dsn":`, `DSN":`,
	`TOKEN":`, `Token":`, `token":`, `ENDPOINT":`, `Endpoint":`, `endpoint":`}

func configHint(text string) bool {
	for _, h := range configHints {
		if strings.Contains(text, h) {
			return true
		}
	}
	return false
}

// b64Re is a string of base64, padded or not.
var b64Re = regexp.MustCompile(`^={0,2}[A-Za-z0-9+/_-]+={0,2}$`)

// encoded reads a JSON object an app keeps as base64, as it is or
// reversed (JSON.parse(atob(s.split("").reverse().join("")))): its
// production settings, which the code's own literals are the defaults
// of.
func (x *extractor) encoded(s string, rawLit []byte) {
	if len(s) < 24 || len(s) > 1<<20 {
		return
	}
	fwd := strings.HasPrefix(s, "eyJ") || strings.HasPrefix(s, "W3s")
	rev := strings.HasSuffix(s, "Jye") || strings.HasSuffix(s, "s3W")
	if !fwd && !rev || !b64Re.MatchString(s) {
		return
	}
	var cands []string
	if fwd {
		cands = append(cands, s)
	}
	if rev {
		r := []byte(s)
		slices.Reverse(r)
		cands = append(cands, string(r))
	}
	for _, c := range cands {
		var raw []byte
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(c); err == nil {
				raw = b
				break
			}
		}
		if len(raw) > 0 && json.Valid(raw) {
			x.configPairs(string(raw), rawLit)
			return
		}
	}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

type extractor struct {
	src            []byte
	origSrc        []byte
	lineMap        *esbuildLineMap
	origLineStarts []int
	defs           map[*js.Var][]js.IExpr // what each variable is assigned
	used           map[*js.LiteralExpr]bool
	eps            map[string]*Endpoint
	order          []string
	routes         map[string]bool
	bases          map[string]bool
	ops            map[string]bool // every GraphQL operation seen
	// opsUsed are those attached to a call.
	opsUsed map[string]bool
	paths   map[string]bool
	sums    map[*js.Var]*summary
	xhrs    map[*js.Var]string // an XMLHttpRequest's endpoint, by the variable it is in
	cursor  int
	// lits are the source texts of the literals the last URL was made of,
	// to find where it is.
	lits [][]byte

	// chains are the values each variable is given, in the order of the
	// source: a chain starts at an assignment and goes on through those
	// that build on it (t += …, t = "".concat(t, …), t = new B(t).x()).
	chains    map[*js.Var][]chain
	declDepth map[*js.Var]int      // how many conditions a declaration is under
	bind      map[*js.Var][]string // a variable's value while a step that builds on it is evaluated
	busy      map[any]bool         // what is being evaluated: no loops
	// thisProps are the values given to this.<name> (or to that of an
	// alias, e = this), by name, across the script: a Vue component's
	// this.detailUrl, which a parent may set as a prop.
	thisProps map[string][]js.IExpr
	props     []propDef
	propsOf   map[*js.Var][]string // props by variable, made when first read
	dataObjs  []*js.ObjectExpr     // what data() functions return
	// baseExprs are the baseURL values that are no literal; dynBase is
	// when none of them evaluates, and baseCands the strings that read as
	// an API's root then.
	baseExprs  []js.IExpr
	dynBase    bool
	baseCands  map[string]bool
	headers    []propDef // config.headers.<name> = value
	cloud      map[string]bool
	concats    map[*js.CallExpr]bool // "".concat(…) calls read in a longer chain
	lineStarts []int
	// args are the parameters of a helper being read at a call, bound to
	// what the call gives them.
	args map[*js.Var]js.IExpr
	// routeCalls are the calls that name a router's page, read already.
	routeCalls map[*js.CallExpr]bool
	routeObjs  map[*js.ObjectExpr]bool
	routeMap   map[string]*RouteEntry
	routeOrder []string
	keys2      []Header // the settings that are keys (Result.Keys)
	keysSeen   map[string]bool
	secretVals map[string]bool
	// clientPre are the prefixes each client object's constructor gives
	// it (Z = withBase("/api"), then Z.get("/me") is /api/me), and
	// factoryCalls the calls that make one, which are no endpoints.
	clientPre    map[*js.Var][]string
	factoryCalls map[*js.CallExpr]bool
	pre          []string // the prefixes of the client whose call add reads
	// evalCall's: the calls it is in, how many it made, what functions
	// without parameters return, and its last result.
	calls, callBudget, rootEvals int
	noArgs                       map[*js.Var][]string
	qparams                      map[*js.Var]int
	// producers are the nodes each endpoint was found at; inst, what
	// the calls to a helper made of the call in its body (summary.call).
	producers   map[string][]js.INode
	inst        map[*js.CallExpr][]string
	maker       map[*js.CallExpr]bool
	apiBuilders map[*js.Var]bool
	nested      bool
	ownPre      map[string]bool
	basedPre    map[string]bool
	methodDefs  map[string][]methodDef
	// paramOf is the function a parameter is of, and its place; callsTo
	// the calls of a function: for e.apiBase read from what its callers
	// give (fromCallers).
	paramOf map[*js.Var]paramPlace
	callsTo map[*js.Var][]*js.CallExpr
	// destructFrom is what a variable is destructured from ({apiBase: t}
	// = e); propOf its key.
	destructFrom map[*js.Var]js.IExpr
	sse          map[*js.Var]int // sseParam's, by function
	hasSSE       bool            // the script names text/event-stream
	// fromMemo and givenMemo keep what fromCallersOf and givenFn read off
	// the callers, which is the same wherever it is asked.
	fromMemo  map[[2]any][]string
	givenMemo map[*js.DotExpr]js.IExpr
	// methodMemo keeps methodOf's for receivers that read the same
	// everywhere.
	methodMemo map[methodKey]js.IExpr
	// keyInfo is what the fields of the object literals read for the call
	// being read hold (typeOf); curNames the names of the path's
	// parameters of the URL being added (pathNames).
	keyInfo  map[string]keyInfo
	curNames []string
	// docProd are the production hosts documents' tables name; docDev the
	// variables they set to a development host; pendingBody a request a
	// page writes alone, waiting for the data after it (pendingLeft
	// strings more).
	docProd     []string
	docDev      map[string][]string
	pendingBody string
	pendingLeft int
	// ownerOf is the object or class a method is on; objParent and
	// objKey the object holding an object as a property, and its name
	// ({methods: {…}} of a Vue component).
	ownerOf   map[js.INode]js.INode
	objParent map[*js.ObjectExpr]*js.ObjectExpr
	objKey    map[*js.ObjectExpr]string
	// fnStack are the functions around the call being read (callVisitor),
	// or the method being summarized: what this is in this.x(…).
	fnStack []js.INode
	docVars map[string][]string
	named   map[string][]js.IExpr
	madeBy  map[*js.ObjectExpr]*js.Var
	classOf map[*js.ClassDecl]*js.Var
	// Round 26A (classes.go): the script's classes, the class each
	// variable names, the instances made of each, the URL objects whose
	// parts are set, and while reading: the path of the URL object being
	// evaluated, the instances being read (innermost last), the class
	// whose field initialiser the call being read is in.
	classes     map[*js.ClassDecl]*classInfo
	classOrder  []*js.ClassDecl // the classes in the order the script declares them
	classByVar  map[*js.Var]*js.ClassDecl
	subclasses  map[*js.ClassDecl][]*js.ClassDecl
	privOwner   map[*js.Var]*js.ClassDecl // the class each #private name is declared in
	newSites    map[*js.ClassDecl][]*js.NewExpr
	urlSets     map[*js.Var][]urlSet
	urlPath     map[*js.Var][]string
	self        []*js.ClassDecl
	entryClass  *js.ClassDecl
	thisStack   []js.INode
	fnBase      int                // x.fnStack's length at the call the call pass reads
	readChain   []*js.CallExpr     // the calls in helpers a call read went through
	usedLog     *[]*js.LiteralExpr // the literals a read marked used, while one is kept
	msums       map[js.IExpr]*summary
	made        *[]string
	factories   map[*js.Var]*Factory
	factoryList []*Factory
	tailQuery   map[*js.CallExpr][]string
	lastCall    []string
	// propOf is the property a destructured variable was taken from
	// ({fetchFn: i = globalThis.fetch} = e: i is fetchFn).
	propOf map[*js.Var]string
	// clients are the objects made by a client's constructor or factory.
	clients      map[*js.Var]bool
	exports      []Export
	imports      []Import
	reExports    []ReExport
	builders     []Builder
	deferred     []Deferred
	exportVars   map[string]*js.Var // what each name this module exports is
	deferring    bool               // a request's URL is being read: imported calls are marked
	deferCalls   []deferCall
	reqBases     map[string]bool // the bases requests' URLs are built on (urlreturn.go)
	settings     map[string]bool // name, a zero byte, the base
	propBases    map[string]bool // name, a zero byte, the base (any property, by value shape)
	propBaseDefs []propDef
	noMarkUsed   bool
	// qset are the keys code sets on an object (p.set("k", v)): a
	// URLSearchParams' query.
	qset            map[*js.Var][]string
	segProps        map[string][]js.IExpr
	joinedSeg       map[string]bool
	esImports       map[*js.Var][2]string
	esNSImports     map[*js.Var]string
	awaited         map[*js.CallExpr]bool
	enumProps       map[*js.Var]map[string]js.IExpr
	enumParamTarget map[*js.Var]*js.Var
	omitted         map[*js.Var]bool
	supplied        map[*js.Var]bool
	viaCalls        map[*js.CallExpr]bool
	wpModExports         map[string]map[string]js.IExpr
	wpModDefault         map[string]js.IExpr
	wpReqVars            map[*js.Var]bool
	jsonObjs             map[*js.CallExpr]*js.ObjectExpr
	declFnDepth          map[*js.Var]int
	renderCtxVars        map[*js.Var]bool
	hasVueRenderHint     bool
	thisObjCache         map[string]*js.ObjectExpr
	thisObjDone          map[string]bool
	thisEnumCache        map[string]*js.Var
	thisEnumDone         map[string]bool
	esExports            map[string]js.IExpr
	turbopackConst       map[[2]string]js.IExpr
	unresolvedRoutePerms []UnresolvedRoutePerm
	unresolvedAuthzRules []UnresolvedAuthzRule
}

// newExtractor is an extractor for a script, its tables empty.
func newExtractor(src, origSrc []byte, lm *esbuildLineMap, nested bool) *extractor {
	hasVueHint := bytes.Contains(src, []byte("_c")) || bytes.Contains(src, []byte("$createElement")) || bytes.Contains(src, []byte("_sfc_render"))
	return &extractor{src: src, origSrc: origSrc, lineMap: lm, nested: nested, defs: map[*js.Var][]js.IExpr{}, used: map[*js.LiteralExpr]bool{}, eps: map[string]*Endpoint{},
		routes: map[string]bool{}, bases: map[string]bool{}, ops: map[string]bool{}, opsUsed: map[string]bool{}, paths: map[string]bool{},
		sums: map[*js.Var]*summary{}, xhrs: map[*js.Var]string{},
		chains: map[*js.Var][]chain{}, declDepth: map[*js.Var]int{}, declFnDepth: map[*js.Var]int{}, bind: map[*js.Var][]string{}, busy: map[any]bool{},
		thisProps: map[string][]js.IExpr{}, baseCands: map[string]bool{}, cloud: map[string]bool{}, concats: map[*js.CallExpr]bool{},
		args: map[*js.Var]js.IExpr{}, routeCalls: map[*js.CallExpr]bool{}, routeObjs: map[*js.ObjectExpr]bool{}, routeMap: map[string]*RouteEntry{}, keysSeen: map[string]bool{}, secretVals: map[string]bool{},
		clientPre: map[*js.Var][]string{}, factoryCalls: map[*js.CallExpr]bool{}, noArgs: map[*js.Var][]string{}, qparams: map[*js.Var]int{}, ownPre: map[string]bool{}, basedPre: map[string]bool{}, docVars: map[string][]string{}, docDev: map[string][]string{}, methodDefs: map[string][]methodDef{}, paramOf: map[*js.Var]paramPlace{}, callsTo: map[*js.Var][]*js.CallExpr{}, destructFrom: map[*js.Var]js.IExpr{}, sse: map[*js.Var]int{}, hasSSE: bytes.Contains(src, []byte("text/event-stream")), fromMemo: map[[2]any][]string{}, givenMemo: map[*js.DotExpr]js.IExpr{}, methodMemo: map[methodKey]js.IExpr{}, ownerOf: map[js.INode]js.INode{}, objParent: map[*js.ObjectExpr]*js.ObjectExpr{}, objKey: map[*js.ObjectExpr]string{}, named: map[string][]js.IExpr{}, madeBy: map[*js.ObjectExpr]*js.Var{}, classOf: map[*js.ClassDecl]*js.Var{}, msums: map[js.IExpr]*summary{}, apiBuilders: map[*js.Var]bool{}, producers: map[string][]js.INode{}, inst: map[*js.CallExpr][]string{}, maker: map[*js.CallExpr]bool{}, factories: map[*js.Var]*Factory{}, tailQuery: map[*js.CallExpr][]string{}, propOf: map[*js.Var]string{}, clients: map[*js.Var]bool{}, qset: map[*js.Var][]string{}, settings: map[string]bool{}, propBases: map[string]bool{}, segProps: map[string][]js.IExpr{}, joinedSeg: map[string]bool{}, esImports: map[*js.Var][2]string{}, esNSImports: map[*js.Var]string{}, awaited: map[*js.CallExpr]bool{}, enumProps: map[*js.Var]map[string]js.IExpr{}, enumParamTarget: map[*js.Var]*js.Var{}, omitted: map[*js.Var]bool{}, supplied: map[*js.Var]bool{}, viaCalls: map[*js.CallExpr]bool{},
		wpModExports: map[string]map[string]js.IExpr{}, wpModDefault: map[string]js.IExpr{}, wpReqVars: map[*js.Var]bool{}, jsonObjs: map[*js.CallExpr]*js.ObjectExpr{},
		renderCtxVars: map[*js.Var]bool{}, hasVueRenderHint: hasVueHint, thisObjCache: map[string]*js.ObjectExpr{}, thisObjDone: map[string]bool{}, thisEnumCache: map[string]*js.Var{}, thisEnumDone: map[string]bool{}, esExports: map[string]js.IExpr{}, turbopackConst: map[[2]string]js.IExpr{},
		classes: map[*js.ClassDecl]*classInfo{}, classByVar: map[*js.Var]*js.ClassDecl{}, subclasses: map[*js.ClassDecl][]*js.ClassDecl{}, privOwner: map[*js.Var]*js.ClassDecl{}, newSites: map[*js.ClassDecl][]*js.NewExpr{}, urlSets: map[*js.Var][]urlSet{}, urlPath: map[*js.Var][]string{}, exportVars: map[string]*js.Var{}, reqBases: map[string]bool{}}
}

// prepare reads a script's definitions: the passes before the calls pass.
func (x *extractor) prepare(ast *js.AST) {
	js.Walk(&defsVisitor{x: x}, ast)
	x.settle()
	js.Walk(clientVisitor{x}, ast)
	js.Walk(methodVisitor{x}, ast)
	x.indexClasses(ast)
	js.Walk(builderVisitor{x}, ast)
	x.scanESModules(ast)
}
