// Package guard keeps a harvest from changing the target: it holds back
// requests that write, log out or destroy, answers them with a harmless
// success so that the page carries on, and records each one.
package guard

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
)

// Action is what happens to a request.
type Action string

const (
	Pass Action = "pass" // sent as is
	// Fake answers the request with a harmless success. A blocked request is
	// never failed: a failure looks like a network error, which a service
	// worker's background sync stores and sends again later, when no guard
	// is running.
	Fake Action = "fake"
)

type Request struct {
	Method       string
	URL          string
	ContentType  string
	Body         string
	ResourceType string
	// Override is a method override header's value (X-HTTP-Method-Override
	// and the like), which many servers obey over the request's method.
	Override string
}

// overrideHeaders name the method a server should take a POST for.
var overrideHeaders = []string{"x-http-method-override", "x-http-method", "x-method-override"}

// OverrideHeader returns a method override header's value, from headers
// whose names are lower case.
func OverrideHeader(headers map[string]string) string {
	for _, h := range overrideHeaders {
		if v := strings.TrimSpace(headers[h]); v != "" {
			return v
		}
	}
	return ""
}

// EffectiveMethod is the method a server may act on: an override header,
// or a _method parameter in the query or a form body (Rails, Laravel),
// over the request's own.
func EffectiveMethod(method, override, rawURL, contentType, body string) string {
	if override != "" {
		return strings.ToUpper(override)
	}
	if u, err := url.Parse(rawURL); err == nil {
		if m := u.Query().Get("_method"); m != "" {
			return strings.ToUpper(m)
		}
	}
	if strings.Contains(contentType, "x-www-form-urlencoded") || strings.Contains(contentType, "multipart/") {
		if f, err := url.ParseQuery(body); err == nil && f.Get("_method") != "" {
			return strings.ToUpper(f.Get("_method"))
		}
		if strings.Contains(body, `name="_method"`) {
			return "POST+OVERRIDE" // a multipart override: not a read, whatever it names
		}
	}
	return strings.ToUpper(method)
}

type Decision struct {
	Action Action
	Reason string // allow, refresh, destructive, graphql-mutation, graphql-unknown, write, read, allow-write
}

// Rules holds the policy. The zero value is the default policy.
type Rules struct {
	Allow      *regexp.Regexp // URLs that always pass
	Deny       *regexp.Regexp // extra URLs to block, on top of the destructive words
	AllowWrite bool           // let writes through; destructive URLs are still blocked
	// Explore: the crawl clicks every control by itself, and accepts every
	// confirm(). A DELETE, or a GraphQL mutation that names a destructive
	// action, is destructive even with AllowWrite; a script's GET whose path
	// names an action (approve, archive, toggle…) is held back as a write.
	Explore bool
}

func (r Rules) Classify(req Request) Decision {
	// Deny first: a URL both denied and allowed is held back (an Allow
	// that is too wide, or the user's own refresh rule, never reopens it).
	if r.Deny != nil && r.Deny.MatchString(req.URL) {
		return Decision{Fake, "destructive"}
	}
	if r.Allow != nil && r.Allow.MatchString(req.URL) {
		return Decision{Pass, "allow"}
	}
	if cdnInfra(req.URL) {
		return Decision{Pass, "cdn-infra"}
	}
	if Destructive(req.URL) {
		return Decision{Fake, "destructive"}
	}
	method := EffectiveMethod(req.Method, req.Override, req.URL, req.ContentType, req.Body)
	if method == "DELETE" && !strings.EqualFold(req.Method, "DELETE") {
		return Decision{Fake, "destructive"} // a DELETE disguised as another method
	}
	if strings.EqualFold(req.Method, "POST") && method == "POST" && !isGraphQL(method, req) && refreshGrant(req) {
		return Decision{Pass, "refresh"} // after every Deny/Destructive/DELETE check, before the write branch
	}
	if r.Explore {
		if method == "DELETE" {
			return Decision{Fake, "destructive"}
		}
		if gql, write, _ := graphQL(method, req); gql && write && hasWord(destructiveRe, req.Body+" "+req.URL) {
			return Decision{Fake, "destructive"}
		}
		if (method == "GET" || method == "") && scriptRequest(req.ResourceType) && (actionVerb(req.URL) || operationVerb(req.URL)) {
			return Decision{Fake, "explore-verb"}
		}
	}
	if !r.AllowWrite {
		if gql, write, reason := graphQL(method, req); gql && write {
			return Decision{Fake, reason}
		} else if gql {
			return Decision{Pass, "read"}
		}
	}
	switch method {
	case "GET", "HEAD", "OPTIONS", "":
		return Decision{Pass, "read"}
	}
	if r.AllowWrite {
		return Decision{Pass, "allow-write"}
	}
	return Decision{Fake, "write"}
}

// cdnInfra reports a request to the CDN's own /cdn-cgi/ paths: the
// challenge platform's telemetry and its answer, the RUM beacon, Zaraz,
// trace. They change nothing of the target's, and holding them back breaks
// a challenge that would have passed on its own, and fills blocked.jsonl
// with the vendor's requests. Before the destructive words: the
// challenge's tokens are random and may spell one. Cloudflare Access is the
// exception: /cdn-cgi/access/logout ends the session, so /cdn-cgi/access/
// goes through the rules like the site's own paths.
func cdnInfra(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" {
		return false
	}
	// Only a plain path lets a request through: no escapes, dot segments,
	// ';' parameters or backslashes, which servers read in their own ways
	// (Tomcat's "..;", IIS's "\").
	p := strings.ToLower(u.EscapedPath())
	if strings.ContainsAny(p, "%;\\") || strings.Contains(p, "//") || strings.Contains(p, "/./") || strings.Contains(p, "/../") ||
		strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") {
		return false
	}
	return strings.HasPrefix(p, "/cdn-cgi/") && !strings.HasPrefix(p, "/cdn-cgi/access/")
}

// destructiveRe finds the actions a crawler must never trigger, by any
// method: a GET on /logout ends the session as surely as a POST. Compound
// words may be split by "-" or "_" (sign_out, log-out, end_session).
var destructiveRe = regexp.MustCompile(`(?i)log[-_]?out|log[-_]?off|sign[-_]?out|end[-_]?session|wsignout|revoke|delete|remove|destroy|reset|unsubscribe|deactivate|purge|wipe|truncate|erase`)

// Destructive reports whether a URL's path or query names a destructive
// action as a word of its own: separated by / _ . - ? = & ; , + or the
// ends, or by a camelCase boundary (resetFilters, deleteUser). The URL is
// percent-decoded first, so /%64elete is /delete. It errs towards blocking:
// a page such as /reset-password-help is skipped too, which costs a page,
// never a session.
func Destructive(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	return hasWord(destructiveRe, decode(decode(u.EscapedPath()+"?"+u.RawQuery)))
}

// actionVerbRe names actions that a GET of an app's API may perform for
// all that GET should not: a crawl that clicks every control holds such
// requests back when it explores.
var actionVerbRe = regexp.MustCompile(`(?i)approve|reject|un-?archive|archive|cancel|invite|accept|decline|confirm|mark|toggle|enable|disable|activate|un-?publish|publish|un-?like|like|vote|un-?follow|follow|subscribe|pay|purchase|checkout|purge|clear|wipe|expire|rotate|trigger|execute|restart|un-?lock|lock|un-?ban|ban|kick|grant|assign|transfer|refund|send|sync`)

// actionVerb reports whether a URL's path names an action as a word of its
// own, as Destructive does.
func actionVerb(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return hasWord(actionVerbRe, decode(decode(u.EscapedPath())))
}

// NamesDestructive reports whether a text names a destructive action as a
// word of its own (deleteUser, purge_cache, /logout).
func NamesDestructive(s string) bool { return hasWord(destructiveRe, s) }

// NamesAction reports whether a text names an action a read should not
// perform (approve, toggle, send…), as a word of its own.
func NamesAction(s string) bool { return hasWord(actionVerbRe, s) }

// hasWord reports whether re matches s as a word of its own.
func hasWord(re *regexp.Regexp, s string) bool {
	for _, m := range re.FindAllStringIndex(s, -1) {
		if wordStart(s, m[0]) && wordEnd(s, m[1]) {
			return true
		}
	}
	return false
}

// operationParams are the query parameters by which one URL serves many
// operations (as flow.Discriminators).
var operationParams = []string{"action", "method", "op", "cmd", "operation", "func", "function", "task", "do"}

// operationVerb reports whether a GET names an action in an operation
// parameter: /rpc?action=approve does what /orders/7/approve does.
func operationVerb(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	q := u.Query()
	for _, p := range operationParams {
		if v := q.Get(p); v != "" && hasWord(actionVerbRe, v) {
			return true
		}
	}
	return false
}

// scriptRequest reports whether a request is a script's (fetch, XHR,
// beacon), not a page, frame or resource the browser loads.
func scriptRequest(resourceType string) bool {
	switch resourceType {
	case "XHR", "Fetch", "Ping", "Other", "EventSource":
		return true
	}
	return false
}

func decode(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

func isSep(c byte) bool { return strings.IndexByte("/_.-?=&;,+% ", c) >= 0 }

func wordStart(s string, i int) bool {
	if i == 0 || isSep(s[i-1]) {
		return true
	}
	// camelCase: "userDelete" starts a word at the capital.
	return unicode.IsLower(rune(s[i-1])) && unicode.IsUpper(rune(s[i]))
}

func wordEnd(s string, i int) bool {
	if i == len(s) || isSep(s[i]) {
		return true
	}
	// "wsignout1.0", "revoke2", "resetFilters"
	return unicode.IsUpper(rune(s[i])) || unicode.IsDigit(rune(s[i]))
}

var (
	// writeOpRe finds an operation definition that writes. It runs on the
	// document with comments removed; strings stay, so a string that
	// mentions "mutation X" makes a read look like a write, which blocks a
	// read, never lets a write through.
	writeOpRe = regexp.MustCompile(`(?:^|[\s,{}])(mutation|subscription)\b\s*[\w({@$]`)
	namedOpRe = regexp.MustCompile(`\b(query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)`)
	// docStartRe is how a GraphQL document starts: a selection set, an
	// operation (keyword, optional name, variables and directives, then a
	// selection set) or a fragment. "mutation testing tools" is a search.
	docStartRe = regexp.MustCompile(`^(?:\{|(?:query|mutation|subscription)\s*(?:[_A-Za-z]\w*)?\s*(?:\([^)]*\))?\s*(?:@[_A-Za-z]\w*(?:\([^)]*\))?\s*)*\{|fragment\s+[_A-Za-z]\w*\s+on\s+[_A-Za-z]\w*)`)
)

type gqlOp struct {
	Query         *string         `json:"query"`
	OperationName string          `json:"operationName"`
	Extensions    json.RawMessage `json:"extensions"`
}

// graphQL reports whether the request is GraphQL, and whether it writes.
// A body only counts as GraphQL when its query really reads as a GraphQL
// document: {"query":"shoes"} is a search form's POST, which writes.
func graphQL(method string, req Request) (isGQL, write bool, reason string) {
	var ops []gqlOp
	switch {
	case method == "GET":
		u, err := url.Parse(req.URL)
		if err != nil {
			return false, false, ""
		}
		q := u.Query()
		switch {
		case q.Has("query"):
			if !isDocument(q.Get("query")) {
				return false, false, ""
			}
			doc := q.Get("query")
			ops = []gqlOp{{Query: &doc, OperationName: q.Get("operationName")}}
		case strings.Contains(q.Get("extensions"), "persistedQuery"):
			// A hash-only persisted query over GET: GraphQL over HTTP forbids
			// mutations over GET, so it reads.
			return true, false, ""
		default:
			return false, false, ""
		}
	case strings.Contains(req.ContentType, "application/graphql"):
		if !isDocument(req.Body) {
			return false, false, ""
		}
		doc := req.Body
		ops = []gqlOp{{Query: &doc}}
	default:
		body := strings.TrimSpace(strings.TrimPrefix(req.Body, "\ufeff"))
		if body == "" || (body[0] != '{' && body[0] != '[') {
			return false, false, ""
		}
		if body[0] == '[' {
			var raw []json.RawMessage
			if json.Unmarshal([]byte(body), &raw) != nil {
				return false, false, ""
			}
			for _, r := range raw {
				var o gqlOp
				if json.Unmarshal(r, &o) != nil {
					return true, true, "graphql-unknown"
				}
				ops = append(ops, o)
			}
		} else {
			var o gqlOp
			if json.Unmarshal([]byte(body), &o) != nil {
				return false, false, ""
			}
			ops = []gqlOp{o}
		}
	}

	// Every operation must be a recognised read for the request to pass.
	seenGQL := false
	for _, o := range ops {
		switch {
		case o.Query != nil && isDocument(*o.Query):
			seenGQL = true
			if opWrites(*o.Query, o.OperationName) {
				return true, true, "graphql-mutation"
			}
		case o.Query == nil && strings.Contains(string(o.Extensions), "persistedQuery"):
			// Only a hash: the operation cannot be read, so it may write.
			return true, true, "graphql-unknown"
		default:
			if len(ops) > 1 {
				// An element of a batch that is not a GraphQL read.
				return true, true, "graphql-unknown"
			}
			return false, false, ""
		}
	}
	return seenGQL, false, ""
}

// isDocument reports whether s starts like a GraphQL document, after a byte
// order mark, whitespace, commas and comments.
func isDocument(s string) bool {
	s = stripComments(strings.TrimPrefix(s, "\ufeff"))
	s = strings.TrimLeft(s, " \t\r\n,")
	return docStartRe.MatchString(s)
}

func opWrites(doc, name string) bool {
	doc = stripComments(strings.TrimPrefix(doc, "\ufeff"))
	if name != "" {
		for _, m := range namedOpRe.FindAllStringSubmatch(doc, -1) {
			if m[2] == name {
				return m[1] != "query"
			}
		}
	}
	return writeOpRe.MatchString(doc)
}

// stripComments removes GraphQL comments (# to the end of the line) outside
// string literals, both "…" and block """…""", so that a # inside a string
// cannot hide what follows it.
func stripComments(doc string) string {
	var b strings.Builder
	for i := 0; i < len(doc); {
		switch {
		case strings.HasPrefix(doc[i:], `"""`):
			end := strings.Index(doc[i+3:], `"""`)
			if end < 0 {
				b.WriteString(doc[i:])
				return b.String()
			}
			b.WriteString(doc[i : i+3+end+3])
			i += 3 + end + 3
		case doc[i] == '"':
			j := i + 1
			for j < len(doc) && doc[j] != '"' && doc[j] != '\n' {
				if doc[j] == '\\' {
					j++
				}
				j++
			}
			if j < len(doc) {
				j++
			}
			b.WriteString(doc[i:j])
			i = j
		case doc[i] == '#':
			for i < len(doc) && doc[i] != '\n' {
				i++
			}
		default:
			b.WriteByte(doc[i])
			i++
		}
	}
	return b.String()
}

// refreshGrant reports an OAuth refresh_token grant: a POST whose
// grant_type, in the form body, the JSON body's top level or the query, is
// refresh_token, and that names no other grant anywhere. It renews the
// session, it changes nothing of the target's. The URL's path is never
// taken for one (/api-tokens/refresh rotates a real secret); a revocation
// or introspection endpoint is not one whatever the body says.
func refreshGrant(req Request) bool {
	u, err := url.Parse(req.URL)
	if err != nil || u.Opaque != "" {
		return false
	}
	p := strings.ToLower(decode(decode(u.EscapedPath())))
	if strings.Contains(p, "revoc") || strings.Contains(p, "introspect") {
		return false
	}
	var grants []string
	grants = append(grants, u.Query()["grant_type"]...)
	ct := strings.ToLower(req.ContentType)
	switch {
	case strings.Contains(ct, "x-www-form-urlencoded"):
		f, err := url.ParseQuery(req.Body)
		if err != nil || gqlKeys(f.Has) {
			return false
		}
		grants = append(grants, f["grant_type"]...)
	case strings.Contains(ct, "json"):
		var doc map[string]json.RawMessage
		if json.Unmarshal([]byte(req.Body), &doc) != nil {
			return false
		}
		if gqlKeys(func(k string) bool { _, ok := doc[k]; return ok }) {
			return false // a GraphQL request carrying a grant is not a token refresh
		}
		if raw, ok := doc["grant_type"]; ok {
			var g string
			if json.Unmarshal(raw, &g) != nil {
				return false
			}
			grants = append(grants, g)
		}
	case ct != "" || req.Body != "":
		return false // multipart, text…: not a form a token endpoint reads
	}
	if len(grants) == 0 {
		return false
	}
	for _, g := range grants {
		if g != "refresh_token" {
			return false
		}
	}
	return true
}

// gqlKeys reports a body that names a GraphQL request (query, operationName,
// variables, extensions): the refresh exception never lets one by.
func gqlKeys(has func(string) bool) bool {
	for _, k := range []string{"query", "operationName", "variables", "extensions", "mutation"} {
		if has(k) {
			return true
		}
	}
	return false
}

// isGraphQL reports a request the guard reads as GraphQL (any operation).
func isGraphQL(method string, req Request) bool {
	gql, _, _ := graphQL(method, req)
	return gql
}

// anchoredRe is the shape -guard-allow must have at login: the origin
// first, host spelled out and escaped, then a path.
var anchoredRe = regexp.MustCompile(`^\^http(?:s\?|s|)://([A-Za-z0-9-]+(?:\\\.[A-Za-z0-9-]+)*)(?::\d+|\(:\\d\+\)\?)?/`)

// AnchoredAllow checks a -guard-allow regexp that is saved with a login:
// it must compile, begin ^https://, ^http:// or ^https?:// and a host of the
// target's scope (escaped, with or without a port) and a /, and not be an
// alternation at its top level (^https://app\.x\.com/a|.* matches
// everything). A rule that is wider is refused, never trimmed.
func AnchoredAllow(re string, inScope func(host string) bool) error {
	if _, err := regexp.Compile(re); err != nil {
		return err
	}
	if t, err := syntax.Parse(re, syntax.Perl); err != nil || t.Op == syntax.OpAlternate {
		return fmt.Errorf("guard-allow %q: a top-level alternation is not anchored", re)
	}
	m := anchoredRe.FindStringSubmatch(re)
	if m == nil {
		return fmt.Errorf("guard-allow %q: must begin ^https?://<host>/ with the host escaped (^https://app\\.example\\.com/api/auth/refresh(\\?|$))", re)
	}
	host := strings.ReplaceAll(m[1], `\.`, ".")
	if inScope == nil || !inScope(host) {
		return fmt.Errorf("guard-allow %q: host %s is not in the target's scope", re, host)
	}
	return nil
}

// WithAllow returns r with extra regexps ORed into Allow, each compiled on
// its own first.
func (r Rules) WithAllow(extra ...string) (Rules, error) {
	parts := []string{}
	if r.Allow != nil {
		parts = append(parts, r.Allow.String())
	}
	for _, e := range extra {
		if _, err := regexp.Compile(e); err != nil {
			return r, err
		}
		parts = append(parts, e)
	}
	switch len(parts) {
	case 0:
		return r, nil
	case 1:
		r.Allow = regexp.MustCompile(parts[0])
		return r, nil
	}
	for i := range parts {
		parts[i] = "(?:" + parts[i] + ")"
	}
	re, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return r, err
	}
	r.Allow = re
	return r, nil
}
