package replay

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// IDKind is what an identifier looks like (docs/gd7-bola-design.md 3.3).
type IDKind string

const (
	IDNone     IDKind = ""
	IDUUID     IDKind = "uuid"
	IDULID     IDKind = "ulid"
	IDObjectID IDKind = "objectid"
	IDIntSmall IDKind = "int_small" // 1 .. 2^31-1
	IDInt64    IDKind = "int64"     // 2^31 .. 2^63-1 (Snowflake ids too)
	IDRelay    IDKind = "relay"     // base64("Type:inner")
	IDSlug     IDKind = "slug"
)

// ParsedID is an identifier found at a place of a request.
type ParsedID struct {
	At    string // path:3, query:userId, body:$.variables.id (Param.At)
	In    string
	Name  string
	Kind  IDKind
	Value string
	// Relay: the type and inner id of the decoded Global ID, the inner id's
	// kind, and which of the four base64 alphabets wrote it.
	RelayType, RelayInner string
	InnerKind             IDKind
	relayEnc              int
	Start, End            int
}

// IDCtx is what the request says about a place beyond its value.
type IDCtx struct {
	Wildcard bool // the endpoint's template has a placeholder here (or peers' requests vary here)
	Derived  bool // the value came from an earlier response
}

var (
	uuidIDRe     = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ulidRe       = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	objectIDRe   = regexp.MustCompile(`^(?i)[0-9a-f]{24}$`)
	hexLongRe    = regexp.MustCompile(`^(?i)[0-9a-f]{32,}$`)
	jwtValueRe   = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*$`)
	relayTextRe  = regexp.MustCompile(`^([A-Z][A-Za-z0-9_]{1,63}):([A-Za-z0-9_.-]{1,128})$`)
	slugPlainRe  = regexp.MustCompile(`^[a-z0-9]+(?:[-_][a-z0-9]+)*$`)
	slugPrefixRe = regexp.MustCompile(`^[A-Za-z]{2,10}[-_][A-Za-z0-9][A-Za-z0-9_-]{0,60}$`)
	smallIntRe   = regexp.MustCompile(`^[1-9]\d{0,9}$`)
	bigIntRe     = regexp.MustCompile(`^[1-9]\d{9,18}$`)
	isoDateRe    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([T ][\d:.]+(Z|[+-]\d{2}:?\d{2})?)?$`)
	idNameRe     = regexp.MustCompile(`(?i)(^|[_.-])id$|[a-z]Id$|[a-z]ID$|^(uid|uuid|guid|pk)$`)
	idWordRe     = regexp.MustCompile(`(?i)^(account|user|org|organization|project|item|order|doc|document|wallet|voucher|owner|customer|tenant|workspace|team|group|file|folder|ticket|invoice|member|slug|handle|username|key)s?$`)
	slugNameRe   = regexp.MustCompile(`(?i)^(slug|handle|username|key|project|org|workspace)$`)
	timeNameRe   = regexp.MustCompile(`(?i)^(ts|time|timestamp|expires|exp|iat|since|until)$|_at$|At$`)
	headerIDRe   = regexp.MustCompile(`(?i)^x-([a-z]+-)*(org|tenant|workspace|project|account|team|user)(-id)?$|^x-[a-z-]*-id$`)
)

// controlNames are the parameters that steer a request, not name an object.
var controlNames = map[string]bool{
	"page": true, "per_page": true, "perpage": true, "pagesize": true, "page_size": true, "limit": true, "offset": true, "cursor": true,
	"after": true, "before": true, "first": true, "last": true, "sort": true, "order": true, "order_by": true, "orderby": true,
	"dir": true, "q": true, "search": true, "filter": true, "fields": true, "include": true, "expand": true, "format": true,
	"locale": true, "lang": true, "tz": true, "version": true, "v": true,
}

// signatureParams are the parameters that sign an URL, not name who asks
// (a pre-signed URL carries its authority in them).
var signatureParams = map[string]bool{
	"x-amz-signature": true, "x-amz-credential": true, "x-amz-security-token": true, "x-amz-date": true, "x-amz-expires": true,
	"x-amz-signedheaders": true, "x-goog-signature": true, "x-goog-credential": true, "x-goog-date": true, "x-goog-expires": true,
	"x-goog-signedheaders": true, "x-ms-sig": true, "sig": true, "signature": true, "hmac": true, "mac": true, "digest": true,
	"expires": true, "policy": true, "key-pair-id": true, "sv": true, "se": true, "sp": true, "sr": true, "spr": true, "st": true,
	"skoid": true, "sktid": true, "skt": true, "ske": true, "sks": true, "skv": true,
}

// isURLSignatureParam reports whether a name belongs to the signature of a
// pre-signed or capability URL: it stays on the URL when the request is
// sent under another identity or none (the URL is the authority).
func isURLSignatureParam(name string) bool { return signatureParams[strings.ToLower(name)] }

// isSignatureOrNonce is isURLSignatureParam plus the one-time values that
// are no object's id.
func isSignatureOrNonce(name string) bool {
	n := strings.ToLower(name)
	return signatureParams[n] || n == "nonce" || n == "state" || n == "challenge"
}

// lastKey is the leaf name of a parameter or JSON path, without indexes.
func lastKey(name string) string {
	n := name
	if i := strings.LastIndex(n, "."); i >= 0 {
		n = n[i+1:]
	}
	if i := strings.Index(n, "["); i >= 0 {
		n = n[:i]
	}
	return strings.TrimPrefix(n, "$")
}

func isGQLQueryName(name string) bool {
	if name == "$.query" {
		return true
	}
	rest, ok := strings.CutPrefix(name, "$[")
	return ok && strings.HasSuffix(rest, "].query")
}

func isGQLSyntaxName(name string) bool {
	if isGQLQueryName(name) {
		return true
	}
	for _, s := range []string{"operationName", "extensions"} {
		if name == "$."+s || strings.HasPrefix(name, "$."+s+".") {
			return true
		}
		if rest, ok := strings.CutPrefix(name, "$["); ok {
			if i := strings.Index(rest, "]."); i >= 0 && (rest[i+2:] == s || strings.HasPrefix(rest[i+2:], s+".")) {
				return true
			}
		}
	}
	return false
}

// entropy is the Shannon entropy of a string in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	count := map[rune]int{}
	n := 0
	for _, r := range s {
		count[r]++
		n++
	}
	h := 0.0
	for _, c := range count {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

func mixedCase(s string) bool {
	return strings.ToLower(s) != s && strings.ToUpper(s) != s && strings.ContainsAny(s, "0123456789")
}

var relayEncodings = []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}

// DecodeRelay reads a Relay Global ID: base64("Type:inner") with an inner
// id that is an identifier itself. enc says which alphabet and padding wrote
// it (to write a fake one the same way).
func DecodeRelay(v string) (typ, inner string, innerKind IDKind, enc int, ok bool) {
	if len(v) < 8 || len(v) > 172 {
		return
	}
	for i, e := range relayEncodings {
		raw, err := e.DecodeString(v)
		if err != nil || e.EncodeToString(raw) != v {
			continue
		}
		m := relayTextRe.FindStringSubmatch(string(raw))
		if m == nil {
			continue
		}
		k := innerKindOf(m[2])
		if k == IDNone {
			continue
		}
		return m[1], m[2], k, i, true
	}
	return
}

// EncodeRelay writes a Global ID as DecodeRelay's enc read it.
func EncodeRelay(typ, inner string, enc int) string {
	if enc < 0 || enc >= len(relayEncodings) {
		enc = 0
	}
	return relayEncodings[enc].EncodeToString([]byte(typ + ":" + inner))
}

// typedKind is the kind of a value by its form alone: no context.
func typedKind(v string) IDKind {
	switch {
	case uuidIDRe.MatchString(v):
		return IDUUID
	case ulidRe.MatchString(v):
		return IDULID
	case objectIDRe.MatchString(v):
		return IDObjectID
	case smallIntRe.MatchString(v):
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 1 && n <= math.MaxInt32 {
			return IDIntSmall
		}
		fallthrough
	case bigIntRe.MatchString(v):
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > math.MaxInt32 {
			return IDInt64
		}
	}
	return IDNone
}

func innerKindOf(v string) IDKind {
	if k := typedKind(v); k != IDNone {
		return k
	}
	if len(v) >= 3 && len(v) <= 64 && (slugPlainRe.MatchString(v) || slugPrefixRe.MatchString(v)) {
		return IDSlug
	}
	return IDNone
}

func isSelfAlias(v string) bool {
	switch strings.ToLower(v) {
	case "me", "self", "current", "@me", "~", "mine", "own":
		return true
	}
	return false
}

func idLikeName(name string) bool {
	n := lastKey(name)
	return idNameRe.MatchString(n) || idWordRe.MatchString(n)
}

// ClassifyID says whether a parameter of a request names an object, and of
// what kind (docs/gd7-bola-design.md 3.3).
func ClassifyID(p export.Param, ctx IDCtx) ParsedID {
	out := ParsedID{At: p.At(), In: p.In, Name: p.Name, Value: p.Value, Start: p.Start, End: p.End}
	if out.At == "" {
		return out // a cookie, a multipart field: no place to put another value
	}
	v := p.Value
	switch p.In {
	case "path", "query", "form", "json":
	case "header":
		if credential(p.Name) || !headerIDRe.MatchString(p.Name) {
			return out
		}
	default:
		return out
	}
	if v == "" || len(v) > 200 || isSelfAlias(v) || v == "null" || v == "true" || v == "false" {
		return out
	}
	name := lastKey(p.Name)
	if p.In == "json" && isGQLSyntaxName(p.Name) {
		return out
	}
	if p.In != "path" {
		if isSignatureOrNonce(name) || traffic.Sensitive(name) {
			return out
		}
	}
	if jwtValueRe.MatchString(v) || hexLongRe.MatchString(v) {
		return out
	}
	typed := typedKind(v)
	if typ, inner, ik, enc, ok := DecodeRelay(v); ok {
		out.Kind, out.RelayType, out.RelayInner, out.InnerKind, out.relayEnc = IDRelay, typ, inner, ik, enc
		return out
	}
	if p.In != "path" && controlNames[strings.ToLower(name)] && typed != IDUUID && typed != IDULID {
		return out
	}
	if isoDateRe.MatchString(v) || strings.Contains(v, ".") && floatLike(v) {
		return out
	}
	if timeNameRe.MatchString(name) && (len(v) == 10 || len(v) == 13) && typed != IDNone {
		return out
	}
	// A long random string is a token, not an id (the ones above with a form
	// of their own are checked first).
	if typed != IDUUID && typed != IDULID && typed != IDObjectID && len(v) >= 24 && entropy(v) >= 4.0 && mixedCase(v) {
		return out
	}
	switch typed {
	case IDUUID, IDULID, IDObjectID, IDInt64:
		out.Kind = typed
		return out
	case IDIntSmall:
		if p.In != "path" && !ctx.Derived && len(v) < 4 && !idLikeName(p.Name) {
			return out // a small number in a query: a flag, a count
		}
		out.Kind = IDIntSmall
		return out
	}
	// A slug: only where the place or the name says it names an object.
	slugOK := (len(v) >= 3 && len(v) <= 64) && (slugPlainRe.MatchString(v) || slugPrefixRe.MatchString(v))
	if !slugOK {
		return out
	}
	switch {
	case p.In == "path" && (ctx.Wildcard || ctx.Derived):
	case p.In != "path" && (slugNameRe.MatchString(name) || idLikeName(p.Name) || ctx.Derived):
	default:
		return out
	}
	out.Kind = IDSlug
	return out
}

func floatLike(v string) bool {
	_, err := strconv.ParseFloat(v, 64)
	return err == nil
}

// SeenSet is what a person's (or no one's) responses already show: every
// scalar of their JSON, the segments of the URLs in them, the values of
// HTML attributes and of the headers an application sets. A value in it is
// no secret of another person's.
type SeenSet struct {
	vals map[string]struct{}
	kv   map[string]struct{} // lastKey "=" value, for the short values
}

func NewSeenSet() *SeenSet {
	return &SeenSet{vals: map[string]struct{}{}, kv: map[string]struct{}{}}
}

func normSeen(v string) string { return strings.TrimRight(v, "=") }

// Add notes one value.
func (s *SeenSet) Add(v string) {
	if v == "" {
		return
	}
	s.vals[v] = struct{}{}
	s.vals[normSeen(v)] = struct{}{}
}

// Has reports whether a value is shown somewhere; for a Relay id, whether
// its decoded form or its inner id is.
func (s *SeenSet) Has(v string) bool {
	if s == nil {
		return false
	}
	if _, ok := s.vals[v]; ok {
		return true
	}
	if _, ok := s.vals[normSeen(v)]; ok {
		return true
	}
	if typ, inner, ik, _, ok := DecodeRelay(v); ok {
		if _, ok := s.vals[typ+":"+inner]; ok {
			return true
		}
		// A bare inner id is the object's only where it is unique in the
		// world: a small number is anybody's count.
		if globalKind(ik) {
			if _, ok := s.vals[inner]; ok {
				return true
			}
		}
	}
	return false
}

// globalKind: ids unique across types (UUID, ULID, ObjectId, a long int).
func globalKind(k IDKind) bool {
	return k == IDUUID || k == IDULID || k == IDObjectID || k == IDInt64
}

// HasKV reports whether a value is shown under a leaf of that name: the
// test for a short value (a 7 is anywhere).
func (s *SeenSet) HasKV(key, v string) bool {
	if s == nil {
		return false
	}
	_, ok := s.kv[strings.ToLower(key)+"="+v]
	return ok
}

const (
	seenMaxLeaves = 50000
	seenMaxDepth  = 30
)

var htmlAttrRe = regexp.MustCompile(`(?i)\b(?:content|value|href|src|action|data-[a-z0-9-]+)\s*=\s*["']([^"']{1,300})["']`)

// AddResponse notes what a response shows. Responses that are no
// application's word (>= 500, a guard's fake, a challenge) are the
// caller's to leave out.
func (s *SeenSet) AddResponse(hdr map[string]string, body string) {
	ct := ""
	for k, v := range hdr {
		l := strings.ToLower(k)
		if l == "content-type" {
			ct = v
		}
		if !flow.PlainHeader(l) && l != "set-cookie" && !credential(l) {
			s.Add(strings.TrimSpace(v))
		}
	}
	t := strings.TrimSpace(body)
	if t == "" {
		return
	}
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		if v, ok := decodeJSON([]byte(t)); ok {
			n := 0
			s.walk(v, "", 0, &n)
			return
		}
	}
	if strings.Contains(strings.ToLower(ct), "html") || strings.HasPrefix(t, "<") {
		for _, m := range htmlAttrRe.FindAllStringSubmatch(body, 2000) {
			s.addString(m[1])
		}
		return
	}
	// Text, CSV: each line is a value that is shown.
	for i, l := range strings.Split(body, "\n") {
		if i > seenMaxLeaves {
			break
		}
		if l = strings.TrimSpace(l); l != "" && len(l) <= 2000 {
			s.Add(l)
		}
	}
}

func (s *SeenSet) addString(v string) {
	s.Add(v)
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		if u, err := url.Parse(v); err == nil {
			for _, seg := range strings.Split(u.Path, "/") {
				if seg != "" {
					if d, err := url.PathUnescape(seg); err == nil {
						s.Add(d)
					}
				}
			}
			for k, vs := range u.Query() {
				for _, x := range vs {
					s.Add(x)
					s.kv[strings.ToLower(k)+"="+x] = struct{}{}
				}
			}
		}
	}
	if typ, inner, ik, _, ok := DecodeRelay(v); ok {
		s.Add(typ + ":" + inner)
		if globalKind(ik) {
			s.Add(inner)
		}
	}
}

func (s *SeenSet) walk(v any, key string, depth int, n *int) {
	if depth > seenMaxDepth || *n > seenMaxLeaves {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			s.walk(y, k, depth+1, n)
		}
	case []any:
		for _, y := range x {
			s.walk(y, key, depth+1, n)
		}
	case nil:
	case string:
		*n++
		s.addString(x)
		s.kv[strings.ToLower(key)+"="+x] = struct{}{}
	case json.Number:
		*n++
		s.Add(x.String())
		s.kv[strings.ToLower(key)+"="+x.String()] = struct{}{}
	default:
		*n++
		str := strings.TrimSpace(jsonScalar(x))
		s.Add(str)
		s.kv[strings.ToLower(key)+"="+str] = struct{}{}
	}
}

func jsonScalar(v any) string {
	b, _ := json.Marshal(v)
	return strings.Trim(string(b), `"`)
}

// canonEndpointKey is an export key with every {placeholder} named {}, the
// trailing slash taken off: the same endpoint under two people's names for
// it.
func canonEndpointKey(key string) string {
	method, rest, _ := strings.Cut(key, " ")
	hostPath, op, hasOp := strings.Cut(rest, " ")
	hostPath = placeholderAnyRe.ReplaceAllString(hostPath, "{}")
	if len(hostPath) > 1 {
		if i := strings.Index(hostPath, "/"); i >= 0 && strings.HasSuffix(hostPath, "/") && i < len(hostPath)-1 {
			hostPath = strings.TrimRight(hostPath, "/")
		}
	}
	out := method + " " + hostPath
	if hasOp {
		out += " " + op
	}
	return out
}

var placeholderAnyRe = regexp.MustCompile(`\{[^}]*\}`)

// pathSegments are the escaped segments of a URL's path, as flow numbers
// them (path:1 is the first).
func pathSegments(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	p := strings.Trim(u.EscapedPath(), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

var versionSegRe = regexp.MustCompile(`^[vV]\d+(\.\d+)*$`)

// idish reports a path segment that is an object's id by its form: it has
// a digit, and is a typed id (number, UUID, ULID, ObjectID), a Relay id, a
// slug with a digit (p-77, doc-a1) or a long hex/base64 string. A word of
// letters, dashes and underscores alone (private-notes, org-alpha) never is.
func idish(seg string) bool {
	if !strings.ContainsAny(seg, "0123456789") || versionSegRe.MatchString(seg) {
		return false
	}
	if typedKind(seg) != IDNone || slugPlainRe.MatchString(seg) || slugPrefixRe.MatchString(seg) {
		return true
	}
	if _, _, _, _, ok := DecodeRelay(seg); ok {
		return true
	}
	return len(seg) >= 16 && regexp.MustCompile(`^[A-Za-z0-9+/_=-]+$`).MatchString(seg)
}

// alignWildcards finds the path places where the requests of the models
// differ from each other while the rest is the same endpoint (one or two
// places, each looking like an id): such a place is a placeholder though the
// template of a person who met one value there does not say so. It returns,
// for each request, the 1-based path positions to take as placeholders.
func alignWildcards(models ...*export.Model) map[*export.Request]map[int]bool {
	type sig struct {
		method, host, op string
		n                int
	}
	groups := map[sig][][]*export.Request{}
	segs := map[*export.Request][]string{}
	for mi, m := range models {
		for _, r := range m.Requests {
			if r.Entry.Hop > 0 {
				continue
			}
			u, err := url.Parse(r.Entry.URL)
			if err != nil {
				continue
			}
			s := pathSegments(r.Entry.URL)
			segs[r] = s
			k := sig{r.Entry.Method, u.Host, r.Op, len(s)}
			if groups[k] == nil {
				groups[k] = make([][]*export.Request, len(models))
			}
			groups[k][mi] = append(groups[k][mi], r)
		}
	}
	out := map[*export.Request]map[int]bool{}
	mark := func(r *export.Request, i int) {
		if out[r] == nil {
			out[r] = map[int]bool{}
		}
		out[r][i+1] = true
	}
	for _, per := range groups {
		// At most 300 to a bucket, taken from each model in turn: one
		// person's many requests do not push the other's out.
		var g []*export.Request
		for n := 0; len(g) < 300; n++ {
			more := false
			for _, l := range per {
				if n < len(l) && len(g) < 300 {
					g = append(g, l[n])
					more = true
				}
			}
			if !more {
				break
			}
		}
		for i := 0; i < len(g); i++ {
			for j := i + 1; j < len(g); j++ {
				a, b := segs[g[i]], segs[g[j]]
				var diff []int
				for k := range a {
					if a[k] != b[k] {
						diff = append(diff, k)
					}
				}
				if len(diff) == 0 || len(diff) > 2 {
					continue
				}
				// Only a place where both are ids is a placeholder: a word that
				// differs (private-notes, org-alpha) names another endpoint,
				// and keeps the keys apart.
				for _, k := range diff {
					if idish(a[k]) && idish(b[k]) {
						mark(g[i], k)
						mark(g[j], k)
					}
				}
			}
		}
	}
	return out
}

// wildcardsOf are a request's placeholder positions: its template's, the
// ones its values came from earlier responses at, and the aligned ones.
func wildcardsOf(r *export.Request, aligned map[*export.Request]map[int]bool) (wild, derived map[int]bool) {
	wild, derived = map[int]bool{}, map[int]bool{}
	for i, seg := range strings.Split(strings.Trim(r.Template, "/"), "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			wild[i+1] = true
		}
	}
	for at := range r.Derived {
		if rest, ok := strings.CutPrefix(at, "path:"); ok {
			if n, err := strconv.Atoi(rest); err == nil {
				derived[n] = true
			}
		}
	}
	for i := range aligned[r] {
		wild[i] = true
	}
	return wild, derived
}

// requestIDs lists the identifiers of a request: its parameters that name
// an object.
func requestIDs(r *export.Request, aligned map[*export.Request]map[int]bool) []ParsedID {
	wild, derived := wildcardsOf(r, aligned)
	var out []ParsedID
	for _, p := range r.Params() {
		ctx := IDCtx{}
		if p.In == "path" {
			ctx.Wildcard, ctx.Derived = wild[p.Index], derived[p.Index]
		} else {
			_, ctx.Derived = r.Derived[p.At()]
		}
		if id := ClassifyID(p, ctx); id.Kind != IDNone {
			out = append(out, id)
		}
	}
	return out
}

// reportKey is a request's endpoint key as authz -peers reports it: the
// method, the host, the path with a {} where an id is (its template's
// placeholders, the aligned ones and the ids found), the operation.
func reportKey(r *export.Request, ids []ParsedID, aligned map[*export.Request]map[int]bool) string {
	u, err := url.Parse(r.Entry.URL)
	if err != nil {
		return canonEndpointKey(r.Key)
	}
	segs := pathSegments(r.Entry.URL)
	wild, derived := wildcardsOf(r, aligned)
	for _, id := range ids {
		if id.In == "path" {
			if rest, ok := strings.CutPrefix(id.At, "path:"); ok {
				if n, err := strconv.Atoi(rest); err == nil {
					wild[n] = true
				}
			}
		}
	}
	for i := range derived {
		wild[i] = true
	}
	for i := range segs {
		if wild[i+1] {
			segs[i] = "{}"
		}
	}
	out := r.Entry.Method + " " + u.Host + "/" + strings.Join(segs, "/")
	if r.Op != "" {
		out += " " + r.Op
	}
	return out
}
