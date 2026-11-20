package replay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Verdict is what a trial under a lower role's identity says of the
// server's check (docs/gd5-replay-design.md, 4 and 8).
type Verdict string

const (
	Bypass          Verdict = "bypass"          // the lower role got what the higher one gets
	Unauthenticated Verdict = "unauthenticated" // and so does a request with no identity
	Likely          Verdict = "likely"          // nearly the same answer: a few fields differ
	NeedsReview     Verdict = "needs-review"    // a success, but another answer (filtered, its own object, an error body)
	Enforced        Verdict = "enforced"        // refused: 401, 403, the login page, 404 where the control has it
	Unclear         Verdict = "unclear"         // nothing to conclude: the control failed, a CSRF token went stale, 5xx…
	Skipped         Verdict = "skipped"         // not sent: a write, a destructive action, a login flow, out of scope
	Blocked         Verdict = "blocked"         // a WAF answered, not the application: nothing to tell

	// The verdicts of authz -peers (docs/gd7-bola-design.md 4.4 and 8).
	Shared         Verdict = "shared"          // B reads A's private-looking data, but A and B share an org: by design, perhaps
	ReplayBroken   Verdict = "replay_broken"   // A's own request no longer answers as recorded (a nonce, a signature): no word of the server's check
	EnforcedParent Verdict = "enforced-parent" // refused, but only the parent level was tried (two ids in the request): -substitute tries the leaf
)

// Answer is a response, as far as judging it goes.
type Answer struct {
	Status int
	Header map[string]string // lower-case names
	Body   []byte
	Err    string
	// Block is a vendor's block in place of the application's answer
	// (nil: the application answered).
	Block *Block
}

func (a Answer) ok() bool { return a.Err == "" && a.Status >= 200 && a.Status < 300 }

// Case is one trial and what it is judged against.
type Case struct {
	Write    bool
	Trial    Answer
	Controls []Answer // the higher role's answers, sent after the trial: none for a write
	// NoIdentity is the same request with no identity, nil when not sent.
	NoIdentity *Answer
	// Stale says a credential link (a CSRF token) could not be taken fresh;
	// Kept says the trial still carries a credential of the higher role.
	Stale, Kept bool
	IsLogin     func(location string) bool
}

type Judgement struct {
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason"`
}

// Judge concludes one trial.
func Judge(c Case) Judgement {
	t := c.Trial
	if t.Err != "" {
		return Judgement{Unclear, "no answer: " + t.Err}
	}
	if b := blockOf(t); b != nil {
		if b.Kind == BlockRate {
			return Judgement{Unclear, "rate limited: " + b.String()}
		}
		return Judgement{Blocked, "a WAF answered: " + b.String()}
	}
	for _, c := range c.Controls {
		if b := blockOf(c); b != nil {
			return Judgement{Unclear, "a WAF answered the higher role's control: " + b.String()}
		}
	}
	if cached(t) {
		return Judgement{Unclear, "a shared cache answered the trial"}
	}
	var ctl *Answer
	if !c.Write {
		if len(c.Controls) == 0 || !c.Controls[0].ok() {
			s := "not sent"
			if len(c.Controls) > 0 {
				s = describe(c.Controls[0])
			}
			return Judgement{Unclear, "the higher role's control failed: " + s}
		}
		ctl = &c.Controls[0]
		// A control that says it failed in a 200 is no control: the same
		// error in the trial would read as "the same answer".
		if bodyErrors(ctl.Body, nil) == errAll {
			return Judgement{Unclear, "the higher role's control has an error in its body"}
		}
	}
	switch s := t.Status; {
	case s == 401 || s == 403:
		if c.Stale || c.Kept {
			return Judgement{Unclear, fmt.Sprintf("%d, with a CSRF token or credential not taken fresh", s)}
		}
		return Judgement{Enforced, strconv.Itoa(s)}
	case s == 419:
		return Judgement{Unclear, "419: a CSRF token refused"}
	case s >= 300 && s < 400:
		loc := t.Header["location"]
		if c.IsLogin != nil && c.IsLogin(loc) {
			if c.Stale || c.Kept {
				return Judgement{Unclear, "sent to the login page, with a CSRF token or credential not taken fresh"}
			}
			return Judgement{Enforced, "sent to the login page"}
		}
		return Judgement{Unclear, fmt.Sprintf("%d to %s", s, loc)}
	case s == 404 && ctl != nil:
		if c.Stale || c.Kept {
			return Judgement{Unclear, "404, with a CSRF token or credential not taken fresh"}
		}
		return Judgement{Enforced, "404, where the higher role gets it"}
	case s >= 400 && s < 500:
		return Judgement{Unclear, strconv.Itoa(s)}
	case s >= 500:
		return Judgement{Unclear, strconv.Itoa(s)}
	case s < 200:
		return Judgement{Unclear, strconv.Itoa(s)}
	}
	// A success.
	if c.Kept {
		return Judgement{Unclear, "a success, with the higher role's credential still in the request"}
	}
	var ctlBody []byte
	if ctl != nil {
		ctlBody = ctl.Body
	}
	switch bodyErrors(t.Body, ctlBody) {
	case errAll:
		return Judgement{NeedsReview, "a success with an error in its body"}
	case errSome:
		return Judgement{NeedsReview, "a success, some of its batch with an error in the body"}
	}
	if ctl == nil {
		return Judgement{Bypass, fmt.Sprintf("the write was accepted (%d)", t.Status)}
	}
	if kind(t) != kind(*ctl) {
		return Judgement{Unclear, fmt.Sprintf("a %s answer, where the higher role gets %s (a fallback page?)", kind(t), kind(*ctl))}
	}
	same, near, why := compareBodies(t.Body, c.Controls)
	switch {
	case same && c.NoIdentity != nil && c.NoIdentity.ok() && kind(*c.NoIdentity) == kind(*ctl):
		if s, _, _ := compareBodies(c.NoIdentity.Body, c.Controls); s {
			return Judgement{Unauthenticated, "a request with no identity gets the same answer"}
		}
		return Judgement{Bypass, "the same answer as the higher role's"}
	case same:
		return Judgement{Bypass, "the same answer as the higher role's"}
	case near:
		return Judgement{Likely, why}
	}
	return Judgement{NeedsReview, why}
}

func describe(a Answer) string {
	if a.Err != "" {
		return a.Err
	}
	return strconv.Itoa(a.Status)
}

func cached(a Answer) bool {
	for _, h := range []string{"x-cache", "cf-cache-status", "x-cache-status", "x-proxy-cache"} {
		if strings.Contains(strings.ToUpper(a.Header[h]), "HIT") {
			return true
		}
	}
	if age, err := strconv.Atoi(strings.TrimSpace(a.Header["age"])); err == nil && age > 0 {
		return true
	}
	return false
}

// kind is a response's content kind: json, html, text, or other.
func kind(a Answer) string {
	mt, _, _ := mime.ParseMediaType(a.Header["content-type"])
	switch {
	case strings.Contains(mt, "json"):
		return "json"
	case strings.Contains(mt, "html"):
		return "html"
	case strings.HasPrefix(mt, "text/"), mt == "":
		t := bytes.TrimSpace(a.Body)
		if json.Valid(t) && len(t) > 0 && (t[0] == '{' || t[0] == '[') {
			return "json"
		}
		if _, ok := parseFlight(t); ok {
			return "json"
		}
		if bytes.HasPrefix(bytes.ToLower(t), []byte("<!doctype html")) || bytes.HasPrefix(bytes.ToLower(t), []byte("<html")) {
			return "html"
		}
		return "text"
	}
	return "other"
}

// errState is how much of a success's body says it failed.
type errState int

const (
	errNone errState = iota
	errSome          // a batch (root array) where only some items failed
	errAll
)

// numCodeKeys are the keys (lower-case) a number status lives under.
var numCodeKeys = map[string]bool{"code": true, "status": true, "statuscode": true, "errcode": true, "errorcode": true, "error_code": true}

// metaKeys (lower-case) carry a message or metadata, not data.
var metaKeys = map[string]bool{
	"code": true, "status": true, "statuscode": true, "errcode": true, "errorcode": true, "error_code": true,
	"msg": true, "message": true, "error": true, "errors": true, "success": true, "ok": true,
	"timestamp": true, "time": true, "ts": true, "trace_id": true, "traceid": true,
	"request_id": true, "requestid": true, "req_id": true, "reqid": true,
	// Common metadata of an error body (RFC 7807 included). "details" is
	// left out: it may be data.
	"path": true, "detail": true, "reason": true, "title": true, "type": true, "instance": true,
	"error_description": true, "errmsg": true, "err_msg": true, "error_msg": true, "errormessage": true,
	"description": true, "hint": true, "tip": true, "trace": true, "span_id": true, "spanid": true,
	"request": true, "uri": true, "url": true, "method": true, "server_time": true, "servertime": true,
	"date": true, "version": true,
}

type codeClass int

const (
	codeUnknown codeClass = iota
	codeOK
	codeBad
)

// classifyCode sorts a number code: negative, or whose first three digits
// are 400-599 (40301, 50001, 401001), is an error; 0, 200-299 and 2*10^k
// are a success; the rest (1, 1001, 2001...) cannot be told by the number.
func classifyCode(n int64) codeClass {
	switch {
	case n < 0:
		return codeBad
	case n == 0 || (n >= 200 && n <= 299):
		return codeOK
	}
	if n >= 100 {
		d := n
		for d >= 1000 {
			d /= 10
		}
		if d >= 400 && d <= 599 {
			return codeBad
		}
	}
	for p := int64(2000); p > 0 && p <= n; p *= 10 {
		if n == p {
			return codeOK
		}
	}
	return codeUnknown
}

func intOf(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	if i, err := n.Int64(); err == nil {
		return i, true
	}
	if f, err := n.Float64(); err == nil && f == float64(int64(f)) && f > -1e15 && f < 1e15 {
		return int64(f), true
	}
	return 0, false
}

// noData reports a body that carries nothing but a code, a message and
// metadata, or whose data is null or empty.
func noData(m map[string]any) bool {
	for k, v := range m {
		if strings.EqualFold(k, "data") {
			switch x := v.(type) {
			case nil:
				return true
			case string:
				if x == "" {
					return true
				}
			case map[string]any:
				if len(x) == 0 {
					return true
				}
			case []any:
				if len(x) == 0 {
					return true
				}
			}
		}
	}
	for k := range m {
		if !metaKeys[strings.ToLower(k)] {
			return false
		}
	}
	return true
}

// mapError reports whether a JSON object says it failed. ctl is the
// control's counterpart (nil: none, as when judging the control itself):
// a number code that tells nothing by its value is an error when the
// control's differs, or when the body carries no data.
func mapError(m, ctl map[string]any) bool {
	if e, ok := m["error"]; ok && e != nil && e != false && e != "" {
		return true
	}
	if e, ok := m["errors"].([]any); ok && len(e) > 0 {
		return m["data"] == nil
	}
	for _, k := range []string{"success", "ok"} {
		if v, ok := m[k].(bool); ok && !v {
			return true
		}
	}
	if s, ok := m["status"].(string); ok && strings.EqualFold(s, "error") {
		return true
	}
	unknown, hasOK := false, false
	for k, v := range m {
		if !numCodeKeys[strings.ToLower(k)] {
			continue
		}
		if n, ok := intOf(v); ok && classifyCode(n) == codeOK {
			hasOK = true
		}
	}
	for k, v := range m {
		if !numCodeKeys[strings.ToLower(k)] {
			continue
		}
		n, ok := intOf(v)
		if !ok {
			continue
		}
		switch classifyCode(n) {
		case codeBad:
			return true
		case codeUnknown:
			if hasOK {
				continue // another code says success: this one is a status of the data
			}
			unknown = true
			if ctl != nil {
				if cv, ok := ctl[k]; !ok || fmt.Sprint(cv) != fmt.Sprint(v) {
					return true
				}
			}
		}
	}
	return unknown && noData(m)
}

func isFlightHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func looksLikeFlight(b []byte) bool {
	t := bytes.TrimSpace(b)
	if len(t) < 3 || !isFlightHex(t[0]) {
		return false
	}
	colon := bytes.IndexByte(t[:min(len(t), 10)], ':')
	if colon <= 0 || colon > 8 {
		return false
	}
	for i := 0; i < colon; i++ {
		if !isFlightHex(t[i]) {
			return false
		}
	}
	return true
}

// parseFlight decodes a React Server Components / Next.js Server Action Flight
// wire stream ("0:[...]\n1:{...}\n") into a JSON-compatible map keyed by row id.
func parseFlight(b []byte) (map[string]any, bool) {
	if !looksLikeFlight(b) {
		return nil, false
	}
	rows := map[string]any{}
	for _, rawLine := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		ln := bytes.TrimSpace(rawLine)
		if len(ln) == 0 {
			continue
		}
		colon := bytes.IndexByte(ln, ':')
		if colon <= 0 || colon > 8 {
			return nil, false
		}
		for i := 0; i < colon; i++ {
			if !isFlightHex(ln[i]) {
				return nil, false
			}
		}
		id := string(ln[:colon])
		rest := bytes.TrimSpace(ln[colon+1:])
		if len(rest) == 0 {
			continue
		}
		// Strip optional 1-2 uppercase RSC Flight row tag (I[...], E{...}, HL[...], D{...}).
		tagEnd := 0
		for tagEnd < len(rest) && tagEnd < 2 && rest[tagEnd] >= 'A' && rest[tagEnd] <= 'Z' {
			tagEnd++
		}
		if tagEnd > 0 && tagEnd < len(rest) && (rest[tagEnd] == '{' || rest[tagEnd] == '[' || rest[tagEnd] == '"') {
			rest = rest[tagEnd:]
		}
		if rest[0] == '{' || rest[0] == '[' || rest[0] == '"' ||
			bytes.Equal(rest, []byte("null")) || bytes.Equal(rest, []byte("true")) || bytes.Equal(rest, []byte("false")) {
			dec := json.NewDecoder(bytes.NewReader(rest))
			dec.UseNumber()
			var v any
			if dec.Decode(&v) == nil {
				rows[id] = v
			}
		}
	}
	return rows, len(rows) > 0
}

func decodeJSON(b []byte) (any, bool) {
	if rows, ok := parseFlight(b); ok {
		return rows, true
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil, false
	}
	return v, true
}

// bodyErrors reads whether a success's JSON says it failed; a root array
// (a GraphQL batch) is read item by item. ctl is the control's body, nil
// when there is none.
func bodyErrors(b, ctl []byte) errState {
	v, ok := decodeJSON(b)
	if !ok {
		return errNone
	}
	var cv any
	if ctl != nil {
		cv, _ = decodeJSON(ctl)
	}
	switch x := v.(type) {
	case map[string]any:
		c, _ := cv.(map[string]any)
		if mapError(x, c) {
			return errAll
		}
	case []any:
		// The items are not matched with the control's by place: a list
		// has no order, so only the rules that need no control apply.
		bad := 0
		for _, e := range x {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if mapError(m, nil) {
				bad++
			}
		}
		switch {
		case bad == 0:
		case bad == len(x):
			return errAll
		default:
			return errSome
		}
	}
	return errNone
}

// compareBodies compares a body with the controls': same (equal but for
// the fields that differ between two controls), near (the same fields and
// at least 80% of the values, no list shorter), and why when not same.
func compareBodies(b []byte, controls []Answer) (same, near bool, why string) {
	cf, cj := flatten(controls[0].Body)
	tf, tj := flatten(b)
	if !cj || !tj {
		// Not JSON: compare with what varies masked.
		m := maskText(b)
		c0 := maskText(controls[0].Body)
		if len(controls) > 1 && !bytes.Equal(c0, maskText(controls[1].Body)) {
			return false, false, "the higher role's answer itself varies"
		}
		if bytes.Equal(m, c0) {
			return true, true, ""
		}
		return false, false, fmt.Sprintf("another body (%d bytes, the higher role's %d)", len(b), len(controls[0].Body))
	}
	volatile := map[string]bool{}
	for _, other := range controls[1:] {
		of, ok := flatten(other.Body)
		if !ok {
			continue
		}
		for k, v := range cf {
			if ov, ok := of[k]; !ok || ov != v {
				volatile[k] = true
			}
		}
		for k := range of {
			if _, ok := cf[k]; !ok {
				volatile[k] = true
			}
		}
	}
	keys, equal, total := 0, 0, 0
	var missing, extra []string
	for k, v := range cf {
		if volatile[k] {
			continue
		}
		total++
		tv, ok := tf[k]
		if !ok {
			missing = append(missing, k)
			continue
		}
		keys++
		if tv == v {
			equal++
		}
	}
	for k := range tf {
		if _, ok := cf[k]; !ok && !volatile[k] {
			extra = append(extra, k)
		}
	}
	if total == 0 && len(cf) > 0 {
		// A token, a time stamp: an answer each call makes anew says
		// nothing of whose it is.
		return false, false, "every field of the higher role's answer changes between two calls: nothing stable to compare"
	}
	if len(missing) == 0 && len(extra) == 0 && equal == total {
		return true, true, ""
	}
	sort.Strings(missing)
	if shorter(cf, tf) {
		return false, false, "fewer items than the higher role's: a list filtered by role?"
	}
	if len(missing) == 0 && len(extra) == 0 && total > 0 && float64(equal) >= 0.8*float64(total) {
		return false, true, fmt.Sprintf("the same fields, %d of %d values the same", equal, total)
	}
	switch {
	case len(missing) > 0:
		return false, false, fmt.Sprintf("%d fields of the higher role's answer missing (%s)", len(missing), strings.Join(first(missing, 3), ", "))
	case len(extra) > 0:
		return false, false, fmt.Sprintf("%d fields the higher role's answer has not", len(extra))
	}
	return false, false, fmt.Sprintf("the same fields, %d of %d values the same: its own object?", equal, total)
}

func first(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

var indexRe = regexp.MustCompile(`\[\d+\]`)

// shorter reports whether a list of the control has fewer items in b.
func shorter(control, b map[string]string) bool {
	count := func(m map[string]string) map[string]int {
		out := map[string]int{}
		for k := range m {
			for _, loc := range indexRe.FindAllStringIndex(k, -1) {
				list := k[:loc[0]]
				n, _ := strconv.Atoi(k[loc[0]+1 : loc[1]-1])
				out[list] = max(out[list], n+1)
			}
		}
		return out
	}
	c, t := count(control), count(b)
	for list, n := range c {
		if t[list] < n {
			return true
		}
	}
	return false
}

// flatten turns JSON into its leaves by path ($.a[0].b).
func flatten(b []byte) (map[string]string, bool) {
	v, ok := decodeJSON(b)
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	var walk func(any, string, int)
	walk = func(v any, p string, depth int) {
		if depth > 30 || len(out) > 5000 {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				out[p] = "{}"
			}
			for k, y := range x {
				walk(y, p+"."+k, depth+1)
			}
		case []any:
			if len(x) == 0 {
				out[p] = "[]"
			}
			// A list has no order: its items are read by their own
			// signature, so a reordered list is the same list. The index
			// stays, so "fewer items" is still told.
			for i, y := range sortedItems(x) {
				walk(y, p+"["+strconv.Itoa(i)+"]", depth+1)
			}
		default:
			out[p] = fmt.Sprint(x)
		}
	}
	walk(v, "$", 0)
	return out, true
}

// canonSig is a value's signature with every list in it ordered by its
// items' own signatures, so two values equal but for the order of lists
// at any depth have the same one.
func canonSig(v any) string {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for _, k := range keys {
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.WriteString(canonSig(x[k]))
			b.WriteByte(',')
		}
		b.WriteByte('}')
		return b.String()
	case []any:
		sigs := make([]string, len(x))
		for i, y := range x {
			sigs[i] = canonSig(y)
		}
		sort.Strings(sigs)
		return "[" + strings.Join(sigs, ",") + "]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// sortedItems orders a list's items by their canonical JSON.
func sortedItems(x []any) []any {
	if len(x) < 2 {
		return x
	}
	type item struct {
		sig string
		v   any
	}
	items := make([]item, len(x))
	for i, v := range x {
		items[i] = item{canonSig(v), v}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].sig < items[j].sig })
	out := make([]any, len(x))
	for i, it := range items {
		out[i] = it.v
	}
	return out
}

var volatileTextRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ][\d:.]+(Z|[+-]\d{2}:?\d{2})?|\b\d{10,13}\b|(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|(?i)\b[0-9a-f]{16,}\b|\b[A-Za-z0-9+/_-]{24,}={0,2}`)

func maskText(b []byte) []byte { return volatileTextRe.ReplaceAll(b, []byte("~")) }

func head(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
