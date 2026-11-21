package traffic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/TimoMangCut/JSharvest/internal/secretsig"
)

// Redactor replaces credentials with REDACTED_<8 hex>, an HMAC of the value
// under a key made for this run: equal values still match within the run's
// files, and a weak password cannot be found again from a dictionary, as
// it could from a plain hash.
//
// It works on text with patterns rather than by parsing, so that order is
// kept and a truncated body is still covered. It errs towards hiding.
type Redactor struct{ key []byte }

func NewRedactor() *Redactor {
	key := make([]byte, 32)
	rand.Read(key)
	return &Redactor{key: key}
}

// Value hashes one sensitive value into REDACTED_<8 hex>.
func (r *Redactor) Value(v string) string {
	return r.mask(v)
}

func (r *Redactor) mask(v string) string {
	if strings.HasPrefix(v, "REDACTED_") {
		return v
	}
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(v))
	return "REDACTED_" + hex.EncodeToString(m.Sum(nil))[:8]
}

var (
	// sensitiveWords hide a name when one of its words is among them:
	// X-CSRF-Token, accessToken, session_id.
	sensitiveWords = set("auth", "password", "passwd", "pwd", "pass", "passphrase", "secret", "token", "session", "sessid",
		"cookie", "csrf", "xsrf", "jwt", "credential", "credentials", "signature", "apikey", "authorization", "bearer",
		"otp", "totp", "mfa", "cvv", "ssn", "sid")
	// sensitiveParts hide a name that contains them anywhere: refreshtoken,
	// clientsecret, newpass, oauth_verifier.
	sensitiveParts = []string{"token", "secret", "passw", "passcode", "newpass", "oldpass", "pwd", "apikey", "sessionid", "sessid",
		"csrf", "xsrf", "authcode", "verifier", "privatekey", "accesskey", "secretkey", "saml", "ticket"}
	// sensitiveNames hide a name only when it is the whole name: "code" is
	// an OAuth code, "country_code" is not.
	sensitiveNames = set("key", "code", "pin", "sig")
	// keyWords hide a name that ends in them: private_key, x-access-key,
	// api_keys, but not monkey or keys_count.
	keyWords = set("key", "keys")
	// codeQualifiers hide a name ending in code(s) after one of them:
	// verification_code, recovery_codes, but not country_code.
	codeQualifiers = set("verification", "verify", "auth", "otp", "mfa", "recovery", "reset", "confirm", "confirmation",
		"sms", "login", "backup", "security", "invite", "activation", "access")
)

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// Sensitive reports whether a header, parameter, field or cookie name
// probably holds a credential.
func Sensitive(name string) bool {
	lower := strings.ToLower(name)
	if sensitiveNames[lower] {
		return true
	}
	joined := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, name)
	for _, p := range sensitiveParts {
		if strings.Contains(joined, p) {
			return true
		}
	}
	ws := words(name)
	for _, w := range ws {
		if sensitiveWords[w] {
			return true
		}
	}
	if n := len(ws); n >= 2 {
		if keyWords[ws[n-1]] {
			return true
		}
		if (ws[n-1] == "code" || ws[n-1] == "codes") && codeQualifiers[ws[n-2]] {
			return true
		}
	}
	return false
}

// words splits a name at separators and camelCase boundaries, lower-cased.
func words(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, c := range rs {
		switch {
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			flush()
		case unicode.IsUpper(c) && i > 0 && unicode.IsLower(rs[i-1]):
			flush()
			cur = append(cur, c)
		default:
			cur = append(cur, c)
		}
	}
	flush()
	return out
}

var (
	jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	// "name": value, in JSON: a string, a number, a literal, or an array
	// of those.
	jsonPairRe = regexp.MustCompile(`"((?:[^"\\]|\\.){1,100})"(\s*:\s*)("(?:[^"\\]|\\.)*"?|-?[0-9][0-9.eE+-]*|true|false|null|\[[^\[\]{}]*\]?)`)
	// name: "value" or name = 'value' in JavaScript, GraphQL arguments,
	// single-quoted or unquoted keys, and JSON escaped inside a string
	// (\"password\":\"x\").
	codePairRe = regexp.MustCompile(`([A-Za-z_$][\w$.-]{0,100})(\\?['"]?\s*[:=]\s*)(\\"(?:[^"\\]|\\[^"])*\\"|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')`)
	// name=value, in a query, a form body, XML/HTML text or a URL inside other text.
	formPairRe = regexp.MustCompile(`(^|[?&;\s"'(>])([^=&?;\s"'()<>]{1,100})=([^&\s;#"'<>]*)`)
	// A multipart part: its name, then its value after a blank line.
	multipartRe = regexp.MustCompile(`(name="([^"]{1,100})"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)((?s:.*?))(\r?\n--|$)`)
	// An HTML input with a name and a value, in either order.
	inputRe = regexp.MustCompile(`(?i)<input\b[^>]*>`)
	attrRe  = regexp.MustCompile(`(?i)\b(name|value)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
)

// Text hides the credentials in free text: vendor API keys/tokens, JWTs,
// and the values of sensitive JSON fields, form or query pairs, multipart
// parts and inputs.
func (r *Redactor) Text(s string) string {
	s = secretsig.ReplaceAllFunc(s, r.mask)
	s = jwtRe.ReplaceAllStringFunc(s, r.mask)
	s = replaceSub(jsonPairRe, s, func(m []string) string {
		if !Sensitive(m[1]) {
			return m[0]
		}
		v := m[3]
		switch {
		case strings.HasPrefix(v, `"`):
			v = strings.TrimSuffix(strings.TrimPrefix(v, `"`), `"`)
		case strings.EqualFold(m[1], "code") && !strings.HasPrefix(v, "["):
			return m[0] // {"code": 200} is a status, not an OAuth code
		}
		return `"` + m[1] + `"` + m[2] + `"` + r.mask(v) + `"`
	})
	s = r.codePairs(s, 3)
	s = replaceSub(formPairRe, s, func(m []string) string {
		name, _ := url.QueryUnescape(m[2])
		if !Sensitive(name) || m[3] == "" {
			return m[0]
		}
		return m[1] + m[2] + "=" + r.mask(m[3])
	})
	s = replaceSub(multipartRe, s, func(m []string) string {
		if !Sensitive(m[2]) {
			return m[0]
		}
		return m[1] + r.mask(m[3]) + m[4]
	})
	s = inputRe.ReplaceAllStringFunc(s, func(tag string) string {
		var name string
		for _, a := range attrRe.FindAllStringSubmatch(tag, -1) {
			if strings.EqualFold(a[1], "name") {
				name = strings.Trim(a[2], `"'`)
			}
		}
		if !Sensitive(name) {
			return tag
		}
		return attrRe.ReplaceAllStringFunc(tag, func(a string) string {
			p := attrRe.FindStringSubmatch(a)
			if !strings.EqualFold(p[1], "value") {
				return a
			}
			return p[1] + `="` + r.mask(strings.Trim(p[2], `"'`)) + `"`
		})
	})
	return s
}

// codePairs hides the sensitive name: "value" pairs of code and escaped
// JSON. A pair that is not sensitive may hold more inside its string (JSON
// in a JSON string, a GraphQL query), so its value is searched too, to
// depth levels.
func (r *Redactor) codePairs(s string, depth int) string {
	return replaceSub(codePairRe, s, func(m []string) string {
		v := m[3]
		q := v[:1]
		if strings.HasPrefix(v, `\"`) {
			q = `\"`
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(v, q), q)
		if Sensitive(m[1]) {
			return m[1] + m[2] + q + r.mask(inner) + q
		}
		if depth > 0 && strings.Contains(inner, `\`) {
			return m[1] + m[2] + q + r.codePairs(inner, depth-1) + q
		}
		return m[0]
	})
}

func replaceSub(re *regexp.Regexp, s string, f func([]string) string) string {
	return re.ReplaceAllStringFunc(s, func(m string) string { return f(re.FindStringSubmatch(m)) })
}

// URL hides passwords or tokens in raw authority userinfo and credentials in
// the query or path, both on standalone URLs and on embedded URLs inside text.
func (r *Redactor) URL(raw string) string {
	return r.Text(r.redactRawUserinfo(raw))
}

func (r *Redactor) redactRawUserinfo(raw string) string {
	var b strings.Builder
	wrote := false
	pos := 0
	for pos < len(raw) {
		rel := strings.Index(raw[pos:], "://")
		if rel < 0 {
			break
		}
		schemeEnd := pos + rel
		schemeStart := schemeEnd
		for schemeStart > pos && isSchemeByte(raw[schemeStart-1]) {
			schemeStart--
		}
		if schemeStart == schemeEnd {
			pos = schemeEnd + 3
			continue
		}
		authStart := schemeEnd + 3
		authEnd := authStart
		for authEnd < len(raw) {
			c := raw[authEnd]
			if c == '/' || c == '?' || c == '#' || c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
				c == '"' || c == '\'' || c == ')' || c == '>' || c == ']' || c == '\\' {
				break
			}
			authEnd++
		}
		auth := raw[authStart:authEnd]
		at := strings.LastIndexByte(auth, '@')
		if at > 0 {
			userinfo := auth[:at]
			var repl string
			if rawUser, rawPass, hasColon := strings.Cut(userinfo, ":"); hasColon {
				decPass := rawPass
				if d, err := url.PathUnescape(rawPass); err == nil {
					decPass = d
				}
				maskedUser := rawUser
				decUser := rawUser
				if d, err := url.PathUnescape(rawUser); err == nil {
					decUser = d
				}
				if Sensitive(rawUser) || Sensitive(decUser) || looksLikeLogToken(rawUser) || looksLikeLogToken(decUser) {
					maskedUser = r.mask(decUser)
				}
				repl = maskedUser + ":" + r.mask(decPass)
			} else {
				decUser := userinfo
				if d, err := url.PathUnescape(userinfo); err == nil {
					decUser = d
				}
				repl = r.mask(decUser)
			}
			if !wrote {
				b.Grow(len(raw) + 16)
				wrote = true
			}
			b.WriteString(raw[pos:authStart])
			b.WriteString(repl)
			b.WriteByte('@')
			b.WriteString(auth[at+1:])
			pos = authEnd
			continue
		}
		pos = authEnd
	}
	if !wrote {
		return raw
	}
	b.WriteString(raw[pos:])
	return b.String()
}

func isSchemeByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
}

var logQueryRedactor = NewRedactor()

// LogURL scrubs a URL before it is written to a log line: userinfo and
// fragments are removed, and sensitive or token-shaped query values are
// replaced with "…" without reordering or re-encoding the rest of the query.
func LogURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "(unparsable)"
	}
	if u.Host == "" && u.Path == "" {
		switch strings.ToLower(u.Scheme) {
		case "about":
			if u.Opaque == "" {
				return "(unparsable)"
			}
			return u.Scheme + ":" + u.Opaque
		case "blob":
			if u.Opaque == "" {
				return "(unparsable)"
			}
			inner := u.Opaque
			if u.RawQuery != "" {
				inner += "?" + u.RawQuery
			}
			return u.Scheme + ":" + LogURL(inner)
		case "data":
			meta, _, ok := strings.Cut(u.Opaque, ",")
			if !ok {
				return u.Scheme + ":…"
			}
			return u.Scheme + ":" + meta + ",…"
		case "javascript", "mailto":
			return u.Scheme + ":…"
		default:
			return "(unparsable)"
		}
	}
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""
	if u.RawQuery != "" {
		u.RawQuery = maskLogQuery(u.RawQuery)
	}
	u.ForceQuery = false
	return u.String()
}

// LogURLs applies LogURL to a slice of URLs, returning a fresh slice.
func LogURLs(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = LogURL(s)
	}
	return out
}

// LogBundleLabels scrubs bundle labels (either script URLs or 12-hex SHA-256
// prefixes for anonymous scripts) before logging.
func LogBundleLabels(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	out := make([]string, len(labels))
	for i, s := range labels {
		if isHexLabel(s) {
			out[i] = s
		} else {
			out[i] = LogURL(s)
		}
	}
	return out
}

func isHexLabel(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func maskLogQuery(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		sep := strings.IndexAny(raw[i:], "&;")
		var seg string
		var delim byte
		if sep < 0 {
			seg = raw[i:]
			i = len(raw)
		} else {
			seg = raw[i : i+sep]
			delim = raw[i+sep]
			i += sep + 1
		}
		b.WriteString(maskLogQuerySeg(seg))
		if delim != 0 {
			b.WriteByte(delim)
		}
	}
	return b.String()
}

func maskLogQuerySeg(seg string) string {
	if seg == "" {
		return ""
	}
	rawK, rawV, hasEq := strings.Cut(seg, "=")
	if !hasEq {
		dec, err := url.QueryUnescape(rawK)
		if err != nil || looksLikeLogToken(dec) || looksLikeLogToken(rawK) {
			return "…"
		}
		return seg
	}
	if rawV == "" {
		return seg
	}
	k, kErr := url.QueryUnescape(rawK)
	v, vErr := url.QueryUnescape(rawV)
	if kErr != nil {
		return "…"
	}
	if vErr != nil || Sensitive(k) || Sensitive(rawK) || looksLikeLogToken(v) || looksLikeLogToken(rawV) {
		return rawK + "=…"
	}
	if logQueryRedactor.URL(v) != v || logQueryRedactor.URL(rawV) != rawV {
		return rawK + "=…"
	}
	return seg
}

func looksLikeLogToken(v string) bool {
	if v == "" {
		return false
	}
	if jwtRe.MatchString(v) || len(secretsig.FindAll(v)) > 0 {
		return true
	}
	trimmed := strings.TrimRight(v, "=")
	pad := len(v) - len(trimmed)
	if len(trimmed) < 24 || pad > 2 || (pad == 0 && strings.HasPrefix(trimmed, "/")) {
		return false
	}
	allHex := pad == 0
	allB64URL := pad == 0
	allB64Std := true
	var hasDigit, hasUpper, hasLower, hasSlash bool
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'f':
			hasLower = true
		case c >= 'A' && c <= 'F':
			hasUpper = true
		case c >= 'g' && c <= 'z':
			allHex = false
			hasLower = true
		case c >= 'G' && c <= 'Z':
			allHex = false
			hasUpper = true
		case c == '-' || c == '_':
			allHex = false
			allB64Std = false
		case c == '+':
			allHex = false
			allB64URL = false
		case c == '/':
			allHex = false
			allB64URL = false
			hasSlash = true
		default:
			return false
		}
	}
	if allHex {
		return true
	}
	if allB64URL && hasDigit && (hasUpper || hasLower) {
		return true
	}
	if allB64Std && (!hasSlash || (hasUpper && hasLower && hasDigit)) && hasDigit && (hasUpper || hasLower) {
		return true
	}
	return false
}

// Headers returns a copy of h with credentials hidden. Cookie names are
// kept, so that a fuzzer still knows which cookies a request needs.
func (r *Redactor) Headers(h map[string]string) map[string]string {
	if h == nil {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		name := strings.ToLower(k)
		switch {
		case name == "cookie":
			out[k] = r.cookies(v)
		case name == "set-cookie":
			lines := strings.Split(v, "\n")
			for i, l := range lines {
				first, rest, _ := strings.Cut(l, ";")
				lines[i] = r.cookies(first) + cut(";", rest)
			}
			out[k] = strings.Join(lines, "\n")
		case name == "authorization" || name == "proxy-authorization":
			if scheme, cred, ok := strings.Cut(v, " "); ok {
				out[k] = scheme + " " + r.mask(cred)
			} else {
				out[k] = r.mask(v)
			}
		case strings.HasPrefix(name, "access-control-"):
			out[k] = v
		case Sensitive(strings.TrimPrefix(name, ":")):
			out[k] = r.mask(v)
		default:
			out[k] = r.Text(v)
		}
	}
	return out
}

func cut(sep, rest string) string {
	if rest == "" {
		return ""
	}
	return sep + rest
}

// cookies hides every cookie value of "a=1; b=2", keeping the names.
func (r *Redactor) cookies(v string) string {
	parts := strings.Split(v, ";")
	for i, p := range parts {
		name, val, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || val == "" {
			parts[i] = strings.TrimSpace(p)
			continue
		}
		parts[i] = name + "=" + r.mask(val)
	}
	return strings.Join(parts, "; ")
}

// Body hides credentials in a body. A base64 body is not all text, but its
// text parts can still hold credentials (a multipart form with a file, a
// Latin-1 form), so it is searched as bytes too.
func (r *Redactor) Body(b Body) Body {
	switch {
	case b.Body == "":
	case b.BodyBase64:
		raw, err := base64.StdEncoding.DecodeString(b.Body)
		if err != nil {
			return b
		}
		if out := r.Text(string(raw)); out != string(raw) {
			b.Body = base64.StdEncoding.EncodeToString([]byte(out))
		}
	default:
		b.Body = r.Text(b.Body)
	}
	return b
}

// Entry hides the credentials of one log line in place.
func (r *Redactor) Entry(e *Entry) {
	e.URL = r.URL(e.URL)
	e.Page = r.URL(e.Page)
	e.TargetURL = r.URL(e.TargetURL)
	e.Headers = r.Headers(e.Headers)
	e.Body = r.Body(e.Body)
	if e.Response != nil {
		resp := *e.Response
		resp.Headers = r.Headers(resp.Headers)
		resp.Body = r.Body(resp.Body)
		e.Response = &resp
	}
	if e.Initiator != nil {
		in := *e.Initiator
		in.URL = r.URL(in.URL)
		in.Stack = append([]Frame(nil), in.Stack...)
		for i := range in.Stack {
			in.Stack[i].URL = r.URL(in.Stack[i].URL)
		}
		e.Initiator = &in
	}
}
