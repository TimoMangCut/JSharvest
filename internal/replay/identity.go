package replay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Identity is what a role's requests carry to say who sends them: its
// cookies, and its credential headers (Authorization, an API key, a CSRF
// header) by lower-case name.
type Identity struct {
	Role  string
	None  bool // no identity at all: a visitor
	Jar   *cookiejar.Jar
	Creds map[string]string
	// Notes say what was left out, and why (a masked value, an expired
	// token).
	Notes []string
}

// credential reports whether a request header says who sends it.
func credential(name string) bool {
	n := strings.ToLower(name)
	if n == "authorization" || n == "proxy-authorization" {
		return true
	}
	return n != "cookie" && !flow.PlainHeader(n) && traffic.Sensitive(n)
}

// NoIdentity is a visitor's: nothing.
func NoIdentity() *Identity {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &Identity{Role: "(none)", None: true, Jar: jar, Creds: map[string]string{}}
}

// NewIdentity makes a role's identity: the cookies of its login snapshot,
// when it has one, else those its newest requests carried; and the
// credential headers its newest requests carried. entries are the role's
// requests, oldest first.
func NewIdentity(role string, snap *session.Snapshot, entries []traffic.Entry, now time.Time) *Identity {
	id := NoIdentity()
	id.Role, id.None = role, false
	fromSnap := snap != nil && len(snap.Cookies) > 0
	if fromSnap {
		for _, c := range snap.Cookies {
			if c.Expires > 0 && time.Unix(int64(c.Expires), 0).Before(now) {
				continue
			}
			// A CDN's cookie is not the login's (round 25L review): the
			// Sender keeps the ones the host sets during the run, per role;
			// an old __cf_bm or cf_clearance of the browser's is not sent.
			if traffic.CDNCookie(c.Name) {
				continue
			}
			if strings.HasPrefix(c.Value, "REDACTED_") {
				id.Notes = append(id.Notes, "cookie "+c.Name+" is masked in the snapshot")
				continue
			}
			host := strings.TrimPrefix(c.Domain, ".")
			scheme := "http"
			if c.Secure {
				scheme = "https"
			}
			u := &url.URL{Scheme: scheme, Host: host, Path: "/"}
			hc := &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Secure: c.Secure, HttpOnly: c.HTTPOnly}
			if strings.HasPrefix(c.Domain, ".") {
				hc.Domain = host
			}
			id.Jar.SetCookies(u, []*http.Cookie{hc})
		}
	}
	seenCookieHost := map[string]bool{}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.HeadersProvisional || strings.HasPrefix(e.Outcome, "held_back") {
			continue
		}
		u, err := url.Parse(e.URL)
		if err != nil {
			continue
		}
		for k, v := range e.Headers {
			n := strings.ToLower(k)
			switch {
			case n == "cookie" && !fromSnap && !seenCookieHost[u.Host]:
				seenCookieHost[u.Host] = true
				var cs []*http.Cookie
				for _, part := range strings.Split(strings.ReplaceAll(v, "\n", "; "), ";") {
					if name, val, ok := strings.Cut(strings.TrimSpace(part), "="); ok && !strings.HasPrefix(val, "REDACTED_") && !traffic.CDNCookie(name) {
						cs = append(cs, &http.Cookie{Name: name, Value: val, Path: "/"})
					}
				}
				id.Jar.SetCookies(&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}, cs)
			case credential(n):
				if _, have := id.Creds[n]; have {
					continue
				}
				switch {
				case strings.Contains(v, "REDACTED_"):
					id.Notes = append(id.Notes, n+" is masked in the log")
				case expiredJWT(v, now):
					id.Notes = append(id.Notes, n+" holds an expired token")
				default:
					id.Creds[n] = v
				}
			}
		}
	}
	return id
}

// expiredJWT reports whether a value holds a JWT whose exp has passed.
func expiredJWT(v string, now time.Time) bool {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "bearer "))
	parts := strings.Split(v, ".")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "eyJ") {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if json.Unmarshal(b, &claims) != nil || claims.Exp == 0 {
		return false
	}
	return time.Unix(int64(claims.Exp), 0).Before(now)
}

// Apply puts an identity on a raw request in place of the one it carries:
// the higher role's cookies and credential headers go, the identity's
// come. keep names headers left as they are, to be refreshed after (a CSRF
// header taken fresh from a source request). missing are the credentials
// the request carried that the identity has no equivalent of: a trial
// without them would be refused for the wrong reason.
func Apply(raw []byte, id *Identity, rawURL string, keep map[string]bool) (out []byte, missing []string) {
	head := bytes.Index(raw, []byte("\r\n\r\n"))
	if head < 0 {
		return raw, nil
	}
	lines := strings.Split(string(raw[:head]), "\r\n")
	kept := []string{lines[0]}
	for _, l := range lines[1:] {
		name, _, _ := strings.Cut(l, ":")
		n := strings.ToLower(strings.TrimSpace(name))
		switch {
		case n == "cookie":
			continue
		case credential(n) && !keep[n]:
			if !id.None {
				if _, ok := id.Creds[n]; !ok {
					missing = append(missing, n)
				}
			}
			continue
		}
		kept = append(kept, l)
	}
	if !id.None {
		names := make([]string, 0, len(id.Creds))
		for n := range id.Creds {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if keep[n] {
				continue
			}
			if had := headerIn(lines[1:], n); had {
				kept = append(kept, canonical(n)+": "+id.Creds[n])
			}
		}
	}
	if u, err := url.Parse(rawURL); err == nil {
		if cs := id.Jar.Cookies(u); len(cs) > 0 {
			parts := make([]string, len(cs))
			for i, c := range cs {
				parts[i] = c.Name + "=" + c.Value
			}
			kept = append(kept, "Cookie: "+strings.Join(parts, "; "))
		}
	}
	out = []byte(strings.Join(kept, "\r\n") + "\r\n\r\n")
	return append(out, raw[head+4:]...), missing
}

func headerIn(lines []string, name string) bool {
	for _, l := range lines {
		if n, _, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(n), name) {
			return true
		}
	}
	return false
}

func canonical(n string) string { return http.CanonicalHeaderKey(n) }
