package httpcrawl

import (
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Cookie is a cookie the target set during the crawl, as the browser would
// keep it: what an escalation to Chrome takes on (round 25L), so that its
// pages see what the crawl's did (a consent, a region, a CSRF cookie).
type Cookie struct {
	Name, Value string
	// Domain is the Domain attribute ("" for a host-only cookie, whose URL
	// is the one that set it); Path its path.
	Domain, Path, URL string
	Secure, HTTPOnly  bool
	SameSite          http.SameSite
	Expires           time.Time // zero: a session cookie
}

// recJar is the crawl's cookie jar that remembers each cookie as it was set,
// with its attributes, which http.CookieJar.Cookies does not give back.
type recJar struct {
	http.CookieJar
	mu  sync.Mutex
	set []setCookie
}

// setCookie is one cookie as set, its scope worked out as a browser does
// (RFC 6265, as net/http/cookiejar): the Domain (none for a host-only
// cookie), the path (no Path, or one not starting with "/": the setting
// URL's directory), when it expires (Max-Age counts from now, the time it
// was set), whether it was a deletion.
type setCookie struct {
	u       *url.URL
	c       http.Cookie
	domain  string // "" for a host-only cookie
	path    string
	expires time.Time
	deleted bool
}

func (j *recJar) SetCookies(u *url.URL, cs []*http.Cookie) {
	j.CookieJar.SetCookies(u, cs)
	now := time.Now()
	host := strings.ToLower(u.Hostname())
	j.mu.Lock()
	defer j.mu.Unlock()
	uc := *u
	for _, c := range cs {
		s := setCookie{u: &uc, c: *c, path: c.Path}
		if d := strings.TrimPrefix(strings.ToLower(c.Domain), "."); d != "" {
			switch {
			case net.ParseIP(host) != nil:
				// An IP address has no subdomains: its own address as the
				// Domain makes a host-only cookie, any other is refused.
				if d != host {
					continue
				}
			case host != d && !strings.HasSuffix(host, "."+d):
				continue // a Domain the host is not under: the jar refuses it
			default:
				s.domain = d
			}
		}
		if s.path == "" || s.path[0] != '/' {
			s.path = defaultPath(u.Path)
		}
		switch {
		case c.MaxAge < 0:
			s.deleted = true
		case c.MaxAge > 0:
			s.expires = now.Add(time.Duration(c.MaxAge) * time.Second)
		case !c.Expires.IsZero():
			s.expires = c.Expires
			s.deleted = !c.Expires.After(now)
		}
		j.set = append(j.set, s)
	}
}

// defaultPath is RFC 6265's default-path of a request path: its directory.
func defaultPath(p string) string {
	if p == "" || p[0] != '/' {
		return "/"
	}
	i := strings.LastIndex(p, "/")
	if i == 0 {
		return "/"
	}
	return p[:i]
}

// cookies are the cookies the jar still holds (not deleted, expired or set
// again since), the application's: in scope, never a CDN's or a bot
// manager's (traffic.CDNCookie), which go with the client that got them.
// A cookie is one per name, Domain (or host, when host-only) and path: a
// domain cookie two of the site's hosts set is one.
func (j *recJar) cookies(inScope func(string) bool) []Cookie {
	j.mu.Lock()
	set := append([]setCookie(nil), j.set...)
	j.mu.Unlock()
	now := time.Now()
	var out []Cookie
	seen := map[string]bool{}
	for i := len(set) - 1; i >= 0; i-- { // the last setting of each wins
		s := set[i]
		c := s.c
		scope := "h:" + strings.ToLower(s.u.Hostname())
		if s.domain != "" {
			scope = "d:" + s.domain
		}
		key := c.Name + "\x00" + scope + "\x00" + s.path
		if seen[key] {
			continue
		}
		seen[key] = true
		if s.deleted || (!s.expires.IsZero() && s.expires.Before(now)) || traffic.CDNCookie(c.Name) || !inScope(s.u.Hostname()) {
			continue
		}
		// Still held: the jar gives it back where it was set (a refusal the
		// jar made that this one did not, a public suffix, leaves it out).
		alive := false
		for _, have := range j.CookieJar.Cookies(&url.URL{Scheme: s.u.Scheme, Host: s.u.Host, Path: s.path}) {
			if have.Name == c.Name && have.Value == c.Value {
				alive = true
				break
			}
		}
		if !alive {
			continue
		}
		k := Cookie{Name: c.Name, Value: c.Value, Path: s.path, Secure: c.Secure, HTTPOnly: c.HttpOnly, SameSite: c.SameSite, Expires: s.expires}
		if s.domain != "" {
			k.Domain = "." + s.domain
		} else {
			k.URL = s.u.Scheme + "://" + s.u.Host + s.path
		}
		out = append(out, k)
	}
	// In the order they were set.
	slices.Reverse(out)
	return out
}
