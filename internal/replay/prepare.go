package replay

import (
	"bytes"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
	"github.com/TimoMangCut/JSharvest/internal/uahints"
	"golang.org/x/net/publicsuffix"
)

// hopByHop are the headers of one HTTP/1.1 connection: a raw request
// recorded or written as HTTP/1.1 may carry them, HTTP/2 refuses them.
var hopByHop = []string{"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"}

// prepare is the raw request as it goes on the wire (round 25K), and as
// sent.jsonl logs it: no hop-by-hop header; the run's browser
// User-Agent when it says none; the client hints a Chrome with that
// User-Agent sends a secure origin, when it has none; the CDN cookies
// the host set for this role (never for the Sender's own role "", the
// control requests), the fresher where the request carries an older one.
func (s *Sender) prepare(raw []byte, scheme, host, uri, role string) []byte {
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return raw
	}
	lines := strings.Split(string(head), "\r\n")
	get := func(name string) (int, string) {
		for i, l := range lines[1:] {
			n, v, _ := strings.Cut(l, ":")
			if strings.EqualFold(strings.TrimSpace(n), name) {
				return i + 1, strings.TrimSpace(v)
			}
		}
		return -1, ""
	}
	set := func(name, value string) {
		if i, _ := get(name); i > 0 {
			lines[i] = name + ": " + value
			return
		}
		lines = append(lines, name+": "+value)
	}
	for _, h := range hopByHop {
		for i, _ := get(h); i > 0; i, _ = get(h) {
			lines = append(lines[:i], lines[i+1:]...)
		}
	}
	if i, v := get("te"); i > 0 && !strings.EqualFold(v, "trailers") {
		lines = append(lines[:i], lines[i+1:]...)
	}
	ua := s.o.UserAgent
	if i, v := get("user-agent"); i > 0 {
		ua = v
	} else {
		set("User-Agent", ua)
	}
	if i, _ := get("sec-ch-ua"); i < 0 && scheme == "https" {
		hints := uahints.Hints(ua)
		for _, k := range []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"} {
			if v, ok := hints[k]; ok {
				set(hintHeader(k), v)
			}
		}
	}
	if role != "" {
		if u, err := url.Parse(scheme + "://" + host + uri); err == nil {
			if cs := s.cdnJar(role).Cookies(u); len(cs) > 0 {
				_, have := get("cookie")
				set("Cookie", mergeCookies(have, cs))
			}
		}
	}
	out := []byte(strings.Join(lines, "\r\n") + "\r\n\r\n")
	return append(out, body...)
}

// keepCDN takes the CDN cookies an answer sets into the role's jar.
func (s *Sender) keepCDN(role string, u *url.URL, setCookie string) {
	if role == "" || setCookie == "" {
		return
	}
	h := http.Header{}
	for _, l := range strings.Split(setCookie, "\n") {
		h.Add("Set-Cookie", l)
	}
	var cdn []*http.Cookie
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if traffic.CDNCookie(c.Name) {
			cdn = append(cdn, c)
		}
	}
	if len(cdn) > 0 {
		s.cdnJar(role).SetCookies(u, cdn)
	}
}

// cdnJar is a role's CDN cookies, in this Sender's memory only: never
// another role's, never written out (the roles stay apart).
func (s *Sender) cdnJar(role string) http.CookieJar {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cdn == nil {
		s.cdn = map[string]http.CookieJar{}
	}
	j := s.cdn[role]
	if j == nil {
		j, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		s.cdn[role] = j
	}
	return j
}

// mergeCookies is a Cookie header with the CDN cookies set: a value the
// request has for one of them is replaced, the others are kept as they are.
func mergeCookies(have string, cdn []*http.Cookie) string {
	byName := map[string]string{}
	for _, c := range cdn {
		byName[c.Name] = c.Value
	}
	var out []string
	for _, p := range strings.Split(have, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, _, _ := strings.Cut(p, "=")
		if v, ok := byName[n]; ok {
			out = append(out, n+"="+v)
			delete(byName, n)
			continue
		}
		out = append(out, p)
	}
	for _, c := range cdn {
		if v, ok := byName[c.Name]; ok {
			out = append(out, c.Name+"="+v)
		}
	}
	return strings.Join(out, "; ")
}

func hintHeader(k string) string {
	switch k {
	case "sec-ch-ua":
		return "Sec-CH-UA"
	case "sec-ch-ua-mobile":
		return "Sec-CH-UA-Mobile"
	case "sec-ch-ua-platform":
		return "Sec-CH-UA-Platform"
	}
	return http.CanonicalHeaderKey(k)
}
