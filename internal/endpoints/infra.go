package endpoints

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// ServerHint is what the target's servers say they run (passive telemetry), read
// from the answers a crawl got: their Server and X-Powered-By headers, the
// shape of their error bodies. Passive: nothing is sent for it.
type ServerHint struct {
	Name     string   `json:"name"`               // Express, NestJS, nginx/1.18.0 (Ubuntu)…
	Origins  []string `json:"origins"`            // where it was seen
	Evidence string   `json:"evidence,omitempty"` // the header or body that says it
}

// SecurityNote is a configuration worth a look the answers show, passively:
// a lead to check by hand, not a finding.
type SecurityNote struct {
	// Kind: cors_wildcard_with_credentials (Access-Control-Allow-Origin *
	// with -Credentials true: check whether the server reflects an Origin
	// it is sent), cors_credentials_for_origin (an in-scope API allowed
	// another origin with credentials: an allowlist or a reflection, which
	// only a request with a foreign Origin tells apart),
	// tls_incomplete_chain (the server sends an incomplete certificate
	// chain: a client that does not fetch the AIA fails, and its users are
	// tempted to turn verification off).
	Kind    string   `json:"kind"`
	Origins []string `json:"origins"`
	Example string   `json:"example,omitempty"` // a URL it was seen on
	Count   int      `json:"count"`
}

// nestErrorRe is NestJS's default error body: {"statusCode":404,
// "message":"Cannot GET /x","error":"Not Found"}.
var nestErrorRe = regexp.MustCompile(`^\s*\{\s*"statusCode"\s*:\s*\d{3}\s*,\s*"message"\s*:\s*(?:"[^"]*"|\[[^\]]*\])\s*,\s*"error"\s*:\s*"[^"]*"\s*\}\s*$`)

// expressHTMLRe is Express's own 404 page: <pre>Cannot GET /x</pre>.
var expressHTMLRe = regexp.MustCompile(`<pre>Cannot (?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /[^<]*</pre>`)

// Infra reads requests.jsonl of a role's directory for the hints and notes
// of the in-scope answers; challenge pages and the tool's own requests
// count too (they reach the same servers), third parties do not.
func Infra(dir string, inScope func(host string) bool) ([]ServerHint, []SecurityNote) {
	hs, ns, _ := infraAll(dir, inScope)
	return hs, ns
}

func infraAll(dir string, inScope func(host string) bool) ([]ServerHint, []SecurityNote, []AuthFlow) {
	hints := map[string]*ServerHint{}
	notes := map[string]*SecurityNote{}
	var flows []AuthFlow
	hint := func(name, origin, evidence string) {
		h := hints[name]
		if h == nil {
			h = &ServerHint{Name: name, Evidence: evidence}
			hints[name] = h
		}
		if !slices.Contains(h.Origins, origin) {
			h.Origins = append(h.Origins, origin)
		}
	}
	note := func(kind, origin, example string) {
		n := notes[kind]
		if n == nil {
			n = &SecurityNote{Kind: kind, Example: example}
			notes[kind] = n
		}
		n.Count++
		if !slices.Contains(n.Origins, origin) {
			n.Origins = append(n.Origins, origin)
		}
	}

	if f, err := os.Open(filepath.Join(dir, "requests.jsonl")); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			var e struct {
				URL      string            `json:"url"`
				Headers  map[string]string `json:"headers"`
				Response *struct {
					Status   int               `json:"status"`
					Headers  map[string]string `json:"headers"`
					Body     string            `json:"body"`
					Base64   bool              `json:"body_base64"`
					TLSChain bool              `json:"tls_incomplete_chain"`
				} `json:"response"`
			}
			if json.Unmarshal(sc.Bytes(), &e) != nil || e.Response == nil || e.Response.Status == 0 {
				continue
			}
			u, err := url.Parse(e.URL)
			if err != nil || u.Host == "" || inScope != nil && !inScope(u.Hostname()) {
				continue
			}
			origin := strings.ToLower(u.Scheme + "://" + u.Host)
			h := e.Response.Headers
			if v := strings.TrimSpace(h["server"]); v != "" && len(v) < 80 {
				hint(v, origin, "server: "+v)
			}
			if v := strings.TrimSpace(h["x-powered-by"]); v != "" && len(v) < 80 {
				hint(v, origin, "x-powered-by: "+v)
			}
			inferFrameworkHints(h, origin, hint)
			if !e.Response.Base64 && e.Response.Status >= 400 {
				switch b := e.Response.Body; {
				case nestErrorRe.MatchString(b):
					hint("NestJS", origin, "error body "+clip(b, 120))
				case expressHTMLRe.MatchString(b):
					hint("Express", origin, "error page "+clip(expressHTMLRe.FindString(b), 120))
				}
			}
			acao, acac := strings.TrimSpace(h["access-control-allow-origin"]), strings.EqualFold(strings.TrimSpace(h["access-control-allow-credentials"]), "true")
			switch {
			case acao == "*" && acac:
				note("cors_wildcard_with_credentials", origin, e.URL)
			case acac && acao != "" && acao != "null" && !strings.EqualFold(acao, origin) && strings.EqualFold(acao, e.Headers["origin"]):
				note("cors_credentials_for_origin", origin, e.URL)
			}
			if e.Response.TLSChain {
				note("tls_incomplete_chain", origin, e.URL)
			}
			if e.Response.Status >= 200 && e.Response.Status < 400 {
				var body []byte
				if !e.Response.Base64 {
					body = []byte(e.Response.Body)
				}
				fs, fn := ExtractAuthFlows(e.URL, e.Response.Status, h, body)
				flows = append(flows, fs...)
				for _, k := range fn {
					note(k, origin, e.URL)
				}
			}
		}
		_ = f.Close()
	}

	// Scan pages.jsonl for HTML <a href> / <form action> / redirect OAuth2/OIDC
	// authorization URLs discovered on in-scope pages (requests.jsonl omits HTML bodies).
	if pf, err := os.Open(filepath.Join(dir, "pages.jsonl")); err == nil {
		sc := bufio.NewScanner(pf)
		sc.Buffer(make([]byte, 256<<10), 16<<20)
		for sc.Scan() {
			var p struct {
				URL  string `json:"url"`
				From string `json:"from"`
			}
			if json.Unmarshal(sc.Bytes(), &p) != nil || p.URL == "" {
				continue
			}
			srcURL := p.From
			if srcURL == "" {
				srcURL = p.URL
			}
			su, err := url.Parse(srcURL)
			if err != nil || su.Host == "" || (inScope != nil && !inScope(su.Hostname())) {
				continue
			}
			origin := strings.ToLower(su.Scheme + "://" + su.Host)
			fs, fn := ExtractAuthFlows(srcURL, 200, nil, []byte(p.URL))
			flows = append(flows, fs...)
			for _, k := range fn {
				note(k, origin, srcURL)
			}
		}
		_ = pf.Close()
	}

	if len(hints) == 0 && len(notes) == 0 && len(flows) == 0 {
		return nil, nil, nil
	}
	var hs []ServerHint
	for _, h := range hints {
		slices.Sort(h.Origins)
		hs = append(hs, *h)
	}
	slices.SortFunc(hs, func(a, b ServerHint) int { return strings.Compare(a.Name, b.Name) })
	var ns []SecurityNote
	for _, n := range notes {
		slices.Sort(n.Origins)
		ns = append(ns, *n)
	}
	slices.SortFunc(ns, func(a, b SecurityNote) int { return strings.Compare(a.Kind, b.Kind) })
	return hs, ns, dedupAuthFlows(flows)
}

// inferFrameworkHints passively identifies backend frameworks from response
// header names and Set-Cookie names (never reading or storing cookie values).
func inferFrameworkHints(headers map[string]string, origin string, hint func(name, origin, evidence string)) {
	for k, v := range headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		switch lk {
		case "x-drupal-cache", "x-drupal-dynamic-cache":
			if cv := strings.TrimSpace(v); cv != "" && len(cv) < 60 {
				hint("Drupal", origin, lk+": "+cv)
			}
		case "x-aspnet-version", "x-aspnetmvc-version":
			if cv := strings.TrimSpace(v); cv != "" && len(cv) < 60 {
				hint("ASP.NET", origin, lk+": "+cv)
			}
		case "set-cookie":
			for _, line := range strings.Split(v, "\n") {
				name, _, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				name = strings.TrimSpace(name)
				lname := strings.ToLower(name)
				switch {
				case lname == "laravel_session":
					hint("Laravel", origin, "cookie: "+name)
				case lname == "asp.net_sessionid" || strings.HasPrefix(lname, ".aspnetcore."):
					hint("ASP.NET", origin, "cookie: "+name)
				case lname == "jsessionid":
					hint("Java Servlet", origin, "cookie: "+name)
				case lname == "phpsessid":
					hint("PHP", origin, "cookie: "+name)
				case lname == "_rails_session":
					hint("Ruby on Rails", origin, "cookie: "+name)
				case lname == "connect.sid":
					hint("Express", origin, "cookie: "+name)
				case lname == "ci_session":
					hint("CodeIgniter", origin, "cookie: "+name)
				}
			}
		}
	}
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
