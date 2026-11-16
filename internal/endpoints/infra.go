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
	f, err := os.Open(filepath.Join(dir, "requests.jsonl"))
	if err != nil {
		return nil, nil, nil
	}
	defer f.Close()
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

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
