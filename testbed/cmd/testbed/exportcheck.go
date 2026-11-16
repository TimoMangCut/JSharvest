package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// exportcheck checks a jsharvest export (docs/gd4-export-design.md, 7)
// against the run it was made of and a truth file:
//
//   - every request the truth's steps expect has a raw file in its flow;
//     every API request of the run is in one flow.json, once;
//
//   - every raw file reads as HTTP/1.1, and says what the log says: method,
//     target, body, headers (but those the export leaves out);
//
//   - the HARs have what ZAP's and DevTools' importers require;
//
//   - every ffuf file has its keyword once, in place of the value of its
//     request's file;
//
//   - params.jsonl has the truth's params;
//
//   - with -replay, the files replayed against the testbed get the
//     recorded status, and the same body where the truth says so;
//
//   - with -redacted, no secret of the log is left in the export, and the
//     replays the truth names are refused;
//
//   - files 0600, directories 0700, one host.
//
//   - with -openapi FILE (alone, with -log and -truth): the OpenAPI document
//     of `export -format openapi` is a well-formed 3.1 one (see
//     openapiProblems), is 0600, holds no secret of the log, and has every
//     endpoint of the truth's params;
//
//     testbed exportcheck -export DIR -log <out>/<host>/<role> -truth export.truth.json
//     -steps flows.truth.json [-replay http://127.0.0.1:8770] [-held] [-redacted]
func exportcheck(args []string) error {
	fset := flag.NewFlagSet("exportcheck", flag.ExitOnError)
	dir := fset.String("export", "", "the export's directory")
	logDir := fset.String("log", "", "the role's output directory (requests.jsonl)")
	truthPath := fset.String("truth", "", "export.truth.json")
	stepsPath := fset.String("steps", "", "flows.truth.json: the requests each step makes")
	replay := fset.String("replay", "", "the testbed's base URL: replay the files there")
	held := fset.Bool("held", false, "the run had the guard on: writes are .held.http files")
	redacted := fset.Bool("redacted", false, "the export was made with -redact")
	openapi := fset.String("openapi", "", "check the OpenAPI document at this path instead of an export")
	fset.Parse(args)
	if *openapi != "" {
		return openapiCheck(*openapi, *logDir, *truthPath)
	}

	c := &xcheck{dir: *dir}
	if err := c.loadLog(filepath.Join(*logDir, "requests.jsonl")); err != nil {
		return err
	}
	var truth exportTruth
	if err := readJSON(*truthPath, &truth); err != nil {
		return err
	}
	var man struct {
		Runs      []string               `json:"runs"`
		Keyword   string                 `json:"keyword"`
		Flows     []struct{ Dir string } `json:"flows"`
		Endpoints []struct {
			Key            string
			File           string
			Representative struct {
				Run string
				ID  int
			}
		} `json:"endpoints"`
	}
	if err := readJSON(filepath.Join(*dir, "manifest.json"), &man); err != nil {
		return err
	}
	c.run = man.Runs[0]
	c.files()
	c.redacted = *redacted
	c.flowFiles(man.Flows)
	if *stepsPath != "" {
		c.steps(*stepsPath, *held)
	}
	for _, h := range append([]string{"all.har"}, c.hars...) {
		c.har(h)
	}
	if !*redacted {
		c.ffuf(man.Keyword)
	}
	c.params(truth, *redacted, *held)
	if *replay != "" {
		base, _ := url.Parse(*replay)
		bodies := map[string]bool{}
		for _, e := range truth.ReplaySameBody {
			bodies[e] = true
		}
		if !*redacted {
			for _, ep := range man.Endpoints {
				key := stripHost(ep.Key)
				if !strings.HasPrefix(key, "GET ") {
					continue
				}
				rec := c.log[ref{ep.Representative.Run, ep.Representative.ID}]
				status, body, err := send(base, filepath.Join(*dir, ep.File))
				switch {
				case err != nil:
					c.fail("replay %s: %v", ep.File, err)
				case rec == nil || rec.Response == nil:
					c.fail("replay %s: no recorded response", ep.File)
				case status != rec.Response.Status:
					c.fail("replay %s: status %d, recorded %d", ep.File, status, rec.Response.Status)
				case bodies[key] && body != rec.Response.Body:
					c.fail("replay %s: body %q, recorded %q", ep.File, body, rec.Response.Body)
				default:
					c.ok("replay")
				}
			}
		}
		for _, r := range truth.Replay {
			want := r.Status
			if *redacted {
				want = r.RedactedStatus
			}
			file := c.fileFor(r.Endpoint, *held && r.Write)
			if file == "" {
				c.fail("replay %s: no file", r.Endpoint)
				continue
			}
			status, _, err := send(base, file)
			if err != nil || status != want {
				c.fail("replay %s (%s): status %d, want %d (%v)", r.Endpoint, rel(*dir, file), status, want, err)
				continue
			}
			c.ok("replay named")
		}
	}
	if *redacted {
		c.secrets()
	}
	for _, k := range sortedKeys(c.counts) {
		fmt.Printf("  %-22s %d\n", k, c.counts[k])
	}
	if len(c.errs) > 0 {
		for _, e := range c.errs {
			fmt.Println("FAIL", e)
		}
		return fmt.Errorf("exportcheck: %d failure(s)", len(c.errs))
	}
	fmt.Println("exportcheck: ok")
	return nil
}

type exportTruth struct {
	Params []struct {
		Endpoint, In, Name, Type, DerivedFrom, Refresh string
		Index                                          int
		Observed                                       *bool
		InJS                                           *bool `json:"in_js"`
		Ffuf                                           *bool
		Destructive                                    bool
		NoDerived                                      bool `json:"no_derived"`
		// GuardOff: true of the run with the guard off only (a held write
		// gives no value to derive from).
		GuardOff bool `json:"guard_off"`
	} `json:"params"`
	NotParams []struct {
		Endpoint, In, Name string
	} `json:"not_params"`
	ReplaySameBody []string `json:"replay_same_body"`
	Replay         []struct {
		Endpoint       string
		Write          bool // held back in a run with the guard on
		Status         int64
		RedactedStatus int64 `json:"redacted_status"`
	} `json:"replay"`
}

type ref struct {
	Run string
	ID  int
}

type logEntry struct {
	Run          string            `json:"run"`
	ID           int               `json:"id"`
	Hop          int               `json:"hop"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	ResourceType string            `json:"resource_type"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	BodyBase64   bool              `json:"body_base64"`
	Outcome      string            `json:"outcome"`
	Tags         []string          `json:"tags"`
	Response     *struct {
		Status  int64             `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"response"`
}

type xcheck struct {
	dir    string
	run    string
	log    map[ref]*logEntry
	order  []ref
	hars   []string
	byFile map[string]ref // a flow's raw file -> its request
	inFlow map[ref]int
	counts map[string]int
	errs   []string
	// redacted: values are masked, so headers are compared by name only.
	redacted bool
}

func (c *xcheck) ok(what string) {
	if c.counts == nil {
		c.counts = map[string]int{}
	}
	c.counts[what]++
}

func (c *xcheck) fail(f string, a ...any) {
	if len(c.errs) < 60 {
		c.errs = append(c.errs, fmt.Sprintf(f, a...))
	}
	c.ok("failures")
}

func (c *xcheck) loadLog(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	c.log = map[ref]*logEntry{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var e logEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			c.log[ref{e.Run, e.ID}] = &e
			c.order = append(c.order, ref{e.Run, e.ID})
		}
	}
	return sc.Err()
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	return nil
}

func rel(dir, p string) string {
	r, err := filepath.Rel(dir, p)
	if err != nil {
		return p
	}
	return r
}

// files checks the permissions, that every raw file reads as HTTP/1.1, and
// that every one is for the testbed's host.
func (c *xcheck) files() {
	host := ""
	filepath.WalkDir(c.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, _ := d.Info()
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			c.fail("%s: mode %o, want %o", rel(c.dir, p), info.Mode().Perm(), want)
		}
		if strings.HasSuffix(p, ".har") && strings.Contains(p, "/flows/") {
			c.hars = append(c.hars, rel(c.dir, p))
		}
		if !strings.HasSuffix(p, ".http") {
			return nil
		}
		b, _ := os.ReadFile(p)
		q, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
		if err != nil {
			c.fail("%s: %v", rel(c.dir, p), err)
			return nil
		}
		if host == "" {
			host = q.Host
		} else if q.Host != host {
			c.fail("%s: host %s, the others %s", rel(c.dir, p), q.Host, host)
		}
		if !strings.Contains(string(b), "\r\n\r\n") || strings.Contains(strings.ReplaceAll(string(b[:bytes.Index(b, []byte("\r\n\r\n"))]), "\r\n", ""), "\n") {
			c.fail("%s: a bare LF in the head", rel(c.dir, p))
		}
		c.ok("raw files read")
		return nil
	})
}

var droppedHeaders = map[string]bool{"host": true, "connection": true, "keep-alive": true, "proxy-connection": true,
	"transfer-encoding": true, "te": true, "upgrade": true, "priority": true, "accept-encoding": true, "content-length": true}

// flowFiles checks each flow.json's raw files against the log, and that
// every API request of the run is in one flow.
func (c *xcheck) flowFiles(flows []struct{ Dir string }) {
	c.byFile, c.inFlow = map[string]ref{}, map[ref]int{}
	for _, f := range flows {
		var ff struct {
			Run      string
			Requests []struct {
				ID         int
				File       string
				Outcome    string
				CookieFrom int `json:"cookie_from"`
			}
		}
		if err := readJSON(filepath.Join(c.dir, f.Dir, "flow.json"), &ff); err != nil {
			c.fail("%v", err)
			continue
		}
		if _, err := os.Stat(filepath.Join(c.dir, f.Dir, "flow.har")); err != nil {
			c.fail("%s: no flow.har", f.Dir)
		}
		for _, r := range ff.Requests {
			k := ref{ff.Run, r.ID}
			c.inFlow[k]++
			if r.File == "" {
				continue
			}
			p := filepath.Join(c.dir, f.Dir, r.File)
			c.byFile[p] = k
			e := c.log[k]
			if e == nil {
				c.fail("%s: request %d not in the log", r.File, r.ID)
				continue
			}
			if strings.HasPrefix(e.Outcome, "held_back") != strings.HasSuffix(r.File, ".held.http") {
				c.fail("%s: outcome %s", r.File, e.Outcome)
			}
			c.same(p, e, r.CookieFrom)
		}
	}
	for _, k := range c.order {
		e := c.log[k]
		if k.Run != c.run || e.Hop > 0 || slices.Contains(e.Tags, "jsharvest") {
			continue
		}
		switch e.ResourceType {
		case "Fetch", "XHR", "Ping", "EventSource":
		default:
			continue
		}
		if c.inFlow[k] != 1 {
			c.fail("request %d %s %s: in %d flows", k.ID, e.Method, e.URL, c.inFlow[k])
		} else {
			c.ok("requests in a flow")
		}
	}
}

// same checks a raw file says what the log says.
func (c *xcheck) same(p string, e *logEntry, cookieFrom int) {
	b, _ := os.ReadFile(p)
	q, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
	if err != nil {
		return // reported by files
	}
	u, _ := url.Parse(e.URL)
	target, _, _ := strings.Cut(e.URL[len(u.Scheme)+3+len(u.Host):], "#")
	if target == "" || target[0] == '?' {
		target = "/" + target
	}
	body, _ := io.ReadAll(q.Body)
	want := []byte(e.Body)
	if e.BodyBase64 {
		want = nil // binary: compared by length
	}
	switch {
	case q.Method != e.Method:
		c.fail("%s: method %s, logged %s", rel(c.dir, p), q.Method, e.Method)
	case c.redacted && (strings.Contains(q.RequestURI, "REDACTED_") || bytes.Contains(body, []byte("REDACTED_"))):
		c.ok("raw files masked")
	case q.RequestURI != target:
		c.fail("%s: target %s, logged %s", rel(c.dir, p), q.RequestURI, target)
	case q.Host != u.Host:
		c.fail("%s: host %s, logged %s", rel(c.dir, p), q.Host, u.Host)
	case want != nil && !bytes.Equal(body, want):
		c.fail("%s: body %q, logged %q", rel(c.dir, p), body, want)
	default:
		c.ok("raw files match the log")
	}
	for k, v := range e.Headers {
		if strings.HasPrefix(k, ":") || droppedHeaders[k] {
			continue
		}
		sep := ", "
		if k == "cookie" {
			sep = "; "
		}
		got := strings.Join(q.Header.Values(k), sep)
		if c.redacted && got != "" {
			continue
		}
		if got != strings.ReplaceAll(v, "\n", sep) {
			c.fail("%s: header %s %q, logged %q", rel(c.dir, p), k, got, v)
		}
	}
	if cookieFrom > 0 && q.Header.Get("Cookie") == "" {
		c.fail("%s: cookie_from %d but no Cookie", rel(c.dir, p), cookieFrom)
	} else if cookieFrom > 0 {
		c.ok("cookies borrowed")
	}
}

var expectRe = regexp.MustCompile(`\{[^}]+\}`)

// steps checks every request the steps expect has a raw file in a flow.
func (c *xcheck) steps(p string, held bool) {
	var t struct {
		Steps []struct {
			Expect []string `json:"expect"`
		} `json:"steps"`
	}
	if err := readJSON(p, &t); err != nil {
		c.fail("%v", err)
		return
	}
	lines := map[string]string{} // request line -> file
	for f := range c.byFile {
		b, _ := os.ReadFile(f)
		line, _, _ := strings.Cut(string(b), " HTTP/1.1\r\n")
		lines[line] = f
	}
	for _, s := range t.Steps {
		for _, x := range s.Expect {
			method, target, _ := strings.Cut(x, " ")
			var parts []string
			for _, lit := range expectRe.Split(target, -1) {
				parts = append(parts, regexp.QuoteMeta(lit))
			}
			re := regexp.MustCompile("^" + method + " " + strings.Join(parts, `[^/?]+`) + "$")
			var found string
			for l, f := range lines {
				if re.MatchString(l) {
					found = f
				}
			}
			switch {
			case found == "":
				c.fail("step request %s: no raw file in a flow", x)
			case held && method != "GET" && !strings.HasSuffix(found, ".held.http"):
				c.fail("step request %s: %s is not .held", x, rel(c.dir, found))
			default:
				c.ok("step requests")
			}
		}
	}
}

// har checks the fields HAR importers require.
func (c *xcheck) har(name string) {
	var h struct {
		Log *struct {
			Creator *map[string]any  `json:"creator"`
			Entries []map[string]any `json:"entries"`
		} `json:"log"`
	}
	if err := readJSON(filepath.Join(c.dir, name), &h); err != nil || h.Log == nil || h.Log.Creator == nil || h.Log.Entries == nil {
		c.fail("%s: no log, creator or entries (%v)", name, err)
		return
	}
	for i, e := range h.Log.Entries {
		bad := func(what string) { c.fail("%s entry %d: %s", name, i, what) }
		if s, _ := e["startedDateTime"].(string); s == "" {
			bad("startedDateTime")
		} else if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
			bad("startedDateTime " + s)
		}
		if _, ok := e["time"].(float64); !ok {
			bad("time")
		}
		req, _ := e["request"].(map[string]any)
		resp, _ := e["response"].(map[string]any)
		if req == nil || resp == nil {
			bad("request or response")
			continue
		}
		for _, k := range []string{"method", "url", "httpVersion", "headers", "queryString", "cookies", "headersSize", "bodySize"} {
			if _, ok := req[k]; !ok {
				bad("request." + k)
			}
		}
		for _, k := range []string{"status", "statusText", "headers", "cookies", "redirectURL", "headersSize", "bodySize"} {
			if _, ok := resp[k]; !ok {
				bad("response." + k)
			}
		}
		switch v, _ := resp["httpVersion"].(string); v {
		case "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3":
		default:
			bad("response.httpVersion " + v)
		}
		ct, _ := resp["content"].(map[string]any)
		if _, ok := ct["size"].(float64); !ok || ct["mimeType"] == nil {
			bad("response.content")
		}
		tm, _ := e["timings"].(map[string]any)
		for _, k := range []string{"send", "wait", "receive"} {
			if _, ok := tm[k].(float64); !ok {
				bad("timings." + k)
			}
		}
		if _, ok := e["cache"]; !ok {
			bad("cache")
		}
	}
	c.ok("hars")
}

// ffuf checks each ffuf file is its request's file with the keyword in
// place of the value: one keyword, and around it the request's bytes.
func (c *xcheck) ffuf(keyword string) {
	byRef := map[ref]string{}
	for f, r := range c.byFile {
		byRef[r] = f
	}
	clRe := regexp.MustCompile(`(?m)^Content-Length: \d+\r\n`)
	forEachParam(c.dir, func(p paramLine) {
		if p.Ffuf == "" {
			return
		}
		b, err := os.ReadFile(filepath.Join(c.dir, p.Ffuf))
		if err != nil {
			c.fail("%v", err)
			return
		}
		if n := bytes.Count(b, []byte(keyword)); n != 1 {
			c.fail("%s: %d keywords", p.Ffuf, n)
			return
		}
		if bytes.Contains(b, []byte("Content-Length:")) {
			c.fail("%s: has Content-Length", p.Ffuf)
		}
		src := byRef[ref{p.FfufFrom.Run, p.FfufFrom.ID}]
		if src == "" {
			c.ok("ffuf files without a flow file")
			return
		}
		orig, _ := os.ReadFile(src)
		head := bytes.Index(orig, []byte("\r\n\r\n"))
		orig = append(clRe.ReplaceAll(orig[:head+2], nil), orig[head+2:]...)
		before, after, _ := bytes.Cut(b, []byte(keyword))
		if !bytes.HasPrefix(orig, before) || !bytes.HasSuffix(orig, after) || len(before)+len(after) > len(orig) {
			c.fail("%s: not its request with one value replaced", p.Ffuf)
			return
		}
		value := string(orig[len(before) : len(orig)-len(after)])
		dec := value
		switch p.In {
		case "query", "form":
			dec, _ = url.QueryUnescape(value)
		case "path":
			dec, _ = url.PathUnescape(value)
		case "json":
			json.Unmarshal([]byte(`"`+value+`"`), &dec)
		}
		if !slices.Contains(p.Samples, dec) && !slices.Contains(p.Samples, value) {
			c.fail("%s: replaced %q, not one of the samples %v", p.Ffuf, value, p.Samples)
			return
		}
		c.ok("ffuf files")
	})
}

type paramLine struct {
	Endpoint    string   `json:"endpoint"`
	In          string   `json:"in"`
	Name        string   `json:"name"`
	Index       int      `json:"index"`
	Type        string   `json:"type"`
	Samples     []string `json:"samples"`
	Observed    bool     `json:"observed"`
	InJS        *bool    `json:"in_js"`
	Destructive bool     `json:"destructive"`
	DerivedFrom *struct {
		From    string `json:"from"`
		Refresh string `json:"refresh"`
	} `json:"derived_from"`
	Ffuf     string `json:"ffuf"`
	FfufFrom *ref   `json:"ffuf_from"`
}

func forEachParam(dir string, f func(paramLine)) {
	b, _ := os.ReadFile(filepath.Join(dir, "params.jsonl"))
	for _, line := range bytes.Split(b, []byte("\n")) {
		var p paramLine
		if json.Unmarshal(line, &p) == nil && p.Endpoint != "" {
			f(p)
		}
	}
}

// stripHost turns "METHOD host/path op" into "METHOD /path op".
func stripHost(key string) string {
	method, rest, _ := strings.Cut(key, " ")
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[i:]
	}
	return method + " " + rest
}

func (c *xcheck) params(t exportTruth, redacted, held bool) {
	var all []paramLine
	forEachParam(c.dir, func(p paramLine) { all = append(all, p) })
	for _, w := range t.Params {
		if w.GuardOff && held {
			continue
		}
		var got *paramLine
		for i, p := range all {
			if stripHost(p.Endpoint) == w.Endpoint && p.In == w.In && (w.Name == "" || p.Name == w.Name) && p.Index == w.Index {
				got = &all[i]
			}
		}
		name := fmt.Sprintf("%s %s %s%d", w.Endpoint, w.In, w.Name, w.Index)
		switch {
		case got == nil:
			c.fail("param %s: missing", name)
			continue
		case w.Type != "" && !redacted && got.Type != w.Type:
			c.fail("param %s: type %s, want %s", name, got.Type, w.Type)
		case w.Observed != nil && got.Observed != *w.Observed:
			c.fail("param %s: observed %v", name, got.Observed)
		case w.InJS != nil && (got.InJS == nil || *got.InJS != *w.InJS):
			c.fail("param %s: in_js %v, want %v", name, got.InJS, *w.InJS)
		case w.DerivedFrom != "" && (got.DerivedFrom == nil || !strings.HasPrefix(stripScheme(got.DerivedFrom.From), w.DerivedFrom)):
			c.fail("param %s: derived_from %+v, want %s", name, got.DerivedFrom, w.DerivedFrom)
		case w.Refresh != "" && (got.DerivedFrom == nil || got.DerivedFrom.Refresh != w.Refresh):
			c.fail("param %s: refresh %+v, want %s", name, got.DerivedFrom, w.Refresh)
		case w.NoDerived && got.DerivedFrom != nil:
			c.fail("param %s: derived_from %+v, want none", name, got.DerivedFrom)
		case !redacted && w.Ffuf != nil && (got.Ffuf != "") != *w.Ffuf:
			c.fail("param %s: ffuf %q", name, got.Ffuf)
		case w.Destructive && (!got.Destructive || !strings.HasPrefix(got.Ffuf, "ffuf-destructive/")):
			c.fail("param %s: destructive %v, ffuf %q", name, got.Destructive, got.Ffuf)
		default:
			c.ok("params")
		}
	}
	for _, w := range t.NotParams {
		for _, p := range all {
			if stripHost(p.Endpoint) == w.Endpoint && p.In == w.In && p.Name == w.Name {
				c.fail("param %s %s %s: should not be", w.Endpoint, w.In, w.Name)
			}
		}
	}
}

// stripScheme turns "GET http://host/path" into "GET /path".
func stripScheme(s string) string {
	method, u, _ := strings.Cut(s, " ")
	if p, err := url.Parse(u); err == nil {
		return method + " " + p.EscapedPath()
	}
	return s
}

// fileFor finds a raw file of an endpoint: a held one in a flow, or the
// endpoint's own.
func (c *xcheck) fileFor(endpoint string, held bool) string {
	method, path, _ := strings.Cut(endpoint, " ")
	for f, r := range c.byFile {
		e := c.log[r]
		u, _ := url.Parse(e.URL)
		if e.Method == method && u.Path == path && held == strings.HasSuffix(f, ".held.http") {
			return f
		}
	}
	return ""
}

// send replays a raw file against base, without following redirects.
func send(base *url.URL, file string) (int64, string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return 0, "", err
	}
	q, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
	if err != nil {
		return 0, "", err
	}
	body, _ := io.ReadAll(q.Body)
	req, err := http.NewRequest(q.Method, base.Scheme+"://"+base.Host+q.RequestURI, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header = q.Header
	req.Host = q.Host
	cl := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return int64(resp.StatusCode), string(rb), nil
}

// secrets checks no cookie value or token of the log is in the export.
func (c *xcheck) secrets() {
	secret := map[string]bool{}
	for _, e := range c.log {
		for k, v := range e.Headers {
			switch {
			case k == "cookie":
				for _, part := range strings.Split(strings.ReplaceAll(v, "\n", "; "), "; ") {
					if _, val, ok := strings.Cut(part, "="); ok && len(val) >= 8 {
						secret[val] = true
					}
				}
			case strings.Contains(k, "csrf") || strings.Contains(k, "token") || k == "authorization":
				if len(v) >= 8 {
					secret[v] = true
				}
			}
		}
	}
	filepath.WalkDir(c.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for s := range secret {
			if bytes.Contains(b, []byte(s)) {
				c.fail("%s: holds a secret of the log (%s…)", rel(c.dir, p), s[:4])
			}
		}
		return nil
	})
	c.ok("secrets checked")
	c.counts["secrets known"] = len(secret)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// openapiCheck checks `export -format openapi`'s document: its form, its
// mode, that no secret of the log is in it, and that the truth's
// endpoints are.
func openapiCheck(path, logDir, truthPath string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c := &xcheck{dir: filepath.Dir(path)}
	if st, err := os.Stat(path); err != nil {
		return err
	} else if st.Mode().Perm() != 0o600 {
		c.fail("%s: mode %o, want 600", path, st.Mode().Perm())
	}
	var want []string
	if truthPath != "" {
		var truth exportTruth
		if err := readJSON(truthPath, &truth); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, p := range truth.Params {
			if !strings.HasPrefix(p.Endpoint, "*") && !seen[p.Endpoint] {
				seen[p.Endpoint] = true
				want = append(want, p.Endpoint)
			}
		}
	}
	for _, p := range openapiProblems(b, want) {
		c.fail("openapi: %s", p)
	}
	if logDir != "" {
		if err := c.loadLog(filepath.Join(logDir, "requests.jsonl")); err != nil {
			return err
		}
		c.secrets() // the directory holds the document alone
	}
	c.ok("openapi checked")
	for _, k := range sortedKeys(c.counts) {
		fmt.Printf("  %-22s %d\n", k, c.counts[k])
	}
	if len(c.errs) > 0 {
		for _, e := range c.errs {
			fmt.Println("FAIL", e)
		}
		return fmt.Errorf("exportcheck: %d failure(s)", len(c.errs))
	}
	fmt.Println("exportcheck: ok")
	return nil
}

var (
	oaBraceRe  = regexp.MustCompile(`\{([^{}]*)\}`)
	oaMethodRe = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}
)

// openapiProblems is a minimal structural check of an OpenAPI 3.1
// document (no validator is in the dependencies): the fields the version
// requires, paths that start with "/", the {names} of a path and its
// "in: path" parameters the same set (each required), unique
// operationIds, responses in each operation, no value on a credential's
// header, and an operation for each of want ("METHOD /path/{}").
func openapiProblems(b []byte, want []string) []string {
	var probs []string
	bad := func(f string, a ...any) { probs = append(probs, fmt.Sprintf(f, a...)) }
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return []string{"not JSON: " + err.Error()}
	}
	if doc["openapi"] != "3.1.0" {
		bad("openapi is %v, want 3.1.0", doc["openapi"])
	}
	info, _ := doc["info"].(map[string]any)
	for _, k := range []string{"title", "version"} {
		if s, _ := info[k].(string); s == "" {
			bad("info.%s missing", k)
		}
	}
	if srv, ok := doc["servers"].([]any); ok {
		for _, s := range srv {
			if m, _ := s.(map[string]any); m == nil || m["url"] == nil || m["url"] == "" {
				bad("a server with no url")
			}
		}
	}
	paths, _ := doc["paths"].(map[string]any)
	if paths == nil {
		bad("no paths")
	}
	ids := map[string]string{}
	have := map[string]bool{}
	credHeader := func(n string) bool {
		n = strings.ToLower(n)
		return n == "authorization" || n == "cookie" || n == "proxy-authorization"
	}
	paramList := func(v any) []map[string]any {
		var out []map[string]any
		l, _ := v.([]any)
		for _, p := range l {
			if m, ok := p.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	for _, p := range sortedAny(paths) {
		item, _ := paths[p].(map[string]any)
		if !strings.HasPrefix(p, "/") {
			bad("path %q does not start with /", p)
		}
		inPath := map[string]bool{}
		check := func(where string, ps []map[string]any) {
			for _, m := range ps {
				name, _ := m["name"].(string)
				in, _ := m["in"].(string)
				if name == "" || (in != "path" && in != "query" && in != "header" && in != "cookie") {
					bad("%s: a parameter with name %q in %q", where, name, in)
					continue
				}
				if in == "path" {
					if m["required"] != true {
						bad("%s: path parameter %s is not required: true", where, name)
					}
					inPath[name] = true
				}
				if in == "header" && credHeader(name) {
					sc, _ := m["schema"].(map[string]any)
					for _, k := range []string{"example", "examples", "default"} {
						if m[k] != nil || sc[k] != nil {
							bad("%s: header %s carries a value (%s)", where, name, k)
						}
					}
					if strings.EqualFold(name, "cookie") {
						bad("%s: a header parameter named Cookie", where)
					}
				}
			}
		}
		shared := paramList(item["parameters"])
		names := map[string]bool{}
		for _, m := range oaBraceRe.FindAllStringSubmatch(p, -1) {
			if m[1] == "" {
				bad("path %s has an unnamed {}", p)
			}
			names[m[1]] = true
		}
		for _, m := range sortedAny(item) {
			ml := strings.ToLower(m)
			if !oaMethodRe[ml] {
				continue
			}
			op, _ := item[m].(map[string]any)
			where := ml + " " + p
			have[strings.ToUpper(ml)+" "+oaBraceRe.ReplaceAllString(p, "{}")] = true
			inPath = map[string]bool{}
			check(where, shared)
			check(where, paramList(op["parameters"]))
			for n := range names {
				if !inPath[n] {
					bad("%s: {%s} in the path has no in: path parameter", where, n)
				}
			}
			for n := range inPath {
				if !names[n] {
					bad("%s: in: path parameter %s is not in the path", where, n)
				}
			}
			id, _ := op["operationId"].(string)
			switch {
			case id == "":
				bad("%s: no operationId", where)
			case ids[id] != "":
				bad("%s: operationId %s is also %s's", where, id, ids[id])
			default:
				ids[id] = where
			}
			if r, _ := op["responses"].(map[string]any); len(r) == 0 {
				bad("%s: no responses", where)
			}
			if x, _ := op["x-jsharvest"].(map[string]any); x != nil {
				if s, _ := x["source"].(string); s != "traffic" && s != "code" && s != "both" {
					bad("%s: x-jsharvest.source %q", where, s)
				}
			}
		}
	}
	for _, w := range want {
		method, path, _ := strings.Cut(w, " ")
		if !have[strings.ToUpper(method)+" "+oaBraceRe.ReplaceAllString(path, "{}")] {
			bad("no operation for %s", w)
		}
	}
	return probs
}

func sortedAny(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
