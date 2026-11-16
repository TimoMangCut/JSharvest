package export

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/roles"
)

const creator = "jsharvest export"

// Manifest is manifest.json: what the export holds, and what to know
// before replaying it.
type Manifest struct {
	Creator   string         `json:"creator"`
	Generated time.Time      `json:"generated"`
	Dir       string         `json:"dir"`
	Runs      []string       `json:"runs"`
	Redacted  bool           `json:"redacted"`
	Keyword   string         `json:"keyword"` // the ffuf files' fuzz keyword
	Schemes   []string       `json:"schemes"`
	Counts    map[string]int `json:"counts"`
	Warnings  []string       `json:"warnings,omitempty"`
	Flows     []ManFlow      `json:"flows"`
	Endpoints []ManEndpoint  `json:"endpoints"`
	// Incomplete are raw files whose body is not all that was sent.
	Incomplete map[string]string `json:"incomplete,omitempty"`
	// SqlmapMarker are raw files with a "*" sqlmap takes for its mark.
	SqlmapMarker []string `json:"sqlmap_marker,omitempty"`
}

type ManFlow struct {
	Dir      string   `json:"dir"`
	Run      string   `json:"run"`
	Action   string   `json:"action"`
	Kind     string   `json:"kind"`
	Label    string   `json:"label"`
	Requests int      `json:"requests"`
	Files    []string `json:"files"`
}

type ManEndpoint struct {
	Key            string   `json:"key"`
	File           string   `json:"file"`
	Requests       int      `json:"requests"`
	Representative Ref      `json:"representative"`
	Held           bool     `json:"held,omitempty"`
	Destructive    bool     `json:"destructive,omitempty"`
	Ffuf           []string `json:"ffuf,omitempty"`
}

type flowFile struct {
	Run           string     `json:"run"`
	Action        string     `json:"action"`
	Kind          string     `json:"kind"`
	Label         string     `json:"label"`
	Page          string     `json:"page,omitempty"`
	Started       time.Time  `json:"started"`
	Requests      []flowReq  `json:"requests"`
	DependsOn     []flowLink `json:"depends_on,omitempty"`
	Prerequisites []flowLink `json:"prerequisites,omitempty"` // sources in other flows: run them first
}

type flowReq struct {
	ID          int    `json:"id"`
	File        string `json:"file,omitempty"`
	Why         string `json:"why_no_file,omitempty"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Endpoint    string `json:"endpoint"`
	How         string `json:"how,omitempty"`
	Outcome     string `json:"outcome"`
	Status      int64  `json:"status,omitempty"`
	Provisional bool   `json:"headers_provisional,omitempty"`
	CookieFrom  int    `json:"cookie_from,omitempty"`
}

type flowLink struct {
	Request  int    `json:"request"`
	At       string `json:"at"`
	From     int    `json:"from"`
	FromAt   string `json:"from_at"`
	FromFlow string `json:"from_flow,omitempty"`
	FromFile string `json:"from_file,omitempty"`
}

type writer struct {
	*exporter
	tmp  string
	man  *Manifest
	file map[*item]string // an item's raw file in its flow
}

func (x *exporter) write() (*Manifest, error) {
	if err := checkDest(x.o.Dest); err != nil {
		return nil, err
	}
	tok := make([]byte, 4)
	rand.Read(tok)
	tmp := x.o.Dest + ".tmp-" + hex.EncodeToString(tok)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, err
	}
	w := &writer{exporter: x, tmp: tmp, file: map[*item]string{},
		man: &Manifest{Creator: creator, Generated: time.Now().UTC(), Dir: x.o.Dir, Runs: x.runs, Redacted: x.o.Redact != nil,
			Counts: map[string]int{}, Incomplete: map[string]string{}, Flows: []ManFlow{}, Endpoints: []ManEndpoint{}}}
	err := w.all()
	if err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}
	if err := os.RemoveAll(x.o.Dest); err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, x.o.Dest); err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}
	return w.man, nil
}

// checkDest refuses to replace a directory jsharvest did not write.
func checkDest(dest string) error {
	st, err := os.Stat(dest)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(filepath.Dir(dest), 0o700)
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("export: %s is not a directory", dest)
	}
	var m Manifest
	b, err := os.ReadFile(filepath.Join(dest, "manifest.json"))
	if err != nil && (draftsOnly(dest) || openapiOnly(dest)) {
		return nil // export -drafts with no traffic wrote it: drafts/ alone
	}
	if err != nil || json.Unmarshal(b, &m) != nil || m.Creator != creator {
		return fmt.Errorf("export: %s exists and is not an export of jsharvest (no manifest.json): will not replace it", dest)
	}
	return nil
}

func (w *writer) put(rel string, b []byte) error {
	p := filepath.Join(w.tmp, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func (w *writer) putJSON(rel string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return w.put(rel, append(b, '\n'))
}

func (w *writer) all() error {
	x := w.exporter
	w.keyword = "FUZZ"
	for _, it := range x.items {
		if it.file && bytes.Contains(it.raw.Bytes, []byte("FUZZ")) {
			w.keyword = "JSHFUZZ"
			x.warn = append(x.warn, "a request has the text FUZZ: the ffuf files use the keyword JSHFUZZ (ffuf -w list:JSHFUZZ)")
			break
		}
	}
	w.man.Keyword = w.keyword
	schemes := map[string]bool{}
	for _, it := range x.items {
		if u, err := url.Parse(it.e.URL); err == nil {
			schemes[u.Scheme] = true
		}
	}
	for s := range schemes {
		w.man.Schemes = append(w.man.Schemes, s)
	}
	sort.Strings(w.man.Schemes)

	if err := w.flows(); err != nil {
		return err
	}
	groups, order := w.groups()
	params := x.params(groups, order)
	if err := w.endpointFiles(groups, order, params); err != nil {
		return err
	}
	sortParams(params)
	var pb bytes.Buffer
	enc := json.NewEncoder(&pb)
	for _, p := range params {
		if x.o.Redact != nil {
			for i, s := range p.line.Samples {
				p.line.Samples[i] = maskPII(s)
			}
		}
		if err := enc.Encode(p.line); err != nil {
			return err
		}
		if p.line.Observed {
			w.man.Counts["params"]++
		} else {
			w.man.Counts["params_code_only"]++
		}
	}
	if err := w.put("params.jsonl", pb.Bytes()); err != nil {
		return err
	}
	var pages []HARPage
	var entries []HAREntry
	for _, run := range x.runs {
		for _, f := range x.flows[run] {
			pages = append(pages, HARPage{ID: w.pageID(run, f.Action), Title: w.label(f.Label), Started: f.Started})
		}
	}
	for _, it := range x.items {
		entries = append(entries, w.harEntry(it))
	}
	b, err := NewHAR(pages, entries).Marshal()
	if err != nil {
		return err
	}
	if err := w.put("all.har", b); err != nil {
		return err
	}
	w.man.Counts["requests"] = len(x.items)
	for _, it := range x.items {
		if it.held() {
			w.man.Counts["held_back"]++
		}
		if provisional(it.e) {
			w.man.Counts["headers_provisional"]++
		}
		if it.cookieFrom > 0 {
			w.man.Counts["cookie_borrowed"]++
		}
	}
	w.man.Warnings = x.warn
	if len(w.man.Incomplete) == 0 {
		w.man.Incomplete = nil
	}
	if err := w.putJSON("manifest.json", w.man); err != nil {
		return err
	}
	return w.put("README.txt", []byte(w.readme()))
}

func (w *writer) pageID(run, action string) string {
	if len(w.runs) > 1 {
		return fmt.Sprintf("r%d-%s", slices.Index(w.runs, run)+1, action)
	}
	return action
}

func (w *writer) harEntry(it *item) HAREntry {
	info := map[string]any{"run": it.run, "id": it.e.ID, "endpoint": w.mask(it.key)}
	if it.flow != nil {
		info["action"], info["how"] = it.flow.Action, it.how
	}
	if it.held() {
		info["held_back"] = strings.TrimPrefix(it.e.Outcome, "held_back:")
	}
	if provisional(it.e) {
		info["headers_provisional"] = true
	}
	if it.cookieFrom > 0 {
		info["cookie_from"] = it.cookieFrom
	}
	page := ""
	if it.flow != nil {
		page = w.pageID(it.run, it.flow.Action)
	}
	return HAREntry{Entry: it.e, Page: page, Info: info}
}

// flows writes a directory for each flow that has requests: its raw files
// in order, its HAR, and flow.json.
func (w *writer) flows() error {
	x := w.exporter
	byFlow := map[*flow.Flow][]*item{}
	for _, it := range x.items {
		if it.flow != nil {
			byFlow[it.flow] = append(byFlow[it.flow], it)
		}
	}
	dirOf := map[*flow.Flow]string{}
	type pending struct {
		f   *flow.Flow
		dir string
	}
	var all []pending
	for _, run := range x.runs {
		fs := x.flows[run]
		for i := range fs {
			f := &fs[i]
			items := byFlow[f]
			if len(items) == 0 {
				continue
			}
			first := ""
			for _, it := range items {
				if it.file {
					first = it.e.Method + "-" + w.slugPath(it.tmpl)
					break
				}
			}
			name := f.Action + "-" + f.Kind
			if first != "" {
				name += "-" + slug(first)
			}
			if len(x.runs) > 1 {
				name = fmt.Sprintf("r%d-%s", slices.Index(x.runs, run)+1, name)
			}
			dirOf[f] = "flows/" + name
			all = append(all, pending{f, "flows/" + name})
		}
	}
	// Name the raw files first: a flow's prerequisites name files of others.
	for _, p := range all {
		n := 0
		once := map[string]bool{}
		for _, it := range byFlow[p.f] {
			if !it.file {
				continue
			}
			if p.f.Kind == "background" {
				if once[it.key] {
					it.why = "background: one request of each endpoint"
					continue
				}
				once[it.key] = true
			}
			n++
			held := ""
			if it.held() {
				held = ".held"
			}
			w.file[it] = fmt.Sprintf("%s/%02d-%s-%s%s.http", p.dir, n, it.e.Method, w.slugPath(it.tmpl), held)
		}
	}
	byRef := map[string]*item{}
	for _, it := range x.items {
		byRef[fmt.Sprint(it.run, "/", it.e.ID)] = it
	}
	for _, p := range all {
		f := p.f
		items := byFlow[f]
		ff := flowFile{Run: items[0].run, Action: f.Action, Kind: f.Kind, Label: w.label(f.Label), Page: w.mask(f.Page), Started: f.Started}
		mf := ManFlow{Dir: p.dir, Run: ff.Run, Action: f.Action, Kind: f.Kind, Label: ff.Label, Requests: len(items)}
		var har []HAREntry
		for _, it := range items {
			fr := flowReq{ID: it.e.ID, File: w.rel(p.dir, w.file[it]), Method: it.e.Method, URL: w.mask(it.e.URL), Endpoint: w.mask(it.key),
				How: it.how, Outcome: it.e.Outcome, Provisional: provisional(it.e), CookieFrom: it.cookieFrom}
			if it.e.Response != nil {
				fr.Status = it.e.Response.Status
			}
			if w.file[it] == "" {
				fr.Why = it.why
			} else {
				if err := w.put(w.file[it], it.raw.Bytes); err != nil {
					return err
				}
				mf.Files = append(mf.Files, fr.File)
				w.man.Counts["raw_files"]++
				if it.raw.Incomplete != "" {
					w.man.Incomplete[w.file[it]] = it.raw.Incomplete
				}
				if it.raw.Star {
					w.man.SqlmapMarker = append(w.man.SqlmapMarker, w.file[it])
				}
			}
			ff.Requests = append(ff.Requests, fr)
			har = append(har, w.harEntry(it))
		}
		for _, l := range f.DependsOn {
			src := byRef[fmt.Sprint(ff.Run, "/", l.From.Request)]
			fl := flowLink{Request: l.Request, At: l.At, From: l.From.Request, FromAt: l.From.At}
			if src != nil && src.flow != f {
				if src.flow != nil {
					fl.FromFlow = src.flow.Action
				}
				fl.FromFile = w.file[src]
				ff.Prerequisites = append(ff.Prerequisites, fl)
				continue
			}
			ff.DependsOn = append(ff.DependsOn, fl)
		}
		if err := w.putJSON(p.dir+"/flow.json", ff); err != nil {
			return err
		}
		b, err := NewHAR([]HARPage{{ID: w.pageID(ff.Run, f.Action), Title: ff.Label, Started: f.Started}}, har).Marshal()
		if err != nil {
			return err
		}
		if err := w.put(p.dir+"/flow.har", b); err != nil {
			return err
		}
		w.man.Flows = append(w.man.Flows, mf)
	}
	w.man.Counts["flows"] = len(all)
	return nil
}

// rel is a flow's file as flow.json names it: next to it.
func (w *writer) rel(dir, file string) string {
	return strings.TrimPrefix(file, dir+"/")
}

// groups are the endpoints of the requests that get raw files, in the
// order first met.
func (w *writer) groups() (map[string][]*item, []string) {
	groups := map[string][]*item{}
	var order []string
	for _, it := range w.endpointItems() {
		if !it.file {
			continue
		}
		if groups[it.key] == nil {
			order = append(order, it.key)
		}
		groups[it.key] = append(groups[it.key], it)
	}
	return groups, order
}

// endpointFiles writes endpoints/ (a representative of each endpoint) and
// the ffuf files: one for each param, from the newest request that has it.
func (w *writer) endpointFiles(groups map[string][]*item, order []string, params []*paramAgg) error {
	hosts := map[string]bool{}
	for _, k := range order {
		u, _ := url.Parse(groups[k][0].e.URL)
		hosts[u.Host] = true
	}
	names := map[string]bool{}
	base := map[string]string{}
	for _, k := range order {
		it := groups[k][0]
		u, _ := url.Parse(it.e.URL)
		b := it.e.Method + "-" + w.slugPath(it.tmpl)
		if it.op != "" {
			b += "-" + slug(w.mask(it.op))
		}
		if len(hosts) > 1 {
			b = slug(u.Host) + "-" + b
		}
		name := b
		for n := 2; names[name]; n++ {
			name = fmt.Sprintf("%s-%d", b, n)
		}
		names[name] = true
		base[k] = name
	}
	byKey := map[string][]*paramAgg{}
	for _, p := range params {
		byKey[p.line.Endpoint] = append(byKey[p.line.Endpoint], p)
	}
	for _, k := range order {
		group := groups[k]
		rep := representative(group)
		me := ManEndpoint{Key: w.mask(k), File: "endpoints/" + base[k] + ".http", Requests: len(group), Representative: Ref{rep.run, rep.e.ID}}
		for _, it := range group {
			me.Held = me.Held || it.held()
			me.Destructive = me.Destructive || it.destr
		}
		if err := w.put(me.File, rep.raw.Bytes); err != nil {
			return err
		}
		w.man.Counts["endpoints"]++
		dir := "ffuf/"
		if me.Destructive {
			dir = "ffuf-destructive/"
		}
		files := map[string]bool{}
		for _, p := range byKey[k] {
			p.line.Endpoint = w.mask(k)
			if !p.line.Observed {
				continue
			}
			p.line.File = me.File
			if why := skipFuzz(p.line); why != "" {
				p.line.FfufSkipped = why
				continue
			}
			src := representative(p.items)
			raw, ok := fuzzFile(src, p.line, w.keyword)
			if !ok {
				p.line.FfufSkipped = "not found in the request"
				continue
			}
			pn := p.line.Name
			if p.line.In == "path" {
				pn = fmt.Sprintf("%d", p.line.Index)
			}
			fb := dir + base[k] + "/" + p.line.In + "-" + slug(pn)
			f := fb + ".http"
			for n := 2; files[f]; n++ {
				f = fmt.Sprintf("%s-%d.http", fb, n)
			}
			files[f] = true
			if err := w.put(f, raw); err != nil {
				return err
			}
			p.line.Ffuf, p.line.FfufFrom = f, &Ref{src.run, src.e.ID}
			me.Ffuf = append(me.Ffuf, f)
			w.man.Counts["ffuf_files"]++
		}
		w.man.Endpoints = append(w.man.Endpoints, me)
	}
	return nil
}

// skipFuzz says why a param gets no ffuf file: a whole GraphQL query, or a
// credential (fuzzing a session cookie or a CSRF token only gets 401s).
func skipFuzz(l ParamLine) string {
	switch {
	case l.Type == "graphql":
		return "a GraphQL query: fuzz its variables"
	case l.Sensitive && (l.In == "cookie" || l.In == "header"):
		return "a credential"
	case l.Sensitive && l.DerivedFrom != nil && l.DerivedFrom.Refresh == "likely":
		return "a value a replay must take fresh from " + l.DerivedFrom.From
	}
	return ""
}

// fuzzFile puts the keyword in place of a param's value, as encoded in the
// request, and leaves Content-Length out (ffuf writes it).
func fuzzFile(it *item, l ParamLine, keyword string) ([]byte, bool) {
	segs := strings.Split(it.tmpl, "/")
	for _, p := range it.params {
		name := p.Name
		if p.In == "path" {
			if p.Index >= len(segs) {
				continue
			}
			name = segs[p.Index]
		}
		if p.In != l.In || name != l.Name || p.Index != l.Index {
			continue
		}
		b := it.raw.Bytes
		out := make([]byte, 0, len(b)+len(keyword))
		out = append(out, b[:p.Start]...)
		out = append(out, keyword...)
		out = append(out, b[p.End:]...)
		return StripContentLength(out), true
	}
	return nil, false
}

var contentLengthRe = regexp.MustCompile(`(?m)^Content-Length: \d+\r\n`)

// StripContentLength is a raw request without its Content-Length line, as
// the ffuf files are written.
func StripContentLength(b []byte) []byte {
	head := bytes.Index(b, []byte("\r\n\r\n"))
	if head < 0 {
		return b
	}
	return append(contentLengthRe.ReplaceAll(b[:head+2], nil), b[head+2:]...)
}

// slugPath names a file after a template, with tokens and emails masked.
func (w *writer) slugPath(tmpl string) string {
	return slug(strings.ReplaceAll(roles.MaskTokens(tmpl), "{}", "{var}"))
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 60 {
		s = strings.TrimRight(s[:60], "-")
	}
	if s == "" {
		return "root"
	}
	return s
}

// mask hides what could identify someone in what the export quotes, when
// it redacts: the URL's credentials, and tokens and emails in its path.
func (w *writer) mask(s string) string {
	if w.o.Redact == nil {
		return s
	}
	return maskPII(roles.MaskTokens(w.o.Redact.URL(s)))
}

func (w *writer) label(s string) string {
	if w.o.Redact == nil {
		return s
	}
	return maskPII(w.o.Redact.Text(s))
}

var anyEmailRe = regexp.MustCompile(`[\w.+-]+@[\w-]+(\.[\w-]+)+`)

func maskPII(s string) string { return anyEmailRe.ReplaceAllString(s, "{email}") }

func (w *writer) readme() string {
	proto := "https"
	if len(w.man.Schemes) == 1 {
		proto = w.man.Schemes[0]
	}
	sslNote := ""
	if proto == "https" {
		sslNote = " --force-ssl"
	}
	var b strings.Builder
	fmt.Fprintf(&b, `jsharvest export of %s
runs: %s

THIS DIRECTORY HOLDS CREDENTIALS (cookies, tokens) unless it was made with
-redact. Keep it private. Send these requests only to targets you are
authorized to test.

Layout
  flows/<action>-<kind>-<endpoint>/  one action and the requests it caused, in
                                     order: NN-METHOD-endpoint[.held].http,
                                     flow.har, flow.json (depends_on, and the
                                     prerequisites: values taken from requests
                                     of other flows, run those first)
  endpoints/METHOD-endpoint.http     one request for each endpoint
  ffuf/<endpoint>/<in>-<name>.http   the keyword %s in place of one parameter
  ffuf-destructive/                  the same, for DELETE, logout, wipe...:
                                     fuzzing them destroys data or the session
  params.jsonl                       every parameter: where, its type, samples,
                                     whether the code names it (in_js), and
                                     derived_from (a value an earlier response
                                     gave; refresh "likely" means take a fresh
                                     one before replaying)
  all.har                            every request, with its response
  manifest.json                      counts, warnings, files with an incomplete
                                     body, files sqlmap would misread

Raw files are HTTP/1.1 with the URL's scheme left out. Files ending in
.held.http are writes jsharvest's guard held back: they never reached the
server. Requests whose headers were not the wire's (held back, a worker's)
carry the cookie of the nearest request that went out (cookie_from).

ffuf
  ffuf -request ffuf/<endpoint>/<file>.http -request-proto %s -w words.txt
  Values are as encoded in the request: add -enc %s:urlencode for path,
  query and form parameters. EventSource and long polls need -timeout.

sqlmap
  sqlmap -r endpoints/<file>.http%s --batch
  A file listed in manifest.json sqlmap_marker has a "*", which sqlmap takes
  for an injection mark.

Burp Suite, Caido
  No native HAR import: open a raw file in Repeater (Paste from file), or send
  through the proxy (ffuf -replay-proxy http://127.0.0.1:8080, sqlmap --proxy).

ZAP, Chrome DevTools
  Import all.har or a flow.har.
`, w.o.Dir, strings.Join(w.runs, ", "), w.keyword, proto, w.keyword, sslNote)
	if len(w.warn) > 0 {
		b.WriteString("\nWarnings\n")
		for _, s := range w.warn {
			b.WriteString("  - " + s + "\n")
		}
	}
	return b.String()
}

// draftsOnly reports a directory holding jsharvest's drafts/ and nothing
// else (export -drafts of a catalog with no traffic).
func draftsOnly(dest string) bool {
	es, err := os.ReadDir(dest)
	if err != nil || len(es) != 1 || es[0].Name() != "drafts" {
		return false
	}
	_, err = os.Stat(filepath.Join(dest, "drafts", "index.json"))
	return err == nil
}
