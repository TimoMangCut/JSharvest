// Package export writes a role's recorded traffic as what fuzzers and
// proxies read: HAR, raw HTTP requests (ffuf -request, sqlmap -r, Burp's
// Repeater), and a catalog of the parameters, by flow (an action and the
// requests it caused) and by endpoint. It reads the output and sends
// nothing. See docs/gd4-export-design.md.
package export

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

type Options struct {
	Dir  string // <out>/<host>/<role>
	Dest string // the export's directory; Dir/export by default
	// Run is a run id, "all", or "" for the latest run that has flows.
	Run        string
	InScope    func(host string) bool
	ThirdParty bool // export hosts out of scope too
	// Redact hides credentials everywhere, and leaves response bodies out:
	// for sharing. The files then do not replay.
	Redact  *traffic.Redactor
	Catalog []endpoints.Endpoint
	// Role names the role in the OpenAPI document (x-jsharvest.roles).
	Role string
}

// apiTypes are the requests that call the application (as package
// endpoints counts them); a page load and Other are taken on conditions.
var apiTypes = map[string]bool{"Fetch": true, "XHR": true, "EventSource": true, "Ping": true, "": true}

// harOnly are kept out of everything: not application traffic, or not
// something a raw request can say.
var never = map[string]bool{"Script": true, "Stylesheet": true, "Image": true, "Media": true, "Font": true, "TextTrack": true,
	"Manifest": true, "Preflight": true, "WebSocket": true, "CSPViolationReport": true, "SignedExchange": true}

// item is one recorded request of the export.
type item struct {
	e      traffic.Entry // with the fixes: a cookie borrowed, an origin
	run    string
	runN   int // the run's place among the exported runs, from 1
	q      *results.Req
	flow   *flow.Flow
	how    string
	file   bool // gets raw files (else only the HARs)
	raw    Raw
	params []Param
	key    string // METHOD host/template [operation]
	tmpl   string
	op     string
	// derived are the places whose value came from an earlier response.
	derived    map[string]flow.LinkEnd
	cookieFrom int
	why        string // why there is no raw file
	destr      bool
	ep         *endpoints.Endpoint
	// parts are the operations of a GraphQL batch, one request each (the
	// representative of that operation's endpoint): the batch itself stays
	// the item of its flow, whole.
	parts []*item
}

// endpointItems are the requests an endpoint is made of: a batch counts
// as its parts, one for each operation.
func (x *exporter) endpointItems() []*item {
	out := make([]*item, 0, len(x.items))
	for _, it := range x.items {
		if len(it.parts) > 0 {
			out = append(out, it.parts...)
		} else {
			out = append(out, it)
		}
	}
	return out
}

// split makes the request an operation of a batch would have been: the
// body of that operation alone (an array of one), its length, its params.
func (it *item) split(p flow.BatchPart, u *url.URL) *item {
	c := *it
	c.parts = nil
	c.op = p.Op
	c.key = it.e.Method + " " + u.Host + it.tmpl
	if p.Op != "" {
		c.key += " " + p.Op
	}
	// The places that came from earlier responses were named on the whole
	// batch: this request's element is $[0], and the others' are not its.
	if it.derived != nil {
		at := "body:$[" + strconv.Itoa(p.Index) + "]"
		d := make(map[string]flow.LinkEnd, len(it.derived))
		for k, v := range it.derived {
			if !strings.HasPrefix(k, "body:$[") {
				d[k] = v
				continue
			}
			if rest, ok := strings.CutPrefix(k, at); ok && (rest == "" || rest[0] == '.' || rest[0] == '[') {
				d["body:$[0]"+rest] = v
			}
		}
		c.derived = d
	}
	c.e.Body = traffic.Body{Body: p.Body}
	if it.e.Headers != nil {
		h := make(map[string]string, len(it.e.Headers))
		for k, v := range it.e.Headers {
			if strings.EqualFold(k, "content-length") {
				v = strconv.Itoa(len(p.Body))
			}
			h[k] = v
		}
		c.e.Headers = h
	}
	return &c
}

func (it *item) held() bool { return strings.HasPrefix(it.e.Outcome, "held_back") }

// provisional reports whether the headers are not the wire's: no Cookie,
// no Host. Logs of before the flag have no host header then.
func provisional(e traffic.Entry) bool {
	if e.HeadersProvisional {
		return true
	}
	_, host := e.Headers["host"]
	_, authority := e.Headers[":authority"]
	return !host && !authority
}

type exporter struct {
	o       Options
	d       *results.Dir
	runs    []string
	items   []*item // every request of the runs that is in scope, in time order
	flows   map[string][]flow.Flow
	cat     *catalog
	warn    []string
	keyword string
	srcVals map[string]map[string]map[string]bool // METHOD url -> at -> values seen
}

// Export writes the export of o.Dir to o.Dest.
func Export(o Options) (*Manifest, error) {
	if o.Dest == "" {
		o.Dest = o.Dir + "/export"
	}
	if o.InScope == nil {
		o.InScope = func(string) bool { return true }
	}
	x := newExporter(o)
	if err := x.d.Refresh(); err != nil {
		return nil, err
	}
	if err := x.pickRuns(); err != nil {
		return nil, err
	}
	if err := x.load(); err != nil {
		return nil, err
	}
	x.endpoints()
	return x.write()
}

func newExporter(o Options) *exporter {
	return &exporter{o: o, d: results.Open(o.Dir), flows: map[string][]flow.Flow{}, cat: newCatalog(o.Catalog, o.InScope),
		srcVals: map[string]map[string]map[string]bool{}}
}

// ErrNoFlows: no run of the directory has flows (a crawl of the http
// engine, or one that recorded nothing).
var ErrNoFlows = errors.New("export: no run with flows")

func (x *exporter) pickRuns() error {
	all := x.d.Runs()
	has := func(run string) bool {
		fs, partial, err := x.d.Flows(run)
		if err == nil && len(fs) > 0 {
			x.flows[run] = fs
			if partial {
				x.warn = append(x.warn, fmt.Sprintf("run %s: the flows are a watch's snapshot (it is running, or was killed)", run))
			}
			return true
		}
		return false
	}
	switch x.o.Run {
	case "":
		for i := len(all) - 1; i >= 0; i-- {
			if has(all[i]) {
				x.runs = []string{all[i]}
				return nil
			}
		}
		return fmt.Errorf("%w in %s", ErrNoFlows, x.o.Dir)
	case "all":
		for _, r := range all {
			if has(r) {
				x.runs = append(x.runs, r)
			}
		}
		if len(x.runs) == 0 {
			return fmt.Errorf("%w in %s", ErrNoFlows, x.o.Dir)
		}
		return nil
	}
	if !slices.Contains(all, x.o.Run) {
		return fmt.Errorf("export: no run %s in %s (runs: %s)", x.o.Run, x.o.Dir, strings.Join(all, ", "))
	}
	if !has(x.o.Run) {
		return fmt.Errorf("export: run %s has no flows", x.o.Run)
	}
	x.runs = []string{x.o.Run}
	return nil
}

// load reads the runs' requests, picks those of the export, and fixes the
// ones whose headers are not the wire's.
func (x *exporter) load() error {
	redacted := false
	for n, run := range x.runs {
		owner := map[int]*flow.Flow{}
		how := map[int]string{}
		derived := map[int]map[string]flow.LinkEnd{}
		fs := x.flows[run]
		for i := range fs {
			for _, r := range fs[i].Requests {
				owner[r.ID], how[r.ID] = &fs[i], r.How
			}
			for _, l := range fs[i].DependsOn {
				if derived[l.Request] == nil {
					derived[l.Request] = map[string]flow.LinkEnd{}
				}
				derived[l.Request][l.At] = l.From
			}
		}
		var items []*item
		for _, q := range x.d.Requests(run) {
			if q.Internal || q.Challenge || never[q.ResourceType] {
				continue
			}
			u, err := url.Parse(q.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}
			if !x.o.InScope(u.Hostname()) && !x.o.ThirdParty {
				continue
			}
			e, err := x.d.Entry(run, q.ID)
			if err != nil {
				return err
			}
			if !redacted && strings.Contains(e.URL+fmt.Sprint(e.Headers)+e.Body.Body, "REDACTED_") {
				redacted = true
				x.warn = append(x.warn, "the request log was redacted when it was recorded (-redact): the raw files carry masks, not credentials, and will not replay")
			}
			it := &item{e: e, run: run, runN: n + 1, q: q, flow: owner[q.ID], how: how[q.ID], derived: derived[q.ID]}
			items = append(items, it)
		}
		x.fix(items)
		x.items = append(x.items, items...)
	}
	sort.SliceStable(x.items, func(i, j int) bool { return x.items[i].e.Time.Before(x.items[j].e.Time) })
	// What each source gave, read before redacting drops the bodies.
	for _, it := range x.items {
		src := sourceKey(it.e)
		if x.srcVals[src] == nil {
			x.srcVals[src] = map[string]map[string]bool{}
		}
		for _, v := range flow.ResponseValues(it.e) {
			if x.srcVals[src][v.At] == nil {
				x.srcVals[src][v.At] = map[string]bool{}
			}
			x.srcVals[src][v.At][v.V] = true
		}
	}
	if x.o.Redact != nil {
		for _, it := range x.items {
			x.o.Redact.Entry(&it.e)
			if r := it.e.Response; r != nil {
				resp := *r
				resp.Body, resp.BodyOmitted = traffic.Body{}, "redacted"
				it.e.Response = &resp
			}
		}
	}
	return nil
}

// fix gives a request whose headers are provisional (held back by the
// guard, a worker's, the cache's) what the wire would have had: the Cookie
// of the nearest request of the run to its host that went out, and an
// Origin when it is not a GET.
func (x *exporter) fix(items []*item) {
	type src struct {
		t      time.Time
		id     int
		cookie string
	}
	byHost := map[string][]src{}
	for _, it := range items {
		if c := it.e.Headers["cookie"]; c != "" && !provisional(it.e) {
			u, _ := url.Parse(it.e.URL)
			byHost[u.Host] = append(byHost[u.Host], src{it.e.Time, it.e.ID, c})
		}
	}
	for _, it := range items {
		if !provisional(it.e) {
			continue
		}
		h := make(map[string]string, len(it.e.Headers)+2)
		for k, v := range it.e.Headers {
			h[k] = v
		}
		u, _ := url.Parse(it.e.URL)
		if _, ok := h["cookie"]; !ok {
			var best *src
			for i, s := range byHost[u.Host] {
				if s.t.After(it.e.Time) {
					if best == nil {
						best = &byHost[u.Host][i]
					}
					break
				}
				best = &byHost[u.Host][i]
			}
			if best != nil {
				h["cookie"], it.cookieFrom = best.cookie, best.id
			}
		}
		if _, ok := h["origin"]; !ok && it.e.Method != "GET" && it.e.Method != "HEAD" {
			from := it.e.Page
			if from == "" {
				from = h["referer"]
			}
			if p, err := url.Parse(from); err == nil && p.Scheme != "" && p.Host != "" {
				h["origin"] = p.Scheme + "://" + p.Host
			}
		}
		it.e.Headers = h
	}
}

// endpoints keys each request by its endpoint: the template inferred over
// all of them, the segments the code computes or an earlier response gave
// made placeholders, and the operation of a GraphQL or RPC endpoint.
func (x *exporter) endpoints() {
	entries := make([]traffic.Entry, len(x.items))
	for i, it := range x.items {
		entries[i] = it.e
	}
	templates := flow.EntryTemplates(entries, func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && (u.Scheme == "http" || u.Scheme == "https") && !x.o.InScope(u.Hostname())
	})
	swAnswered := map[string]bool{}
	for _, it := range x.items {
		if it.e.Target == "service_worker" {
			swAnswered[it.e.Method+" "+it.e.URL] = true
		}
	}
	for i, it := range x.items {
		u, _ := url.Parse(it.e.URL)
		segs := strings.Split(templates[i], "/")
		for at := range it.derived {
			if n, ok := strings.CutPrefix(at, "path:"); ok {
				var k int
				if _, err := fmt.Sscan(n, &k); err == nil && k > 0 && k < len(segs) {
					segs[k] = "{}"
				}
			}
		}
		ep, catPath := x.cat.match(it.e.Method, u.Host, u.EscapedPath())
		if ep != nil {
			cs := strings.Split(catPath, "/")
			if len(cs) == len(segs) || (len(cs) == len(segs)-1 && segs[len(segs)-1] == "") {
				for j, s := range cs {
					if strings.HasPrefix(s, "{") && !strings.HasPrefix(segs[j], "{") {
						segs[j] = "{}"
					}
				}
			}
		}
		it.ep = ep
		it.tmpl = strings.Join(segs, "/")
		it.op = flow.OperationWithHeaders(u, it.e.Headers, it.e.Headers["content-type"], it.e.Body.Body)
		batch := flow.SplitBatch(it.e.Body.Body)
		it.key = it.e.Method + " " + u.Host + it.tmpl
		if it.op != "" {
			it.key += " " + it.op
		}
		it.destr = it.e.Method == "DELETE" || guard.Destructive(it.e.URL)

		rt := it.e.ResourceType
		switch {
		case it.e.Hop > 0:
			it.why = "redirect hop: the browser followed it"
		case strings.HasPrefix(it.e.Outcome, "failed") || it.e.Outcome == "incomplete":
			it.file = true // still the request the page made; never the representative
		case apiTypes[rt]:
			it.file = true
		case rt == "Document":
			if u.RawQuery != "" || it.e.Method != "GET" || strings.Contains(it.tmpl, "{") {
				it.file = true
			} else {
				it.why = "a page without parameters"
			}
		case rt == "Other" && ep != nil:
			it.file = true
		default:
			it.why = "type " + rt
		}
		if it.file && it.e.Target != "service_worker" && it.e.Response != nil && it.e.Response.Source == "service-worker" &&
			swAnswered[it.e.Method+" "+it.e.URL] {
			it.file, it.why = false, "answered by the service worker, whose own request is exported"
		}
		if it.file {
			r, err := RawRequest(it.e)
			if err != nil {
				it.file, it.why = false, err.Error()
				continue
			}
			it.raw, it.params = r, Params(r.Bytes)
			for _, p := range batch {
				part := it.split(p, u)
				if pr, err := RawRequest(part.e); err == nil {
					part.raw, part.params = pr, Params(pr.Bytes)
					it.parts = append(it.parts, part)
				}
			}
		}
	}
}

// representative scores a request as its endpoint's: the wire's headers,
// a success, a whole body, the newest.
func representative(group []*item) *item {
	var best *item
	score := func(it *item) int {
		s := 0
		if !provisional(it.e) {
			s += 8
		}
		if it.e.Response != nil && it.e.Response.Status >= 200 && it.e.Response.Status < 300 && !it.held() {
			s += 4
		}
		if it.raw.Incomplete == "" {
			s += 2
		}
		if strings.HasPrefix(it.e.Outcome, "failed") || it.e.Outcome == "incomplete" {
			s -= 32
		}
		return s
	}
	for _, it := range group {
		if best == nil || score(it) >= score(best) {
			best = it
		}
	}
	return best
}
