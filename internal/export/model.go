package export

import (
	"fmt"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Request is one recorded request as the export sees it: its headers
// fixed when they were provisional, its endpoint, the flow it belongs to,
// and the places whose values earlier responses gave.
type Request struct {
	Entry       traffic.Entry
	Run         string
	Key         string // METHOD host/template [operation]
	Template    string
	Flow        *flow.Flow
	How         string
	Derived     map[string]flow.LinkEnd // place -> the response place it came from
	Provisional bool
	CookieFrom  int
	Held        bool
	File        bool                // the export writes it as a raw file
	Op          string              // the operation of a GraphQL or RPC endpoint: "op=Name", "action=x"; "" for none
	Destructive bool                // a DELETE, or a URL the guard's rules call destructive
	EP          *endpoints.Endpoint // the code's endpoint the request matched, nil for none

	raw    []byte
	params []Param
}

// Raw is the request as a raw HTTP/1.1 message.
func (r *Request) Raw() ([]byte, error) {
	if r.raw == nil {
		rr, err := RawRequest(r.Entry)
		if err != nil {
			return nil, err
		}
		r.raw, r.params = rr.Bytes, Params(rr.Bytes)
	}
	return r.raw, nil
}

// Params are the request's parameters with their places in Raw.
func (r *Request) Params() []Param {
	r.Raw()
	return r.params
}

// Model is a role's traffic as the export reads it, for the replay.
type Model struct {
	Runs     []string
	Flows    map[string][]flow.Flow // by run
	Requests []*Request             // time order
	byRef    map[string]*Request
	// For the OpenAPI document: the code's endpoints, the role, and
	// whether the values are masked (-redact).
	cat      *catalog
	role     string
	redacted bool
}

// Load reads o.Dir as Export does, without writing anything.
func Load(o Options) (*Model, error) {
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
	m := &Model{Runs: x.runs, Flows: x.flows, byRef: map[string]*Request{},
		cat: x.cat, role: o.Role, redacted: o.Redact != nil}
	for _, it := range x.items {
		mk := func(it *item) *Request {
			r := &Request{Entry: it.e, Run: it.run, Key: it.key, Template: it.tmpl, Flow: it.flow, How: it.how, Derived: it.derived,
				Provisional: provisional(it.e), CookieFrom: it.cookieFrom, Held: it.held(), File: it.file,
				Op: it.op, Destructive: it.destr, EP: it.ep}
			if it.file {
				r.raw, r.params = it.raw.Bytes, it.params
			}
			return r
		}
		r := mk(it)
		m.byRef[ref(it.run, it.e.ID)] = r // a batch is found whole by its id
		if len(it.parts) == 0 {
			m.Requests = append(m.Requests, r)
			continue
		}
		// ...and listed as its operations, one request for each.
		for _, p := range it.parts {
			m.Requests = append(m.Requests, mk(p))
		}
	}
	return m, nil
}

func ref(run string, id int) string { return fmt.Sprint(run, "/", id) }

// Request returns a run's request by id.
func (m *Model) Request(run string, id int) *Request { return m.byRef[ref(run, id)] }

// Best is the request a group is best replayed from, as the export picks
// its representative: the wire's headers, a success, a whole body, the
// newest.
func Best(reqs []*Request) *Request {
	var best *Request
	score := func(r *Request) int {
		s := 0
		if !r.Provisional {
			s += 8
		}
		if resp := r.Entry.Response; resp != nil && resp.Status >= 200 && resp.Status < 300 && !r.Held {
			s += 4
		}
		if !r.Entry.BodyTruncated {
			s += 2
		}
		if strings.HasPrefix(r.Entry.Outcome, "failed") || r.Entry.Outcome == "incomplete" {
			s -= 32
		}
		return s
	}
	for _, r := range reqs {
		if best == nil || score(r) >= score(best) {
			best = r
		}
	}
	return best
}
