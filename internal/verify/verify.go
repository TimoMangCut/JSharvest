package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/mdsafe"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Verdicts.
const (
	Alive           = "verified_alive"   // the route answers as itself
	Resource404     = "resource_404"     // a route that says its sample item does not exist
	AuthWall        = "auth_wall_opaque" // the prefix answers 401/403 to any path: a login is needed to tell
	ServerError     = "server_error"     // a 5xx the canary does not give
	WriteUnverified = "write_unverified" // a write whose GET probe matched a method-scoped (404/405) canary (-allow-write needed)
	ClientRoute     = "client_route"     // a bare string (-include-strings) that answered with the SPA's shell
	DeadOrFP        = "dead_or_fp"       // what any path gets: no such route, or the SPA's shell
	Unreachable     = "unreachable"      // no answer
	WAFBlocked      = "waf_blocked"      // a CDN/WAF answered in the application's place: nothing to tell (round 25H)
	HostBlocked     = "host_blocked"     // not sent: the host was given up, a vendor blocks the client there
	HostGated       = "host_gated"       // not sent: every probe of the host answered as its canary did, alike (round 25I)
	Skipped         = "skipped"          // not sent (Reason says why)
	Planned         = "planned"          // -dry-run: what would be sent
)

// verdictRank orders what a line that no candidate answered as a route
// for is said to be: the most a candidate told.
var verdictRank = map[string]int{Unreachable: 1, HostBlocked: 1, HostGated: 1, DeadOrFP: 2, WAFBlocked: 3, ClientRoute: 4, WriteUnverified: 5, Planned: 6, ServerError: 7, AuthWall: 8}

// maxPrefixes bounds the gateway prefixes of one origin a canary is asked
// of; the others share their origin's root's.
const maxPrefixes = 12

// Options are a verification's.
type Options struct {
	Target, Role      string
	Drafts            []Draft
	Sender            *replay.Sender
	Policy            replay.Policy
	InScope           func(host string) bool
	Recorded          map[string]string
	AllowWrite        bool
	IncludeDocs       bool
	IncludeStrings    bool
	IncludeSourceOnly bool
	Identity          *replay.Identity // nil: a visitor's requests
	Dir               string           // <role>/verify
	// GateAfter: that many probes in a row on a host, each answering as
	// its canary and all alike (a login, a device or app header before
	// every route), and the host's other drafts are not sent (round 25I,
	// N4). 0: never.
	GateAfter int
	// MaxPrefixes bounds the gateway prefixes per origin before falling back
	// to 1-segment parent canaries (0: unlimited — every prefix gets its own canary).
	MaxPrefixes int
	// Concurrency: hosts verified at once, each one request at a time
	// unless HostInFlight > 1 (round 25K); the Sender's -rate stays the
	// ceiling on all. 1 (or less): one host after another, in probeOrder.
	Concurrency int
	// HostInFlight: concurrent probes allowed on a single host when
	// Concurrency > 1 (<= 1: strictly 1 request at a time per host).
	HostInFlight int
	Cloud        []endpoints.IntelURL // cloud storage URLs from intel.json
	IntelDir     string               // role directory whose intel.json is updated when writable
	NoCloudProbe bool                 // -no-cloud-probe: skip safe cloud ACL checks
}

// CloudCheck is endpoints.CloudCheck.
type CloudCheck = endpoints.CloudCheck

// Result is what one draft came to.
type Result struct {
	ID             string               `json:"id"`
	Operation      string               `json:"operation,omitempty"`
	Source         string               `json:"source"`
	Method         string               `json:"method"`
	Path           string               `json:"path"`
	Confidence     string               `json:"confidence,omitempty"`
	Tier           string               `json:"tier"`
	Verdict        string               `json:"verdict"`
	Reason         string               `json:"reason,omitempty"`
	Sent           string               `json:"sent,omitempty"` // the method sent (GET: a probe of a write)
	URL            string               `json:"url,omitempty"`
	Prefix         string               `json:"prefix,omitempty"` // origin + gateway prefix of its canary
	Answer         *Sig                 `json:"answer,omitempty"`
	VerifiedBase   string               `json:"verified_base,omitempty"`
	VerifiedMethod string               `json:"verified_method,omitempty"`
	ServerMissing  []string             `json:"server_missing_params,omitempty"`
	AuthFlows      []endpoints.AuthFlow `json:"auth_flows,omitempty"`
}

// Canary is a gateway prefix's answer to a path that cannot exist.
type Canary struct {
	Prefix  string `json:"prefix"`
	URL     string `json:"url"`
	Answer  *Sig   `json:"answer,omitempty"`
	Options *Sig   `json:"options,omitempty"`
	Err     string `json:"error,omitempty"`
	Drafts  int    `json:"drafts"`

	ready   chan struct{}
	optOnce sync.Once
	// uncounted: asked by rootCanary, outside -max-prefixes' budget; the
	// first draft whose own prefix it is counts it (round 37.1, C2).
	uncounted bool
}

// Report is verify.json.
type Report struct {
	Target     string    `json:"target"`
	Role       string    `json:"role"`
	DryRun     bool      `json:"dry_run,omitempty"`
	AllowWrite bool      `json:"allow_write,omitempty"`
	Started    time.Time `json:"started"`
	Ended      time.Time `json:"ended"`
	Sent       int       `json:"sent"`
	Stopped    string    `json:"stopped,omitempty"`
	// HostsBlocked are the hosts given up: a vendor blocked the client
	// there, a control request too (round 25H).
	HostsBlocked map[string]string `json:"hosts_blocked,omitempty"`
	// HostsGated are the hosts whose probes all answered alike, as their
	// canaries did: the rest of their drafts were not sent (round 25I).
	HostsGated  map[string]string `json:"hosts_gated,omitempty"`
	Verdicts    map[string]int    `json:"verdicts"`
	Tiers       map[string]int    `json:"tiers"`
	Confidence  map[string]int    `json:"confidence"`
	Canaries    []*Canary         `json:"canaries"`
	Results     []Result          `json:"results"`
	CloudChecks []CloudCheck      `json:"cloud_checks,omitempty"`
}

// Run verifies the drafts. With a dry-run Sender nothing leaves: each
// request it would send is written to its log, and each draft's verdict
// is planned.
func Run(ctx context.Context, o Options) (*Report, error) {
	rep := &Report{Target: o.Target, Role: o.Role, DryRun: o.Sender.DryRun(), AllowWrite: o.AllowWrite, Started: time.Now().UTC(),
		Verdicts: map[string]int{}, Tiers: map[string]int{}, Confidence: map[string]int{}}
	v := &verifier{o: o, rep: rep, canaries: map[string]*Canary{}, htmlShells: map[string][]Sig{}, shellHosts: map[string]map[string]bool{}, perOrigin: map[string]int{}, gates: map[string]*gate{}, parents: map[string]int{}, hostPrefixes: map[string]int{}, hostPools: map[string]*hostSlotPool{}, specBases: map[string]*specBaseStat{}}
	// The hosts: those of the drafts in scope, nothing else.
	hosts := map[string]bool{}
	for _, d := range o.Drafts {
		for _, t := range append([]string{d.URL}, d.Candidates...) {
			if u, err := url.Parse(t); err == nil && u.Host != "" && !d.ThirdParty && o.InScope(u.Hostname()) {
				hosts[u.Host] = true
			}
		}
	}
	o.Sender.Allow(hosts, o.Recorded)
	// Drafts that differ only in their operation (and id) are the same
	// request: it is sent once and its answer is each one's.
	var uniq []Draft
	rep0 := make([]int, len(o.Drafts)) // draft -> its request's place in uniq
	byReq := map[string]int{}
	for i, d := range o.Drafts {
		c := d
		c.ID, c.Operation = "", ""
		k := ""
		if b, err := json.Marshal(c); err == nil {
			k = string(b)
		}
		if k == "" {
			rep0[i] = len(uniq)
			uniq = append(uniq, d)
			continue
		}
		if j, ok := byReq[k]; ok {
			rep0[i] = j
			continue
		}
		byReq[k] = len(uniq)
		rep0[i] = len(uniq)
		uniq = append(uniq, d)
	}
	all := o.Drafts
	v.o.Drafts, o.Drafts = uniq, uniq
	results := make([]*Result, len(uniq))
	order := v.probeOrder(o.Drafts)
	if o.Concurrency <= 1 {
		for _, i := range order {
			if ctx.Err() != nil {
				break
			}
			r := v.one(ctx, o.Drafts[i])
			results[i] = &r
		}
	} else {
		v.byHost(ctx, order, results)
	}
	v.rejudgeShells(o.Drafts, results)
	// verify.json lists the drafts in their own order, whatever order they
	// were sent in.
	for i, d := range all {
		r := results[rep0[i]]
		if r == nil {
			continue
		}
		res := *r
		res.ID, res.Operation = d.ID, d.Operation
		rep.Tiers[d.Tier]++
		if d.Confidence != "" {
			rep.Confidence[d.Confidence]++
		}
		rep.Verdicts[res.Verdict]++
		rep.Results = append(rep.Results, res)
	}
	for _, k := range slices.Sorted(mapsKeys(v.canaries)) {
		rep.Canaries = append(rep.Canaries, v.canaries[k])
	}
	rep.Sent = o.Sender.Count()
	rep.Stopped = o.Sender.Stopped()
	rep.HostsBlocked = o.Sender.BlockedHosts()
	for h, g := range v.gates {
		if g.why != "" {
			if rep.HostsGated == nil {
				rep.HostsGated = map[string]string{}
			}
			rep.HostsGated[h] = g.why
		}
	}
	if !o.NoCloudProbe && o.Sender != nil && !o.Sender.DryRun() && ctx.Err() == nil {
		intelDir := o.IntelDir
		if intelDir == "" && filepath.Base(o.Dir) == "verify" {
			intelDir = filepath.Dir(o.Dir)
		}
		cloud := o.Cloud
		if len(cloud) == 0 && intelDir != "" {
			var in endpoints.Intel
			if b, err := os.ReadFile(filepath.Join(intelDir, endpoints.IntelFile)); err == nil && json.Unmarshal(b, &in) == nil {
				cloud = in.Cloud
			}
		}
		if len(cloud) > 0 {
			so := o.Sender.Options()
			probed, checks := endpoints.ProbeCloud(ctx, cloud, endpoints.CloudProbeOptions{
				Proxy:        so.Proxy,
				HostRules:    so.HostRules,
				AllowPrivate: so.AllowPrivate,
				Insecure:     so.Insecure,
				Resolver:     so.Resolver,
				UserAgent:    so.UserAgent,
			})
			rep.CloudChecks = checks
			if intelDir != "" {
				_ = endpoints.UpdateIntelCloud(intelDir, probed)
			}
		}
	}
	if o.Sender != nil {
		if r := o.Sender.Redactor(); r != nil {
			for i := range rep.Results {
				if rep.Results[i].URL != "" {
					rep.Results[i].URL = r.URL(rep.Results[i].URL)
				}
			}
			for i := range rep.Canaries {
				if rep.Canaries[i].Err != "" {
					rep.Canaries[i].Err = r.URL(rep.Canaries[i].Err)
				}
			}
		}
	}
	rep.Ended = time.Now().UTC()
	return rep, ctx.Err()
}

func mapsKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

type verifier struct {
	o          Options
	rep        *Report
	canaries   map[string]*Canary        // origin+prefix
	htmlShells map[string][]Sig          // host (or "*") -> 2xx HTML shells observed on canaries
	shellHosts map[string]map[string]bool // Shell hash -> distinct canary hosts
	perOrigin  map[string]int
	gates      map[string]*gate // host
	parents    map[string]int   // origin: 1-segment parent canaries past maxPrefixes
	// hostPrefixes: how many gateway prefixes a host's drafts that are
	// sent have (probeOrder): a host with one or two needs no third to be
	// found gated.
	hostPrefixes map[string]int
	// mu guards the maps every host's probes share (canaries, perOrigin,
	// parents, gates, hostPools, specBases).
	mu        sync.Mutex
	hostPools map[string]*hostSlotPool
	specBases map[string]*specBaseStat
}

type hostSlotPool struct {
	mu        sync.Mutex
	limit    int
	inFlight int
	// throttled: a 429 (or a rate block) was met: one at a time from then on.
	throttled bool
	// gateSer: the host may be gated (a probe answered as its canary with a
	// gate's status): one at a time while the gate is counted, so that it
	// counts probes in a row as -host-inflight 1 does; off again once the
	// host answers otherwise (round 37.1, C4).
	gateSer bool
	wake    chan struct{}
}

func newHostSlotPool(limit int) *hostSlotPool {
	if limit < 1 {
		limit = 1
	}
	return &hostSlotPool{limit: limit, wake: make(chan struct{})}
}

func (p *hostSlotPool) acquire(ctx context.Context) (func(), bool) {
	for {
		p.mu.Lock()
		lim := p.limit
		if p.throttled || p.gateSer || lim < 1 {
			lim = 1
		}
		if p.inFlight < lim {
			p.inFlight++
			p.mu.Unlock()
			return p.release, true
		}
		w := p.wake
		p.mu.Unlock()
		select {
		case <-w:
		case <-ctx.Done():
			return nil, false
		}
	}
}

func (p *hostSlotPool) release() {
	p.mu.Lock()
	p.inFlight--
	close(p.wake)
	p.wake = make(chan struct{})
	p.mu.Unlock()
}

func (p *hostSlotPool) stepDown() {
	p.mu.Lock()
	p.throttled = true
	p.mu.Unlock()
}

// setGateSerial turns the gate's one-at-a-time on or off; off wakes the
// probes that waited for it.
func (p *hostSlotPool) setGateSerial(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gateSer == on {
		return
	}
	p.gateSer = on
	if !on {
		close(p.wake)
		p.wake = make(chan struct{})
	}
}

func (v *verifier) hostMaxInFlight() int {
	if v.o.Concurrency <= 1 || v.o.HostInFlight <= 1 {
		return 1
	}
	return min(v.o.HostInFlight, v.o.Concurrency)
}

func (v *verifier) poolForHost(host string) *hostSlotPool {
	v.mu.Lock()
	p := v.hostPools[host]
	if p == nil {
		p = newHostSlotPool(v.hostMaxInFlight())
		v.hostPools[host] = p
	}
	v.mu.Unlock()
	return p
}

func (v *verifier) stepDownHost(host string) {
	if host == "" || v.hostMaxInFlight() <= 1 {
		return
	}
	v.poolForHost(host).stepDown()
}

const specBasePruneAfter = 16

type specBaseStat struct {
	deadPaths map[string]bool
	signals   int
}

func (v *verifier) isSpecBasePruned(base string) bool {
	if base == "" {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.specBases[base]
	return st != nil && st.signals == 0 && len(st.deadPaths) >= specBasePruneAfter
}

func (v *verifier) noteSpecBase(base, path, verdict string) {
	if base == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.specBases[base]
	if st == nil {
		st = &specBaseStat{deadPaths: map[string]bool{}}
		v.specBases[base] = st
	}
	switch verdict {
	case Alive, Resource404, ServerError, AuthWall, WAFBlocked:
		st.signals++
	case DeadOrFP:
		if st.signals == 0 && path != "" {
			st.deadPaths[path] = true
		}
	}
}

// gate is what a host's probes said so far: alike, as their canaries.
type gate struct {
	first    *Sig
	n        int
	prefixes map[string]bool
	broken   bool   // a probe told something: the host is not gated
	why      string // set once gated
}

// gateStatus are answers a gateway gives before routing: a login, a
// device or app check (e.g., 400 "unauthorized_client"), a proxy's.
// A router's "no such route" (404, 405) and an SPA's shell (2xx, 3xx) are
// routing, not a gate: a host answering so has routes the drafts may miss
// and hit alike, and is never given up for it (round 25I review).
var gateStatus = map[int]bool{400: true, 401: true, 403: true, 407: true, 412: true, 426: true, 428: true}

// gatePrefixes is how many gateway prefixes a gate must be seen on: one
// prefix behind a login (/opaque) is that prefix's, not the host's.
const gatePrefixes = 3

func (v *verifier) hostGateWhy(host string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if g := v.gates[host]; g != nil {
		return g.why
	}
	return ""
}

// acquireHost holds one per-host slot (1 by default, up to -host-inflight).
func (v *verifier) acquireHost(ctx context.Context, host string) (func(), bool) {
	return v.poolForHost(host).acquire(ctx)
}

// noteGate counts a probe's answer toward its host's gate.
func (v *verifier) noteGate(host string, sig Sig, r *Result, asCanary bool) {
	if v.o.GateAfter <= 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	g := v.gates[host]
	if g == nil {
		g = &gate{}
		v.gates[host] = g
	}
	if g.broken || g.why != "" {
		return
	}
	pool := v.hostPools[host] // under v.mu, as poolForHost reads it
	if !asCanary || !gateStatus[sig.Status] || (r.Verdict != DeadOrFP && r.Verdict != AuthWall) || g.first != nil && !Same(sig, *g.first) {
		g.broken = true
		if pool != nil {
			pool.setGateSerial(false) // no gate: back to -host-inflight
		}
		return
	}
	if g.first == nil {
		s := sig
		g.first = &s
		g.prefixes = map[string]bool{}
		if pool != nil && v.hostMaxInFlight() > 1 {
			pool.setGateSerial(true) // a gate may be there: count it one probe at a time
		}
	}
	g.prefixes[r.Prefix] = true
	if g.n++; g.n >= v.o.GateAfter && len(g.prefixes) >= min(gatePrefixes, max(1, v.hostPrefixes[host])) {
		g.why = fmt.Sprintf("the host answered %d probes alike (%d %s), each as its canary: a gate before every route (a login, a device or app header); "+
			"verify it as a role (-role) or with the app's headers", g.n, sig.Status, sig.Type)
	}
}

func (v *verifier) one(ctx context.Context, d Draft) Result {
	r := Result{ID: d.ID, Source: d.Source, Method: d.Method, Path: d.Path, Confidence: d.Confidence, Tier: d.Tier}
	if why := v.preSkip(d); why != "" {
		r.Verdict, r.Reason = Skipped, why
		return r
	}
	targets, bases := []string{d.URL}, []string{""}
	if d.URL == "" {
		targets, bases = d.Candidates, d.CandidateBases
	}
	// Each candidate in turn, to the first that answers as a route; one
	// the policy will not send (a base under /auth) is passed over, not
	// the end of the line (POL-23-1).
	speculative := d.URL == "" && len(targets) > 1
	var best *Result
	probedAny := false
	for i, t := range targets {
		u, err := url.Parse(t)
		if err != nil || !v.o.InScope(u.Hostname()) {
			if best == nil {
				r.Verdict, r.Reason = Skipped, "out_of_scope"
			}
			continue
		}
		candBase := ""
		if i < len(bases) {
			candBase = bases[i]
		}
		if speculative && candBase != "" && v.isSpecBasePruned(candBase) {
			// Always probe at least one candidate per draft so no draft is skipped
			// solely due to speculative base pruning when all candidates were pruned.
			if probedAny || i < len(targets)-1 {
				continue
			}
		}
		probedAny = true
		res := v.probe(ctx, d, t)
		res.ID, res.Source, res.Method, res.Path, res.Confidence, res.Tier = r.ID, r.Source, r.Method, r.Path, r.Confidence, r.Tier
		if speculative && candBase != "" {
			v.noteSpecBase(candBase, d.Path, res.Verdict)
		}
		if (res.Verdict == Alive || res.Verdict == Resource404) && candBase != "" {
			res.VerifiedBase = candBase
		}
		switch {
		case res.Verdict == Alive || res.Verdict == Resource404:
			return res
		case res.Verdict == Skipped:
			if best == nil && (r.Verdict == "" || r.Verdict == Skipped && r.Reason == "out_of_scope") {
				r = res // what is said of the line if no candidate is sent
			}
		case best == nil || verdictRank[res.Verdict] > verdictRank[best.Verdict]:
			b := res
			best = &b
		}
		if errors.Is(ctx.Err(), context.Canceled) || v.o.Sender.Stopped() != "" {
			break
		}
	}
	if best != nil {
		return *best
	}
	return r
}

// preSkip says why a draft is not sent at all, "" when it may be.
func (v *verifier) preSkip(d Draft) string {
	switch {
	case d.ThirdParty:
		return "out_of_scope"
	case d.SourceOnly && !v.o.IncludeSourceOnly:
		return "source_only (use -include-source-only to probe)"
	case d.Confidence == "string" && d.Method == "" && !v.o.IncludeStrings:
		return "bare string (use -include-strings to probe)"
	case d.Confidence == "doc" && !v.o.IncludeDocs:
		return "a document's line (-include-docs)"
	case d.URL == "" && len(d.Candidates) == 0:
		return "no URL: " + d.Why
	}
	return ""
}

// sendPlan is the method a draft goes to target with, or why it is not
// sent there: the policy's word (never, not read either) or a
// destructive URL.
func (v *verifier) sendPlan(d Draft, target string) (method, why string) {
	if d.GraphQLWrite && !v.o.AllowWrite {
		return "", "graphql mutation/subscription (use -allow-write to probe)"
	}
	method = d.Method
	if method == "" {
		method = "GET" // no method known: a read says whether it is there
	}
	real := traffic.Entry{Method: method, URL: target, Body: traffic.Body{Body: string(d.Body)},
		Headers: map[string]string{"content-type": "application/json"}}
	read := traffic.Entry{Method: "GET", URL: target}
	switch dec := v.o.Policy.Classify(real, false); {
	case dec.Kind == replay.Never:
		return "", "never sent: " + dec.Reason
	case dec.Kind == replay.Read && (method == "GET" || method == "HEAD" || dec.Reason == "a GraphQL query"):
	case v.o.AllowWrite && (dec.Kind == replay.Write || dec.Kind == replay.Read):
	default:
		// A write, and no -allow-write (or a destructive one, never): the
		// path is read instead, which changes nothing; a router that
		// knows the route says so (405 and its Allow, a 401 the canary
		// does not get).
		if rd := v.o.Policy.Classify(read, false); rd.Kind != replay.Read {
			return "", "not read either: " + rd.Reason
		}
		method = "GET"
	}
	if guard.Destructive(target) {
		return "", "a destructive URL"
	}
	return method, ""
}

// firstTarget is the URL a draft is sent to first: its own, or the first
// candidate in scope the policy sends; "" when none is.
func (v *verifier) firstTarget(d Draft) string {
	if v.preSkip(d) != "" {
		return ""
	}
	targets := []string{d.URL}
	if d.URL == "" {
		targets = d.Candidates
	}
	for _, t := range targets {
		if u, err := url.Parse(t); err == nil && v.o.InScope(u.Hostname()) {
			if _, why := v.sendPlan(d, t); why == "" {
				return t
			}
		}
	}
	return ""
}

// probeOrder is the order the drafts are sent in (round 25J): a host's
// gateway prefixes taken in turn (one draft of each, then the next of
// each), so that a gate before every route shows on several prefixes
// within a few probes, not after the whole of the first service. Drafts
// not sent keep their place at the front. Deterministic: groups in the
// order they first appear, drafts in their order within a group. It also
// counts each host's prefixes, among the drafts that are sent.
func (v *verifier) probeOrder(ds []Draft) []int {
	var front []int
	groups := map[string][]int{}
	var keys []string
	for i, d := range ds {
		t := v.firstTarget(d)
		if t == "" {
			front = append(front, i)
			continue
		}
		origin, prefix := GatewayPrefix(t)
		k := origin + prefix
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
			v.hostPrefixes[hostOf(t)]++
		}
		groups[k] = append(groups[k], i)
	}
	out := front
	for round := 0; ; round++ {
		took := false
		for _, k := range keys {
			if round < len(groups[k]) {
				out = append(out, groups[k][round])
				took = true
			}
		}
		if !took {
			return out
		}
	}
}

// probe sends one draft to one URL (or the read that stands for a write),
// after its prefix's canary.
func (v *verifier) probe(ctx context.Context, d Draft, target string) Result {
	r := Result{URL: target}
	sendMethod, why := v.sendPlan(d, target)
	if why != "" {
		r.Verdict, r.Reason = Skipped, why
		return r
	}
	r.Sent = sendMethod
	sd := d
	sd.Method = sendMethod
	if sendMethod != d.Method {
		sd.Body = nil
	}
	raw, err := sd.raw(target, v.o.Identity == nil)
	if err != nil {
		r.Verdict, r.Reason = Skipped, err.Error()
		return r
	}
	// Bounded in-flight per host (1 by default, -host-inflight N when opted in).
	unlock, ok := v.acquireHost(ctx, hostOf(target))
	if !ok {
		r.Verdict, r.Reason = Unreachable, ctx.Err().Error()
		return r
	}
	defer unlock()
	if why := v.hostGateWhy(hostOf(target)); why != "" {
		r.Verdict, r.Reason = HostGated, why
		return r
	}
	if why := v.o.Sender.BlockedHosts()[hostOf(target)]; why != "" {
		// Given up: no canary either (it would only log a refusal).
		r.Verdict, r.Reason = HostBlocked, "not sent: the host was given up: "+why
		return r
	}
	c := v.canary(ctx, d, target)
	r.Prefix = c.Prefix
	ans, err := v.send(ctx, raw, target, "verify", d.ID)
	if errors.Is(err, replay.ErrHostBlocked) {
		r.Verdict, r.Reason = HostBlocked, err.Error()
		return r
	}
	if err != nil {
		r.Verdict, r.Reason = Unreachable, err.Error()
		return r
	}
	if v.o.Sender.DryRun() {
		r.Verdict = Planned
		return r
	}
	if ans.Err != "" {
		r.Verdict, r.Reason = Unreachable, ans.Err
		return r
	}
	if ans.Block != nil {
		// The vendor's page, not the route's: an alive 403 it is not.
		r.Verdict, r.Reason = WAFBlocked, ans.Block.String()
		if why := v.o.Sender.BlockedHosts()[hostOf(target)]; why != "" {
			r.Reason += "; the host was given up: " + why
		}
		return r
	}
	sig := SigOf(ans.Status, ans.Header, ans.Body)
	r.Answer = &sig
	if ans.Status >= 200 && ans.Status < 400 {
		r.AuthFlows, _ = endpoints.ExtractAuthFlows(target, ans.Status, ans.Header, ans.Body)
	}
	v.judge(ctx, &r, d, sig, ans.Body, c, raw, target)
	v.noteGate(hostOf(target), sig, &r, c.Answer != nil && Same(sig, *c.Answer))
	return r
}

// judge sets a verdict from an answer and the canary of its prefix.
func (v *verifier) judge(ctx context.Context, r *Result, d Draft, sig Sig, body []byte, c *Canary, raw []byte, target string) {
	same := c.Answer != nil && Same(sig, *c.Answer)
	st := sig.Status
	switch {
	case same && (st == 401 || st == 403):
		// The prefix answers so to any path: its OPTIONS may still tell
		// the route from none.
		opt := v.options(ctx, raw, target, d.ID)
		co := v.canaryOptions(ctx, d, c)
		if opt != nil && co != nil && (opt.Status != co.Status || !strings.EqualFold(opt.Allow, co.Allow)) {
			// Defense in depth: if OPTIONS on the endpoint merely echoed the exact same
			// 401/403 auth-wall signature as GET with no Allow header while the canary redirected,
			// that is still the auth wall, not proof of the route.
			if !(Same(*opt, sig) && opt.Allow == "" && co.Status >= 300 && co.Status < 400) {
				r.Verdict, r.Reason = Alive, "behind the prefix's auth wall, its OPTIONS differs from the canary's"
				if opt.Allow != "" {
					r.VerifiedMethod = methodFrom(opt.Allow, d.Method)
				}
				return
			}
		}
		r.Verdict, r.Reason = AuthWall, "the prefix answers "+fmt.Sprint(st)+" to any path: run again with a role that is logged in"
	case same && r.Sent != d.Method && d.Method != "" && (st == 404 || st == 405) && c.Answer != nil && c.Answer.MethodScoped:
		// ENH-02: a write endpoint probed via read-only GET on a router that
		// matches (method, path) (Express HTML or NestJS/Fastify JSON "Cannot GET …", or 405).
		opt := v.options(ctx, raw, target, d.ID)
		co := v.canaryOptions(ctx, d, c)
		if opt != nil && co != nil && (opt.Status != co.Status || !strings.EqualFold(opt.Allow, co.Allow)) {
			r.Verdict, r.Reason = Alive, "OPTIONS differs from the canary's"
			if opt.Allow != "" {
				r.VerifiedMethod = methodFrom(opt.Allow, d.Method)
			}
			return
		}
		r.Verdict = WriteUnverified
		r.Reason = fmt.Sprintf("GET matched the %d canary; %s requires -allow-write to verify", st, d.Method)
	case same && d.Confidence == "string" && d.Method == "" && c.Answer != nil && c.Answer.Status == 200 && strings.Contains(c.Answer.Type, "html"):
		r.Verdict, r.Reason = ClientRoute, "bare string answered with the SPA's shell"
	case same:
		r.Verdict, r.Reason = DeadOrFP, "answers as any path does (the canary)"
	case st >= 200 && st < 300:
		if sig.Shell != "" && strings.Contains(sig.Type, "html") {
			if c.Answer != nil && sameHTMLShellBody(*c.Answer, sig) {
				if d.Confidence == "string" && d.Method == "" {
					r.Verdict, r.Reason = ClientRoute, "bare string answered 2xx with the canary's HTML shell"
				} else {
					r.Verdict, r.Reason = DeadOrFP, "answers 2xx with the same HTML shell as the canary"
				}
				break
			}
			if !v.matchesKnownHTMLShell(hostOf(target), sig) {
				// An HTML page no canary has shown yet, under a prefix of
				// its own: the origin's root may answer every path with it
				// (an SPA's fallback). Asked once per origin, at any
				// -host-inflight, so that the verdict is the same at all
				// of them (round 37.1, C2).
				if origin, _ := GatewayPrefix(target); origin != "" && c.Prefix != origin+"/" {
					v.rootCanary(ctx, d, origin)
				}
			}
			if v.matchesKnownHTMLShell(hostOf(target), sig) {
				if d.Confidence == "string" && d.Method == "" {
					r.Verdict, r.Reason = ClientRoute, "bare string answered with a catch-all HTML shell"
				} else {
					r.Verdict, r.Reason = DeadOrFP, "answers with a catch-all/WAF HTML shell seen on canaries"
				}
				break
			}
			if subOrigin, subPrefix := subCanaryPrefix(target, c.Prefix); subPrefix != "" {
				sc := v.subCanary(ctx, d, subOrigin, subPrefix)
				if sc != nil && sc.Answer != nil {
					scMatch := Same(sig, *sc.Answer)
					if strings.Contains(sig.Type, "html") && (sig.Shell != "" || sc.Answer.Shell != "") {
						scMatch = sameHTMLShell(*sc.Answer, sig)
					}
					if scMatch {
						r.Prefix = sc.Prefix
						r.Verdict, r.Reason = DeadOrFP, "answers as any path under "+subPrefix+" does (the sub-canary)"
						break
					}
				}
			}
		}
		r.Verdict = Alive
	case st == 405:
		r.Verdict, r.Reason = Alive, "405: the route is there, for another method"
		r.VerifiedMethod = methodFrom(sig.Allow, d.Method)
	case st == 400 || st == 415 || st == 422:
		r.Verdict = Alive
		r.ServerMissing = MissingParams(body)
	case st == 401 || st == 403:
		r.Verdict, r.Reason = Alive, "an auth guard the canary does not meet"
	case st == 404:
		r.Verdict, r.Reason = Resource404, "a 404 of its own, not the router's (the canary's)"
	case st >= 500:
		r.Verdict = ServerError
	case st >= 300 && st < 400:
		r.Verdict, r.Reason = Alive, "a redirect the canary does not get"
	default:
		r.Verdict = Alive
	}
	if r.VerifiedMethod == "" && r.Verdict == Alive && r.Sent == d.Method {
		r.VerifiedMethod = d.Method
	}
}

// rejudgeShells judges again, with every canary's shell now known, the 2xx
// HTML answers that were judged routes (round 37.1, C1). judge tells a
// catch-all shell by the shells the canaries asked so far showed; which
// had been asked when depended on the order the probes ran in (the hosts
// run at once, and so do a host's probes with -host-inflight). The rule is
// judge's own first one for a 2xx HTML answer, so this is the verdict judge
// would have given knowing them all: it sends nothing, it only ever turns
// a route into a catch-all (never the other way), and the result is the
// same whatever the order or the concurrency.
func (v *verifier) rejudgeShells(ds []Draft, results []*Result) {
	for i, r := range results {
		if r == nil || r.Verdict != Alive || r.Answer == nil {
			continue
		}
		sig := *r.Answer
		if sig.Status < 200 || sig.Status >= 300 || sig.Shell == "" || !strings.Contains(sig.Type, "html") || r.URL == "" {
			continue
		}
		if !v.matchesKnownHTMLShell(hostOf(r.URL), sig) {
			continue
		}
		d := ds[i]
		if d.Confidence == "string" && d.Method == "" {
			r.Verdict, r.Reason = ClientRoute, "bare string answered with a catch-all HTML shell (judged again with every canary known)"
		} else {
			r.Verdict, r.Reason = DeadOrFP, "answers with a catch-all/WAF HTML shell seen on canaries (judged again with every canary known)"
		}
		r.VerifiedMethod = ""
		r.VerifiedBase = ""
	}
}

// methodFrom is the method an Allow header confirms: the line's, when it
// lists it, else what it lists.
func methodFrom(allow, method string) string {
	var ms []string
	for _, m := range strings.Split(allow, ",") {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			ms = append(ms, m)
		}
	}
	if method != "" && slices.Contains(ms, method) {
		return method
	}
	return strings.Join(ms, ",")
}

func (v *verifier) send(ctx context.Context, raw []byte, target, purpose, item string) (replay.Answer, error) {
	if v.o.Identity != nil {
		raw, _ = replay.Apply(raw, v.o.Identity, target, nil)
	}
	u, _ := url.Parse(target)
	h := hostOf(target)
	return v.o.Sender.Send(ctx, raw, u.Scheme, purpose, v.o.Role, item, func(line *replay.Sent) {
		if line.Status == 429 || (line.Block != nil && line.Block.Kind == replay.BlockRate) {
			v.stepDownHost(h)
		}
	})
}

// GatewayPrefix is a URL's first fixed path segments, two at most and
// never all of them: /hub/auth of /hub/auth/v1/token, / of /health.
func GatewayPrefix(rawURL string) (origin, prefix string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "/"
	}
	origin = u.Scheme + "://" + u.Host
	segs := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	var keep []string
	for i, s := range segs {
		if i == 2 || i == len(segs)-1 || s == "" || s == sampleUUID || s == "sample-item" || isNumber(s) {
			break
		}
		keep = append(keep, s)
	}
	return origin, "/" + strings.Join(keep, "/")
}

func isNumber(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// canaryHeaderKey distinguishes canaries on the same prefix whose drafts carry
// different non-identity request headers (e.g. X-Requested-With: XMLHttpRequest),
// since gateways often switch between 302 login redirect and 401 JSON on them.
func canaryHeaderKey(d Draft, bare bool) string {
	var parts []string
	for _, h := range d.Headers {
		if bare && slices.ContainsFunc(d.SampleHeaders, func(n string) bool { return strings.EqualFold(n, h[0]) }) {
			continue
		}
		n := strings.ToLower(strings.TrimSpace(h[0]))
		if n == "" || n == "user-agent" || n == "accept" || n == "host" || n == "content-type" || n == "content-length" {
			continue
		}
		parts = append(parts, n+":"+h[1])
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// canary is the answer of the target's prefix to a path that cannot exist,
// asked once (with singleflight synchronization when -host-inflight > 1).
func (v *verifier) canary(ctx context.Context, d Draft, target string) *Canary {
	c, cu, key := v.canaryFor(d, target)
	if cu == "" {
		if c.ready != nil {
			select {
			case <-c.ready:
			case <-ctx.Done():
			}
		}
		return c
	}
	defer close(c.ready)
	cd := Draft{ID: "canary", Method: "GET", Headers: d.Headers, SampleHeaders: d.SampleHeaders}
	raw, err := cd.raw(cu, v.o.Identity == nil)
	if err != nil {
		c.Err = err.Error()
		return c
	}
	ans, err := v.send(ctx, raw, cu, "canary", key)
	return v.canaryAnswer(c, ans, err)
}

// rootCanary asks the origin's root for a path that cannot exist, once (the
// other probes wait for its answer), to learn the HTML shell an SPA answers
// every path with. It is not one of -max-prefixes' canaries: it does not
// count toward the origin's prefixes until a draft of the root prefix
// itself uses it (canaryFor), so that the fallback of later prefixes is
// what it was without it (round 37.1, C2).
func (v *verifier) rootCanary(ctx context.Context, d Draft, origin string) {
	key := origin + "/"
	ck := key
	if hk := canaryHeaderKey(d, v.o.Identity == nil); hk != "" {
		ck += "\x00" + hk
	}
	v.mu.Lock()
	if c := v.canaries[ck]; c != nil {
		v.mu.Unlock()
		if c.ready != nil {
			select {
			case <-c.ready:
			case <-ctx.Done():
			}
		}
		return
	}
	cu := strings.TrimRight(key, "/") + "/" + marker.Slug()
	c := &Canary{Prefix: key, URL: cu, ready: make(chan struct{}), uncounted: true}
	v.canaries[ck] = c
	v.mu.Unlock()
	defer close(c.ready)
	cd := Draft{ID: "canary", Method: "GET", Headers: d.Headers, SampleHeaders: d.SampleHeaders}
	raw, err := cd.raw(cu, v.o.Identity == nil)
	if err != nil {
		c.Err = err.Error()
		return
	}
	ans, err := v.send(ctx, raw, cu, "canary", key)
	v.canaryAnswer(c, ans, err)
}

// claimCanary is a cache hit of canaryFor, under v.mu: a canary rootCanary
// asked counts toward the origin's prefixes when a draft first uses it.
func (v *verifier) claimCanary(c *Canary, origin string) {
	c.Drafts++
	if c.uncounted {
		c.uncounted = false
		v.perOrigin[origin]++
	}
}

// canaryFor is the canary a target is judged against: one already asked
// (cu ""), or a new one to ask at cu. Under v.mu: the canaries are every
// host's (verify -concurrency).
func (v *verifier) canaryFor(d Draft, target string) (c *Canary, cu, key string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	origin, prefix := GatewayPrefix(target)
	key = origin + prefix
	hk := canaryHeaderKey(d, v.o.Identity == nil)
	cacheKey := func(p string) string {
		if hk == "" {
			return p
		}
		return p + "\x00" + hk
	}
	if c := v.canaries[cacheKey(key)]; c != nil {
		v.claimCanary(c, origin)
		return c, "", key
	}
	limit := v.o.MaxPrefixes
	if limit > 0 && v.perOrigin[origin] >= limit && prefix != "/" {
		// ENH-13: fall back to the 1-segment parent (/chat of /chat/tools)
		// before falling all the way back to origin root /. The parent is
		// asked when no canary has it yet, within a budget of its own: a
		// gateway's 13th service judged against / (an SPA's 200 shell)
		// read every gateway refusal as a route (observed 14
		// false verified_alive; round 25I review).
		fellBack := false
		if rest := strings.TrimPrefix(prefix, "/"); strings.Contains(rest, "/") {
			seg, _, _ := strings.Cut(rest, "/")
			if c := v.canaries[cacheKey(origin+"/"+seg)]; c != nil {
				v.claimCanary(c, origin)
				return c, "", key
			}
			if v.parents[origin] < limit {
				v.parents[origin]++
				prefix, key, fellBack = "/"+seg, origin+"/"+seg, true
			}
		}
		if !fellBack {
			prefix = "/"
			key = origin + prefix
			if c := v.canaries[cacheKey(key)]; c != nil {
				v.claimCanary(c, origin)
				return c, "", key
			}
		}
	}
	v.perOrigin[origin]++
	cu = strings.TrimRight(origin+prefix, "/") + "/" + marker.Slug()
	c = &Canary{Prefix: key, URL: cu, Drafts: 1, ready: make(chan struct{})}
	v.canaries[cacheKey(key)] = c
	return c, cu, key
}

// canaryAnswer notes a canary's answer.
func (v *verifier) canaryAnswer(c *Canary, ans replay.Answer, err error) *Canary {
	switch {
	case err != nil:
		c.Err = err.Error()
	case ans.Err != "":
		c.Err = ans.Err
	case ans.Block != nil:
		// A vendor's page is no baseline of the prefix's router, though if it is
		// a 2xx HTML WAF template we record its exact Shell across the RDN.
		c.Err = "blocked: " + ans.Block.String()
		if ans.Status >= 200 && ans.Status < 300 {
			s := SigOf(ans.Status, ans.Header, ans.Body)
			if s.Shell != "" && strings.Contains(s.Type, "html") {
				v.recordHTMLShell(hostOf(c.URL), s, true)
			}
		}
	default:
		s := SigOf(ans.Status, ans.Header, ans.Body)
		c.Answer = &s
		if s.Status >= 200 && s.Status < 300 && s.Shell != "" && strings.Contains(s.Type, "html") {
			v.recordHTMLShell(hostOf(c.URL), s, false)
		}
	}
	return c
}

func sameHTMLShellBody(ex, s Sig) bool {
	if !strings.Contains(ex.Type, "html") || !strings.Contains(s.Type, "html") || s.Shell == "" || ex.Shell != s.Shell {
		return false
	}
	lo, hi := min(ex.Words, s.Words), max(ex.Words, s.Words)
	return hi == 0 || float64(hi-lo) <= 0.25*float64(hi) || (hi <= 45 && hi-lo <= 15)
}

func sameHTMLShell(ex, s Sig) bool {
	return ex.Status == s.Status && sameHTMLShellBody(ex, s)
}

func (v *verifier) recordHTMLShell(host string, s Sig, isWAF bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	add := func(key string) {
		for _, ex := range v.htmlShells[key] {
			if sameHTMLShell(ex, s) {
				return
			}
		}
		v.htmlShells[key] = append(v.htmlShells[key], s)
	}
	if host != "" {
		add(host)
		if v.shellHosts[s.Shell] == nil {
			v.shellHosts[s.Shell] = map[string]bool{}
		}
		v.shellHosts[s.Shell][host] = true
	}
	// Promote to RDN-wide "*" only when confirmed by WAF detection or observed
	// across >= 2 distinct canary hosts in the same run.
	if isWAF || len(v.shellHosts[s.Shell]) >= 2 {
		add("*")
	}
}

func (v *verifier) matchesKnownHTMLShell(host string, s Sig) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, ex := range v.htmlShells[host] {
		if sameHTMLShell(ex, s) {
			return true
		}
	}
	for _, ex := range v.htmlShells["*"] {
		if sameHTMLShell(ex, s) {
			return true
		}
	}
	return false
}

var sensitiveSubSegs = map[string]bool{
	"admin": true, "internal": true, "manage": true, "management": true,
	"console": true, "actuator": true, "debug": true, "private": true, "backoffice": true,
}

func subCanaryPrefix(target, baseKey string) (origin, prefix string) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "", ""
	}
	origin = u.Scheme + "://" + u.Host
	segs := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(segs) <= 3 {
		return "", ""
	}
	// Scan segments deeper than the 2-segment GatewayPrefix (excluding the leaf)
	// for a sensitive sub-router/WAF boundary like /api/applications/admin/*.
	for i := 2; i < len(segs)-1; i++ {
		if sensitiveSubSegs[strings.ToLower(segs[i])] {
			sub := "/" + strings.Join(segs[:i+1], "/")
			if origin+sub != baseKey {
				return origin, sub
			}
		}
	}
	return "", ""
}

func (v *verifier) subCanary(ctx context.Context, d Draft, origin, subPrefix string) *Canary {
	key := origin + subPrefix
	hk := canaryHeaderKey(d, v.o.Identity == nil)
	ck := key
	if hk != "" {
		ck += "\x00" + hk
	}
	v.mu.Lock()
	if c := v.canaries[ck]; c != nil {
		c.Drafts++
		v.mu.Unlock()
		if c.ready != nil {
			select {
			case <-c.ready:
			case <-ctx.Done():
			}
		}
		return c
	}
	cu := strings.TrimRight(key, "/") + "/" + marker.Slug()
	c := &Canary{Prefix: key, URL: cu, Drafts: 1, ready: make(chan struct{})}
	v.canaries[ck] = c
	v.mu.Unlock()

	defer close(c.ready)
	cd := Draft{ID: "canary", Method: "GET", Headers: d.Headers, SampleHeaders: d.SampleHeaders}
	raw, err := cd.raw(cu, v.o.Identity == nil)
	if err != nil {
		c.Err = err.Error()
		return c
	}
	ans, err := v.send(ctx, raw, cu, "canary", key)
	return v.canaryAnswer(c, ans, err)
}

// options is an OPTIONS of a request's URL, as it was (its headers).
func (v *verifier) options(ctx context.Context, raw []byte, target, item string) *Sig {
	line, rest, ok := bytes.Cut(raw, []byte("\r\n"))
	if !ok {
		return nil
	}
	_, after, _ := bytes.Cut(line, []byte(" "))
	head, _, _ := bytes.Cut(rest, []byte("\r\n\r\n"))
	var kept []string
	for _, l := range strings.Split(string(head), "\r\n") {
		n, _, _ := strings.Cut(l, ":")
		if n = strings.ToLower(strings.TrimSpace(n)); n != "content-length" && n != "content-type" && l != "" {
			kept = append(kept, l)
		}
	}
	opt := []byte("OPTIONS " + string(after) + "\r\n" + strings.Join(kept, "\r\n") + "\r\n\r\n")
	ans, err := v.send(ctx, opt, target, "options", item)
	if err != nil || ans.Err != "" || ans.Block != nil {
		return nil
	}
	s := SigOf(ans.Status, ans.Header, ans.Body)
	return &s
}

func (v *verifier) canaryOptions(ctx context.Context, d Draft, c *Canary) *Sig {
	if c == nil || c.Err != "" {
		return nil
	}
	c.optOnce.Do(func() {
		if c.Options != nil {
			return
		}
		cd := Draft{ID: "canary", Method: "GET", Headers: d.Headers, SampleHeaders: d.SampleHeaders}
		raw, err := cd.raw(c.URL, v.o.Identity == nil)
		if err != nil {
			return
		}
		c.Options = v.options(ctx, raw, c.URL, c.Prefix)
	})
	return c.Options
}

// AliveKeys reads a verification's verdicts: the drafts' keys (method
// path) that answered as routes, and the URL each answered at.
func AliveKeys(verifyDir string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(verifyDir, "verify.json"))
	if err != nil {
		return out
	}
	var rep Report
	if json.Unmarshal(b, &rep) != nil {
		return out
	}
	for _, r := range rep.Results {
		if r.Verdict == Alive || r.Verdict == Resource404 {
			out[r.Method+" "+r.Path] = r.URL
		}
	}
	return out
}

// Write writes verify.json and verify.md (0600, in a 0700 directory).
func Write(dir string, rep *Report) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	os.Chmod(dir, 0o700)
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "verify.json"), append(b, '\n')); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, "verify.md"), []byte(Markdown(rep)))
}

func writeFile(p string, b []byte) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Markdown is verify.md: the counts, the canaries, the routes alive.
func Markdown(rep *Report) string {
	var b strings.Builder
	mode := "sent"
	if rep.DryRun {
		mode = "dry run: nothing sent, the plan below"
	}
	fmt.Fprintf(&b, "# jsharvest verify: %s (%s)\n\n%s; %d request(s)", mdsafe.InlineText(rep.Target), mdsafe.InlineText(rep.Role), mode, rep.Sent)
	if rep.Stopped != "" {
		fmt.Fprintf(&b, "; stopped: %s", mdsafe.InlineText(rep.Stopped))
	}
	b.WriteString("\n\n")
	for _, h := range slices.Sorted(mapsKeys(rep.HostsGated)) {
		fmt.Fprintf(&b, "**Host gated:** %s: %s. Its other drafts are `host_gated`.\n\n", mdsafe.InlineText(h), mdsafe.InlineText(rep.HostsGated[h]))
	}
	for _, h := range slices.Sorted(mapsKeys(rep.HostsBlocked)) {
		fmt.Fprintf(&b, "**Host given up:** %s: %s. Its drafts after that are `host_blocked`.\n\n", mdsafe.InlineText(h), mdsafe.InlineText(rep.HostsBlocked[h]))
	}
	counts := func(title string, m map[string]int) {
		fmt.Fprintf(&b, "## %s\n\n| | |\n|---|---|\n", title)
		for _, k := range slices.Sorted(mapsKeys(m)) {
			fmt.Fprintf(&b, "| %s | %d |\n", mdsafe.TableText(k), m[k])
		}
		b.WriteString("\n")
	}
	counts("Verdicts", rep.Verdicts)
	counts("Tiers", rep.Tiers)
	counts("Confidence", rep.Confidence)
	fmt.Fprintf(&b, "## Canaries (gateway prefixes)\n\n| prefix | drafts | answer |\n|---|---|---|\n")
	for _, c := range rep.Canaries {
		a := c.Err
		if c.Answer != nil {
			a = c.Answer.String()
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", mdsafe.TableText(c.Prefix), c.Drafts, mdsafe.TableText(a))
	}
	b.WriteString("\n## Results\n\n| verdict | method | URL | note |\n|---|---|---|---|\n")
	rs := slices.Clone(rep.Results)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Verdict < rs[j].Verdict })
	for _, r := range rs {
		note := r.Reason
		if r.Sent != "" && r.Sent != r.Method && r.Method != "" {
			note += " (probed via " + r.Sent + ")"
		}
		if r.VerifiedMethod != "" {
			note += " method " + r.VerifiedMethod
		}
		if len(r.ServerMissing) > 0 {
			note += " missing " + strings.Join(r.ServerMissing, ",")
		}
		u := r.URL
		if u == "" {
			u = r.Path
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			mdsafe.TableText(string(r.Verdict)),
			mdsafe.TableText(r.Method),
			mdsafe.TableText(u),
			mdsafe.TableText(strings.TrimSpace(note)))
	}
	if len(rep.CloudChecks) > 0 {
		b.WriteString("\n## Cloud Storage Checks\n\n| status | provider | bucket | URL |\n|---|---|---|---|\n")
		for _, c := range rep.CloudChecks {
			st := c.Status
			if st == "" && c.Error != "" {
				st = "error"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				mdsafe.TableText(st),
				mdsafe.TableText(c.Provider),
				mdsafe.TableText(c.Bucket),
				mdsafe.TableText(c.URL))
		}
	}
	return b.String()
}

// hostOf is a URL's host:port, as the Sender keys its hosts.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// byHost verifies the hosts at once, o.Concurrency of them, each host's
// drafts in turn in probeOrder's order (round 25K): what one worker sends
// a host is what a run of one sends it, in the same order. A draft whose
// candidates span hosts is the first one's, and holds each other host it
// tries for its probe (lockHost).
func (v *verifier) byHost(ctx context.Context, order []int, results []*Result) {
	if v.hostMaxInFlight() > 1 {
		var sendOrder []int
		for _, i := range order {
			if v.firstTarget(v.o.Drafts[i]) == "" {
				r := v.one(ctx, v.o.Drafts[i])
				results[i] = &r
				continue
			}
			sendOrder = append(sendOrder, i)
		}
		if len(sendOrder) == 0 {
			return
		}
		ch := make(chan int, len(sendOrder))
		for _, i := range sendOrder {
			ch <- i
		}
		close(ch)
		var wg sync.WaitGroup
		for range min(v.o.Concurrency, len(sendOrder)) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range ch {
					if ctx.Err() != nil {
						return
					}
					r := v.one(ctx, v.o.Drafts[i])
					results[i] = &r
				}
			}()
		}
		wg.Wait()
		return
	}

	queues := map[string][]int{}
	var hosts []string
	for _, i := range order {
		t := v.firstTarget(v.o.Drafts[i])
		if t == "" {
			// Not sent: said at once, no request.
			r := v.one(ctx, v.o.Drafts[i])
			results[i] = &r
			continue
		}
		h := hostOf(t)
		if _, ok := queues[h]; !ok {
			hosts = append(hosts, h)
		}
		queues[h] = append(queues[h], i)
	}
	next := make(chan string)
	var wg sync.WaitGroup
	for range min(v.o.Concurrency, len(hosts)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range next {
				for _, i := range queues[h] {
					if ctx.Err() != nil {
						break
					}
					r := v.one(ctx, v.o.Drafts[i])
					results[i] = &r
				}
			}
		}()
	}
	for _, h := range hosts {
		next <- h
	}
	close(next)
	wg.Wait()
}
