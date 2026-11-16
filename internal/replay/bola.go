package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// BolaOptions configure a run of authz -peers (docs/gd7-bola-design.md).
type BolaOptions struct {
	Root     string // <out>/<host>
	Profiles string // <profiles>/<host>: the peers' login snapshots
	Peers    [2]string
	Relation Relation
	// Private marks the endpoints (by URL or key) whose data is private to a
	// person even inside an org (same-org: shared becomes bypass).
	Private *regexp.Regexp
	// Substitute: for an endpoint with two ids or more, a refusal at the
	// parent is tried again with each id alone put in B's own request.
	Substitute bool
	// AllowWrite lets writes be tried, as blind writes: nothing proves whose
	// object they changed.
	AllowWrite bool
	// Reveal writes the proof's values as they are (else REDACTED_<hash>).
	Reveal  bool
	Policy  Policy
	Sender  *Sender
	InScope func(host string) bool
	Out     string // <root>/authz
	Now     time.Time
}

// BolaReport is bola.json.
type BolaReport struct {
	Host             string            `json:"host"`
	Peers            [2]string         `json:"peers"`
	Relation         Relation          `json:"relation"`
	Substitute       bool              `json:"substitute,omitempty"`
	AllowWrite       bool              `json:"allow_write,omitempty"`
	AnonLoaded       bool              `json:"anon_loaded"`
	Redacted         bool              `json:"redacted"`
	Generated        time.Time         `json:"generated"`
	Sent             int               `json:"sent"`
	Stopped          string            `json:"stopped,omitempty"`
	HostsBlocked     map[string]string `json:"hosts_blocked,omitempty"`
	StoppedEndpoints map[string]string `json:"stopped_endpoints,omitempty"`
	Notes            []string          `json:"notes,omitempty"`
	Summary          map[string]int    `json:"summary"`
	Items            []PeerItem        `json:"items"`
}

// PeerItem is one trial: the request of Owner, sent under As's identity.
type PeerItem struct {
	Key         string        `json:"key"`       // METHOD host/template [operation]
	Direction   string        `json:"direction"` // owner->as
	Owner       string        `json:"owner"`
	As          string        `json:"as"`
	Mode        string        `json:"mode"` // main | substitute:<place>
	Request     Ref           `json:"sample_request"`
	SelfRequest *Ref          `json:"self_request,omitempty"`
	Kind        Kind          `json:"kind"`
	Why         string        `json:"kind_reason,omitempty"`
	IDs         []CandidateID `json:"ids"`
	Judgement
	Evidence    []EvidencePair `json:"evidence,omitempty"`
	Private     string         `json:"private,omitempty"`
	Trial       *Brief         `json:"trial,omitempty"`
	Control     *Brief         `json:"control,omitempty"`
	Reference   *RefBrief      `json:"reference,omitempty"`
	NoIdentity  *Brief         `json:"no_identity,omitempty"`
	File        string         `json:"file,omitempty"`
	KeptHeaders []string       `json:"kept_headers,omitempty"`
	Refreshed   []string       `json:"refreshed,omitempty"`
	Stale       []string       `json:"stale,omitempty"`
	Kept        []string       `json:"kept,omitempty"`
	Missing     []string       `json:"missing,omitempty"`
	At          time.Time      `json:"at,omitzero"`

	stop bool // the endpoint was stopped by this item
}

// CandidateID is an identifier B had not seen, in A's request.
type CandidateID struct {
	At        string `json:"at"`
	Kind      IDKind `json:"kind"`
	Value     string `json:"value"`
	RelayType string `json:"relay_type,omitempty"`
	RelayID   string `json:"relay_id,omitempty"`
	Bogus     string `json:"bogus,omitempty"`
}

// RefBrief is what the trial was compared with: B's own request (self) or
// the request with an id that names nothing (bogus).
type RefBrief struct {
	Kind   string `json:"kind"`
	Status int    `json:"status"`
	Size   int    `json:"size"`
}

// peerCtx is one of the two people.
type peerCtx struct {
	*roleCtx
	snap   *session.Snapshot
	seen   *SeenSet // what its responses and anon's show
	idVals []string // its own identifiers
	// noProbe: no request to tell its session lives with.
	noProbe bool
}

type bola struct {
	o     BolaOptions
	a     *authz
	peers [2]*peerCtx
	red   *traffic.Redactor
	rep   *BolaReport
	// aligned are the path places taken as placeholders for the requests of
	// both peers.
	aligned map[*export.Request]map[int]bool
	trialN  int
}

// candidate is the request of an owner that is worth a trial: it carries an
// id the other person has not seen.
type candidate struct {
	r    *export.Request
	key  string
	ids  []ParsedID // the ids B has not seen
	all  []ParsedID
	self *export.Request // B's own request to the same endpoint, nil for none
}

// Bola tries the requests of each of two peers under the other's identity
// and concludes, by what the answer holds that only the owner had, whether
// the server checks who owns the object (docs/gd7-bola-design.md and its
// section 8). It sends requests: authorized targets only.
func Bola(ctx context.Context, o BolaOptions) (*BolaReport, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Relation != RelSameOrg && o.Relation != RelCrossOrg {
		return nil, errors.New("authz -peers: -relation same-org or cross-org is required")
	}
	if o.Peers[0] == "" || o.Peers[1] == "" || o.Peers[0] == o.Peers[1] {
		return nil, errors.New("authz -peers: two different peers are required")
	}
	for _, p := range o.Peers {
		if p == "anon" || p == "archive" {
			return nil, fmt.Errorf("authz -peers: %s is no peer", p)
		}
	}
	b := &bola{o: o, red: traffic.NewRedactor()}
	b.a = &authz{o: AuthzOptions{Policy: o.Policy, AllowWrite: o.AllowWrite, Sender: o.Sender, InScope: o.InScope, Out: o.Out, Now: o.Now},
		out: &AuthzReport{}, peer: true}
	b.rep = &BolaReport{Host: filepath.Base(o.Root), Peers: o.Peers, Relation: o.Relation, Substitute: o.Substitute, AllowWrite: o.AllowWrite,
		Redacted: !o.Reveal, Generated: o.Now.UTC(), Summary: map[string]int{}}

	anon := NewSeenSet()
	if st, err := os.Stat(filepath.Join(o.Root, "anon")); err == nil && st.IsDir() {
		b.rep.AnonLoaded = loadSeen(filepath.Join(o.Root, "anon"), anon) > 0
	}
	if !b.rep.AnonLoaded {
		b.note("anon: no recorded responses (crawl without -role): what a visitor sees is not used to tell public values; the no-identity probe is still sent")
	}
	for i, name := range o.Peers {
		p, err := b.load(name, anon)
		if err != nil {
			return nil, err
		}
		b.peers[i] = p
	}
	b.aligned = alignWildcards(b.peers[0].model, b.peers[1].model)

	type dirWork struct {
		owner, as *peerCtx
		cands     []*candidate
	}
	var work []dirWork
	for i := range 2 {
		owner, as := b.peers[i], b.peers[1-i]
		work = append(work, dirWork{owner, as, b.candidates(owner, as)})
	}
	b.allowHosts(work[0].cands, work[1].cands)
	for _, p := range b.peers {
		b.confirmProbe(ctx, p)
	}
	for _, p := range b.peers {
		if why := p.deadWhy(); why != "" {
			b.note(fmt.Sprintf("%s: its session is dead (%s): run jsharvest login -role %s", p.name, why, p.name))
		} else if p.noProbe && (len(p.id.Creds) > 0 || p.hasCookies()) {
			b.note(p.name + ": no request to check its session with: a refusal under its identity is not concluded as enforced")
		}
	}
	if o.AllowWrite {
		b.note("-allow-write: writes are sent in both directions, as blind writes, to the real data of both peers")
	}

loop:
	for _, w := range work {
		for _, c := range w.cands {
			if o.Sender.Stopped() != "" || ctx.Err() != nil {
				break loop
			}
			items, err := b.tryCandidate(ctx, w.owner, w.as, c)
			if err != nil {
				return nil, err
			}
			b.rep.Items = append(b.rep.Items, items...)
		}
	}
	b.downgrade()
	if s := o.Sender.Stopped(); s != "" {
		b.rep.Stopped = s
	}
	b.rep.HostsBlocked = o.Sender.BlockedHosts()
	b.rep.Sent = o.Sender.Count()
	for _, it := range b.rep.Items {
		b.rep.Summary[string(it.Verdict)]++
	}
	return b.rep, nil
}

func (b *bola) note(s string) { b.rep.Notes = append(b.rep.Notes, s) }

// soft says an error is the run's end or a scope refusal, not a failure of
// the trial.
func soft(err error) bool {
	return errors.Is(err, ErrBudget) || errors.Is(err, errStopped) || errors.Is(err, ErrScope) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// loadSeen puts what a directory's recorded responses show into s, and says
// how many it read.
func loadSeen(dir string, s *SeenSet) int {
	d := results.Open(dir)
	if d.Refresh() != nil {
		return 0
	}
	n := 0
	for _, run := range d.Runs() {
		for _, q := range d.Requests(run) {
			if q.Internal || q.Challenge {
				continue
			}
			e, err := d.Entry(run, q.ID)
			if err != nil || e.Response == nil || e.Response.Status >= 500 || e.Source == "guard" || strings.HasPrefix(e.Outcome, "held_back") {
				continue
			}
			if header(e.Response.Headers, traffic.GuardHeader) != "" || e.Response.BodyOmitted != "" && e.Response.Body.Body == "" {
				continue
			}
			body := e.Response.Body.Body
			if e.Response.Body.BodyBase64 {
				body = ""
			}
			s.AddResponse(e.Response.Headers, body)
			n++
		}
	}
	return n
}

// load reads a peer: its traffic as a model (with the catalog of the code's
// endpoints, so that a path segment the code knows is a placeholder though
// the peer met one value), its login snapshot and identity, what its
// responses show.
func (b *bola) load(name string, anon *SeenSet) (*peerCtx, error) {
	dir := filepath.Join(b.o.Root, name)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("authz -peers: peer %s: no output at %s (crawl it with -role %s)", name, dir, name)
	}
	cat, err := endpoints.Catalog(dir, b.o.InScope, false)
	if err != nil {
		cat = nil
		b.note(fmt.Sprintf("%s: no catalog of the code's endpoints (%v): placeholders come from its requests alone", name, err))
	}
	m, err := export.Load(export.Options{Dir: dir, Run: "all", InScope: b.o.InScope, Catalog: cat, Role: name})
	if err != nil {
		return nil, fmt.Errorf("authz -peers: peer %s: %w", name, err)
	}
	var snap *session.Snapshot
	if b.o.Profiles != "" {
		if s, err := session.Load(filepath.Join(b.o.Profiles, name)); err == nil {
			snap = s
		}
	}
	entries := make([]traffic.Entry, len(m.Requests))
	for i, r := range m.Requests {
		entries[i] = r.Entry
	}
	rc := &roleCtx{name: name, model: m, id: NewIdentity(name, snap, entries, b.o.Now), login: loginTest(snap)}
	for _, n := range rc.id.Notes {
		b.note(name + ": " + n)
	}
	p := &peerCtx{roleCtx: rc, snap: snap, seen: NewSeenSet()}
	loadSeen(dir, p.seen)
	for v := range anon.vals {
		p.seen.vals[v] = struct{}{}
	}
	for v := range anon.kv {
		p.seen.kv[v] = struct{}{}
	}
	resolveStorageCreds(rc.id, snap, entries, b.o.Now, func(s string) { b.note(name + ": " + s) })
	p.idVals = identityValues(m, snap, rc.id)
	if sessionLost(dir) {
		b.note(name + ": its last crawl lost the session (run.json): the tokens in the snapshot may be dead; log in again and crawl")
	}
	for _, c := range jwtLifetimes(rc.id, b.o.Now, time.Duration(b.o.Sender.o.Max)*b.o.Sender.o.Rate) {
		b.note(name + ": " + c)
	}
	return p, nil
}

// sessionLost reads whether the newest run of a role's directory says the
// session was lost.
func sessionLost(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "runs.jsonl"))
	if err != nil {
		return false
	}
	lost := false
	for _, l := range bytes.Split(data, []byte("\n")) {
		var r struct {
			Session *struct {
				Lost bool `json:"lost"`
			} `json:"session"`
		}
		if len(l) > 0 && jsonUnmarshal(l, &r) == nil && r.Session != nil {
			lost = r.Session.Lost
		}
	}
	return lost
}

// identityValues are the values that name a person in the answers of the
// endpoints that tell who asks (/me, /whoami, /profile, the session check),
// and the subject of a JWT: an object holding one as its owner is that
// person's.
func identityValues(m *export.Model, snap *session.Snapshot, id *Identity) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if len(v) >= 3 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	check := ""
	if snap != nil {
		check = snap.Signs.CheckURL
	}
	for _, r := range m.Requests {
		if r.Entry.Method != "GET" || r.Entry.Response == nil || r.Entry.Response.Status < 200 || r.Entry.Response.Status > 299 {
			continue
		}
		u, err := url.Parse(r.Entry.URL)
		if err != nil || !(selfPathRe.MatchString(u.Path) || (check != "" && strings.HasSuffix(check, u.Path))) {
			continue
		}
		f, ok := flatten([]byte(r.Entry.Response.Body.Body))
		if !ok {
			continue
		}
		for p, v := range f {
			switch strings.ToLower(lastKey(p)) {
			case "id", "userid", "user_id", "uid", "sub", "uuid", "email", "username", "login", "accountid", "account_id":
				add(v)
			}
		}
	}
	for _, v := range id.Creds {
		if sub := jwtSubject(v); sub != "" {
			add(sub)
		}
	}
	sort.Strings(out)
	return out
}

var selfPathRe = regexp.MustCompile(`(?i)/(me|self|whoami|profile|session|current)/?$`)

// candidates are the owner's requests that carry an id the other person has
// not seen: one for each endpoint and set of such places (three at most for
// an endpoint), in the order of the owner's traffic.
func (b *bola) candidates(owner, as *peerCtx) []*candidate {
	type group struct {
		reqs  []*export.Request
		ids   map[*export.Request][]ParsedID
		all   map[*export.Request][]ParsedID
		key   string
		posig string
	}
	groups := map[string]*group{}
	var order []string
	perKey := map[string]int{}
	for _, r := range owner.model.Requests {
		if !r.File || r.Entry.Hop > 0 || r.Entry.Response == nil || r.Entry.Response.Status < 200 || r.Entry.Response.Status > 299 {
			continue
		}
		all := requestIDs(r, b.aligned)
		var unseen []ParsedID
		for _, id := range all {
			if !as.seen.Has(id.Value) {
				unseen = append(unseen, id)
			}
		}
		if len(unseen) == 0 {
			continue
		}
		key := reportKey(r, all, b.aligned)
		ats := make([]string, len(unseen))
		for i, id := range unseen {
			ats[i] = id.At
		}
		sort.Strings(ats)
		sig := key + "\x00" + strings.Join(ats, ",")
		g := groups[sig]
		if g == nil {
			if perKey[key] >= 3 {
				continue
			}
			perKey[key]++
			g = &group{ids: map[*export.Request][]ParsedID{}, all: map[*export.Request][]ParsedID{}, key: key, posig: sig}
			groups[sig] = g
			order = append(order, sig)
		}
		g.reqs = append(g.reqs, r)
		g.ids[r], g.all[r] = unseen, all
	}
	var out []*candidate
	for _, sig := range order {
		g := groups[sig]
		best := export.Best(g.reqs)
		c := &candidate{r: best, key: g.key, ids: g.ids[best], all: g.all[best]}
		c.self = b.findSelf(as, best, c.ids, c.all)
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func paramValueAt(r *export.Request, at string) (string, bool) {
	for _, p := range r.Params() {
		if p.At() == at {
			return p.Value, true
		}
	}
	return "", false
}

// findSelf is a request of the other person to the same endpoint, as that
// person (its own objects): same method, host and operation, the same path
// but at the places of the ids, a value of its own at each of them.
func (b *bola) findSelf(as *peerCtx, r *export.Request, ids, all []ParsedID) *export.Request {
	u, err := url.Parse(r.Entry.URL)
	if err != nil {
		return nil
	}
	segs := pathSegments(r.Entry.URL)
	idAt := map[string]string{}
	pathID := map[int]bool{}
	for _, id := range ids {
		idAt[id.At] = id.Value // the ids B has not seen: B's own differ from them
	}
	for _, id := range all {
		if n, ok := strings.CutPrefix(id.At, "path:"); ok {
			if i, err := strconv.Atoi(n); err == nil {
				pathID[i] = true
			}
		}
	}
	wild, derived := wildcardsOf(r, b.aligned)
	for i := range derived {
		wild[i] = true
	}
	var match []*export.Request
	for _, q := range as.model.Requests {
		if !q.File || q.Entry.Hop > 0 || q.Held || q.Entry.Method != r.Entry.Method || q.Op != r.Op {
			continue
		}
		if q.Entry.Response == nil || q.Entry.Response.Status < 200 || q.Entry.Response.Status > 299 {
			continue
		}
		qu, err := url.Parse(q.Entry.URL)
		if err != nil || qu.Host != u.Host {
			continue
		}
		qs := pathSegments(q.Entry.URL)
		if len(qs) != len(segs) {
			continue
		}
		ok := true
		for i := range segs {
			if !pathID[i+1] && !wild[i+1] && segs[i] != qs[i] {
				ok = false
			}
		}
		for at, v := range idAt {
			if w, has := paramValueAt(q, at); !has || w == v {
				ok = false
			}
		}
		if ok {
			match = append(match, q)
		}
	}
	if len(match) == 0 {
		return nil
	}
	return export.Best(match)
}

// allowHosts lets the run send to the hosts of what it may send, in scope.
func (b *bola) allowHosts(cands ...[]*candidate) {
	hosts, recorded := map[string]bool{}, map[string]string{}
	add := func(r *export.Request) {
		if r == nil {
			return
		}
		u, err := url.Parse(r.Entry.URL)
		if err != nil || !b.o.InScope(u.Hostname()) {
			return
		}
		hosts[u.Host] = true
		if resp := r.Entry.Response; resp != nil && resp.RemoteIP != "" {
			recorded[u.Hostname()] = resp.RemoteIP
		}
	}
	for _, list := range cands {
		for _, c := range list {
			add(c.r)
			add(c.self)
			for _, from := range c.r.Derived {
				for _, p := range b.peers {
					add(p.model.Request(c.r.Run, from.Request))
				}
			}
		}
	}
	for _, p := range b.peers {
		for _, r := range b.probeCandidates(p) {
			add(r)
		}
	}
	b.o.Sender.Allow(hosts, recorded)
}

// probeCandidates are requests that may tell whether a peer's session
// lives: GETs it got a JSON 2xx for, the one that says who asks first.
func (b *bola) probeCandidates(p *peerCtx) []*export.Request {
	check := ""
	if p.snap != nil {
		check = p.snap.Signs.CheckURL
	}
	type scored struct {
		r *export.Request
		n int
	}
	var all []scored
	seen := map[string]bool{}
	for _, r := range p.model.Requests {
		resp := r.Entry.Response
		if r.Entry.Method != "GET" || r.Entry.Hop > 0 || r.Held || r.Provisional || resp == nil || resp.Status < 200 || resp.Status > 299 ||
			!strings.Contains(resp.MIME, "json") || bodyErrors([]byte(resp.Body.Body), nil) == errAll {
			continue
		}
		if b.o.Policy.ClassifyPeer(r.Entry, false).Kind != Read || seen[r.Key] {
			continue
		}
		u, err := url.Parse(r.Entry.URL)
		if err != nil || !b.o.InScope(u.Hostname()) {
			continue
		}
		seen[r.Key] = true
		n := 0
		switch {
		case check != "" && strings.HasSuffix(check, u.Path):
			n = 3
		case selfPathRe.MatchString(u.Path):
			n = 2
		case len(requestIDs(r, b.aligned)) == 0 && u.RawQuery == "":
			n = 1
		}
		all = append(all, scored{r, n})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].n > all[j].n })
	var out []*export.Request
	for _, s := range all {
		if len(out) == 4 {
			break
		}
		out = append(out, s.r)
	}
	return out
}

// confirmProbe gives a peer the request its session is checked with: one
// that a request with no identity is refused, and the peer's own gets a
// 2xx. When requests exist but none answers the peer, its session is dead.
func (b *bola) confirmProbe(ctx context.Context, p *peerCtx) {
	if b.o.Sender.DryRun() {
		return
	}
	cands := b.probeCandidates(p)
	if len(cands) == 0 {
		p.noProbe = true
		return
	}
	failed, why := 0, ""
	for _, r := range cands {
		raw, err := r.Raw()
		if err != nil {
			continue
		}
		stripped := stripPeer(raw, r.Entry.URL, r.Derived, b.a)
		if stripped == nil {
			continue
		}
		bare := addNoCache(stripped)
		pub, err := b.o.Sender.Send(ctx, bare, schemeOf(r.Entry.URL), "probe-check", "(none)", "", nil)
		if err != nil && soft(err) {
			return
		}
		if err == nil && pub.Block != nil {
			return
		}
		if err == nil && pub.ok() && bodyErrors(pub.Body, nil) != errAll {
			continue // open to anyone: no word of a session
		}
		began := time.Now()
		ans, err := b.a.send(ctx, p.roleCtx, r, "probe", "")
		switch {
		case err != nil && soft(err):
			return
		case err != nil:
			failed++
			why = err.Error()
		case ans.Block != nil:
			return
		case ans.ok() && bodyErrors(ans.Body, nil) != errAll:
			p.mu.Lock()
			p.probe, p.goodAt = r, began
			p.mu.Unlock()
			return
		default:
			failed++
			why = fmt.Sprintf("%s answered %s", r.Key, describe(ans))
		}
	}
	if failed > 0 {
		p.mu.Lock()
		p.dead = why
		p.mu.Unlock()
		return
	}
	p.noProbe = true
}

// stripPeer takes the identity off a request: its cookies, credential
// headers, and the credentials in its query and body: but not the
// parameters that sign an URL, which are its authority (a pre-signed URL
// is what authz -peers asks whether anyone may use).
func stripPeer(raw []byte, rawURL string, derived map[string]flow.LinkEnd, a *authz) []byte {
	if len(export.Params(raw)) >= maxExportParams {
		return nil // not all of it could be read for credentials
	}
	out, _ := Apply(raw, NoIdentity(), rawURL, nil)
	for at, from := range derived {
		if credentialLink(at, from) && !a.signatureAt(at) {
			out = dropCredential(out, at)
		}
	}
	for range 50 {
		done := true
		for _, p := range export.Params(out) {
			if a.foreignParam(p) && p.At() != "" {
				out, done = dropCredential(out, p.At()), false
				break
			}
		}
		if done {
			break
		}
	}
	return out
}

// addNoCache asks for a fresh answer: a shared cache that missed the
// Vary of a cookie must not give B what it holds for A.
func addNoCache(raw []byte) []byte {
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return raw
	}
	lines := strings.Split(string(head), "\r\n")
	kept := lines[:1]
	for _, l := range lines[1:] {
		n, _, _ := strings.Cut(l, ":")
		if ln := strings.ToLower(strings.TrimSpace(n)); ln != "cache-control" && ln != "pragma" {
			kept = append(kept, l)
		}
	}
	kept = append(kept, "Cache-Control: no-cache", "Pragma: no-cache")
	return append([]byte(strings.Join(kept, "\r\n")+"\r\n\r\n"), body...)
}

// sentValues are the values a raw request carries that are no credential:
// its query, form and JSON values, custom headers, and the path segments
// that look like ids. An answer that holds one is the request echoed.
func sentValues(raw []byte, ids ...string) []string {
	isID := map[string]bool{}
	for _, v := range ids {
		isID[v] = true
	}
	var out []string
	for _, p := range export.Params(raw) {
		switch p.In {
		case "cookie":
			continue
		case "header":
			if credential(p.Name) {
				continue
			}
		case "path":
			// The segments that are ids (the request's own list, pure-letter
			// slugs too) or look like one.
			if !(isID[p.Value] || typedKind(p.Value) != IDNone || idish(p.Value)) {
				continue
			}
		default:
			if traffic.Sensitive(lastKey(p.Name)) && !isURLSignatureParam(lastKey(p.Name)) {
				continue
			}
		}
		out = append(out, p.Value)
		// A Relay id comes back as its inner id (databaseId: 1001): that is the
		// request echoed too.
		if typ, inner, _, _, ok := DecodeRelay(p.Value); ok {
			out = append(out, typ+":"+inner, inner)
		}
	}
	return out
}

// customHeaders are the application's own headers a request keeps from its
// owner (X-User-Id, X-Org-Id, a nonce): they are not credentials, so they
// go under the other identity as they are; the report names them.
func customHeaders(raw []byte) []string {
	var out []string
	for _, p := range export.Params(raw) {
		if p.In == "header" && !credential(p.Name) {
			out = append(out, p.Name)
		}
	}
	return out
}

func hasIdentityFor(p *peerCtx, rawURL string) bool { return identityFor(p.roleCtx, rawURL) }

// idValues are the values of a candidate's ids.
func idValues(ids []ParsedID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.Value
	}
	return out
}

func recordedOK(r *export.Request) bool {
	resp := r.Entry.Response
	return resp != nil && resp.Status >= 200 && resp.Status < 300 && !r.Held && bodyErrors([]byte(resp.Body.Body), nil) != errAll
}

// tryCandidate tries a candidate: the main trial and, with -substitute, the
// trials of each id alone.
func (b *bola) tryCandidate(ctx context.Context, owner, as *peerCtx, c *candidate) ([]PeerItem, error) {
	if why, stopped := b.rep.StoppedEndpoints[c.key]; stopped {
		// An earlier trial found the endpoint answers any id with data: one
		// line says so, not one for each candidate it would have had.
		for _, it := range b.rep.Items {
			if it.Key == c.key && it.Owner == owner.name && it.As == as.name && it.Mode == "main" {
				return nil, nil
			}
		}
		it := &PeerItem{Key: c.key, Direction: owner.name + "->" + as.name, Owner: owner.name, As: as.name, Mode: "main", Request: Ref{c.r.Run, c.r.Entry.ID}}
		return []PeerItem{*b.skipItem(it, Skipped, "the endpoint was stopped: "+why)}, nil
	}
	main, err := b.try(ctx, owner, as, c, nil)
	if err != nil {
		return nil, err
	}
	items := []PeerItem{*main}
	if !b.o.Substitute || len(c.all) < 2 || c.self == nil || b.o.Sender.Stopped() != "" || main.stop {
		return items, nil
	}
	switch main.Verdict {
	case Enforced, EnforcedParent, NeedsReview, Likely:
	default:
		return items, nil
	}
	n := 0
	for i := range c.all {
		id := c.all[i]
		if id.At == "" || n >= 4 {
			continue
		}
		if v, ok := paramValueAt(c.self, id.At); !ok || v == id.Value {
			continue
		}
		n++
		if b.o.Sender.Stopped() != "" || ctx.Err() != nil {
			break
		}
		it, err := b.try(ctx, owner, as, c, &id)
		if err != nil {
			return nil, err
		}
		items = append(items, *it)
	}
	return items, nil
}

func (b *bola) skipItem(it *PeerItem, v Verdict, why string) *PeerItem {
	it.Judgement = Judgement{v, why}
	return it
}

// try sends the trials of one candidate and concludes. only: the id put
// alone in B's own request (-substitute); nil: the main trial.
func (b *bola) try(ctx context.Context, owner, as *peerCtx, c *candidate, only *ParsedID) (*PeerItem, error) {
	r := c.r
	d := b.o.Policy.ClassifyPeer(r.Entry, r.Held || (c.self != nil && c.self.Held))
	it := &PeerItem{Key: c.key, Direction: owner.name + "->" + as.name, Owner: owner.name, As: as.name, Mode: "main",
		Request: Ref{r.Run, r.Entry.ID}, Kind: d.Kind, Why: d.Reason}
	if only != nil {
		it.Mode = "substitute:" + only.At
	}
	if c.self != nil {
		it.SelfRequest = &Ref{c.self.Run, c.self.Entry.ID}
	}
	for _, id := range c.ids {
		ci := CandidateID{At: id.At, Kind: id.Kind, Value: id.Value, RelayType: id.RelayType, RelayID: id.RelayInner}
		it.IDs = append(it.IDs, ci)
	}
	label := c.key + " " + it.Direction + " " + it.Mode

	switch {
	case d.Kind == Never || d.Kind == Excluded:
		return b.skipItem(it, Skipped, string(d.Kind)+": "+d.Reason), nil
	case d.Kind == Destructive:
		return b.skipItem(it, Skipped, "destructive ("+d.Reason+"): authz never sends it"), nil
	case d.Kind == Write && !b.o.AllowWrite:
		return b.skipItem(it, Skipped, "a write ("+d.Reason+"): -allow-write to try it"), nil
	}
	write := d.Kind == Write
	if why := owner.deadWhy(); why != "" {
		return b.skipItem(it, Unclear, "peer A's session is dead: "+why), nil
	}
	if why := as.deadWhy(); why != "" {
		return b.skipItem(it, Unclear, "peer B's session is dead: "+why), nil
	}
	if !hasIdentityFor(as, r.Entry.URL) {
		return b.skipItem(it, Unclear, "no cookie or credential of B for this host: a request without B's identity would be no trial"), nil
	}

	// The trial request, under B's identity.
	var raw []byte
	var bt built
	var err error
	if only == nil {
		raw, bt, err = b.a.build(ctx, owner.roleCtx, as.roleCtx, r, label)
		if err != nil {
			return nil, err
		}
	} else {
		raw, bt, err = b.a.build(ctx, as.roleCtx, as.roleCtx, c.self, label)
		if err != nil {
			return nil, err
		}
		if raw, err = Patch(raw, only.At, only.Value); err != nil {
			return b.skipItem(it, Skipped, "substitute: "+err.Error()), nil
		}
	}
	raw = addNoCache(raw)
	it.Refreshed, it.Stale, it.Kept, it.Missing = bt.refreshed, bt.stale, bt.kept, bt.missing
	it.KeptHeaders = customHeaders(raw)
	if len(bt.missing) > 0 {
		return b.skipItem(it, Unclear, "no equivalent credential of B: "+strings.Join(bt.missing, ", ")), nil
	}
	if len(bt.kept) > 0 {
		return b.skipItem(it, Unclear, "credential of A cannot be replaced: "+strings.Join(bt.kept, ", ")+" (in the query or body, not taken fresh): not sent"), nil
	}
	note := func(s *Sent) { s.Refreshed, s.Stale = bt.refreshed, bt.stale }
	// The file is of what is sent: never a request that still carries
	// A's credential.
	it.File = b.trialFile(c.key, it.Mode, owner.name, as.name, raw)

	soften := func(err error) (*PeerItem, error) {
		if soft(err) {
			return b.skipItem(it, Skipped, err.Error()), nil
		}
		return b.skipItem(it, Unclear, "not sent: "+err.Error()), nil
	}

	ans, err := b.a.sendRaw(ctx, as.roleCtx, raw, r.Entry.URL, "trial", label, note)
	it.At = time.Now().UTC()
	if err != nil {
		return soften(err)
	}
	it.Trial = &Brief{Status: ans.Status, Size: len(ans.Body)}
	if b.o.Sender.DryRun() {
		return b.skipItem(it, Skipped, "dry run"), nil
	}
	pc := PeerCase{Write: write, Relation: b.o.Relation, Mode: it.Mode, IDCount: len(c.all), Trial: ans,
		Seen: as.seen, OwnerIDs: owner.idVals, PeerIDs: as.idVals, Stale: len(bt.stale) > 0, IsLogin: as.login,
		RecordedOK: recordedOK(r), AliveA: true, Sent: sentValues(raw, idValues(c.all)...)}
	if b.o.Private != nil && (b.o.Private.MatchString(c.key) || b.o.Private.MatchString(r.Entry.URL)) {
		pc.Private = true
	}

	if !write {
		// A's control, always: it tells a refusal from a request that no
		// longer replays.
		cr, cb, err := b.a.build(ctx, owner.roleCtx, owner.roleCtx, r, label)
		if err != nil {
			return nil, err
		}
		if len(cb.missing) > 0 {
			return b.skipItem(it, Unclear, "no credential of A to send its control with: "+strings.Join(cb.missing, ", ")), nil
		}
		c1, err := b.a.sendRaw(ctx, owner.roleCtx, addNoCache(cr), r.Entry.URL, "control", label, nil)
		if err != nil {
			return soften(err)
		}
		pc.Controls = []Answer{c1}
		it.Control = &Brief{Status: c1.Status, Size: len(c1.Body)}
		if !c1.ok() {
			al, known := b.a.peerAlive(ctx, owner.roleCtx)
			pc.AliveA = al && known
		}
		deeper := ans.Err == "" && blockOf(ans) == nil && ans.ok() && c1.ok() && !cached(ans) && blockOf(c1) == nil &&
			bodyErrors(c1.Body, nil) != errAll && bodyErrors(ans.Body, c1.Body) == errNone && kind(ans) == kind(c1)
		if deeper {
			c2, err := b.a.sendRaw(ctx, owner.roleCtx, addNoCache(cr), r.Entry.URL, "control", label, nil)
			if err != nil {
				return soften(err)
			}
			pc.Controls = append(pc.Controls, c2)
			if c.self != nil {
				if sa, err := b.a.send(ctx, as.roleCtx, c.self, "self", label); err == nil {
					if sa.ok() && bodyErrors(sa.Body, nil) != errAll && blockOf(sa) == nil {
						pc.Self = &sa
						it.Reference = &RefBrief{"self", sa.Status, len(sa.Body)}
					}
				} else if soft(err) {
					return soften(err)
				}
			}
			if pc.Self == nil {
				if err := b.sendBogus(ctx, as, c, raw, only, label, &pc, it); err != nil {
					return soften(err)
				}
			}
		}
	}

	var j PeerJudgement
	for range 4 {
		j = JudgePeer(pc)
		switch {
		case j.NeedBogus && !pc.BogusTried:
			if err := b.sendBogus(ctx, as, c, raw, only, label, &pc, it); err != nil {
				return soften(err)
			}
			pc.BogusTried = true
			continue
		case j.NeedBogus:
			pc.BogusTried = true
			continue
		case j.NeedNoID && pc.NoIdentity == nil:
			var na Answer
			if stripped := stripPeer(raw, r.Entry.URL, r.Derived, b.a); stripped == nil {
				na = Answer{Err: "too many parameters to take every credential off"}
			} else {
				var err error
				na, err = b.o.Sender.Send(ctx, addNoCache(stripped), schemeOf(r.Entry.URL), "no-identity", "(none)", label, nil)
				if err != nil {
					if soft(err) {
						return soften(err)
					}
					na = Answer{Err: err.Error()}
				}
			}
			pc.NoIdentity = &na
			if na.Err == "" {
				it.NoIdentity = &Brief{Status: na.Status, Size: len(na.Body)}
			}
			continue
		}
		break
	}
	it.Judgement = j.Judgement
	it.Evidence = b.maskEvidence(j.Evidence)
	it.Private = j.Private
	if j.StopEndpoint {
		it.stop = true
		if b.rep.StoppedEndpoints == nil {
			b.rep.StoppedEndpoints = map[string]string{}
		}
		b.rep.StoppedEndpoints[c.key] = j.Reason
	}
	if (j.Verdict == Enforced || j.Verdict == EnforcedParent) && !b.o.Sender.DryRun() {
		switch {
		case as.noProbe:
			it.Judgement = Judgement{Unclear, "refused, but there is no request to tell that B's session lives"}
		default:
			al, known := b.a.peerAlive(ctx, as.roleCtx)
			switch {
			case !known:
				it.Judgement = Judgement{Unclear, "refused, but whether B's session lives could not be told (the run stopped, the budget is spent, or a vendor answered)"}
			case !al:
				it.Judgement = Judgement{Unclear, "refused, and B's session is dead now: " + as.deadWhy()}
			}
		}
	}
	if pc.NoIdentity != nil && pc.NoIdentity.Err != "" && (it.Verdict == Bypass || it.Verdict == Shared) {
		it.Reason += " (the no-identity probe failed: " + pc.NoIdentity.Err + ")"
	}
	return it, nil
}

// sendBogus sends the trial with an id that names nothing, for the one id
// that is the leaf (the last one in the request): the parents stay.
func (b *bola) sendBogus(ctx context.Context, as *peerCtx, c *candidate, raw []byte, only *ParsedID, label string, pc *PeerCase, it *PeerItem) error {
	target := bogusTarget(c.ids)
	if only != nil {
		target = *only
	}
	avoid := func(v string) bool {
		if as.seen.Has(v) || b.peerOf(as).seen.Has(v) {
			return true
		}
		return near(v, target.Value, target.Kind)
	}
	fake := BogusID(target, avoid)
	if fake == "" {
		pc.BogusTried = true
		return nil
	}
	for i := range it.IDs {
		if it.IDs[i].At == target.At {
			it.IDs[i].Bogus = fake
		}
	}
	braw, err := Patch(raw, target.At, fake)
	if err != nil {
		pc.BogusTried = true
		return nil
	}
	ba, err := b.a.sendRaw(ctx, as.roleCtx, braw, c.r.Entry.URL, "bogus", label, nil)
	if err != nil {
		return err
	}
	pc.Bogus, pc.BogusTried = &ba, true
	pc.SentBogus = sentValues(braw, append(idValues(c.all), fake)...)
	if ba.Err == "" {
		it.Reference = &RefBrief{"bogus", ba.Status, len(ba.Body)}
	}
	return nil
}

func (b *bola) peerOf(as *peerCtx) *peerCtx {
	if b.peers[0] == as {
		return b.peers[1]
	}
	return b.peers[0]
}

// near reports a value within 1000 of another, as numbers (or the inner
// ids of Relay ones): a fake id must not be a neighbour of the real.
func near(v, of string, k IDKind) bool {
	if k == IDRelay {
		if _, inner, _, _, ok := DecodeRelay(v); ok {
			v = inner
		}
		if _, inner, _, _, ok := DecodeRelay(of); ok {
			of = inner
		}
	}
	a, err1 := strconv.ParseInt(v, 10, 64)
	c, err2 := strconv.ParseInt(of, 10, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	d := a - c
	return d >= -1000 && d <= 1000
}

func (b *bola) maskEvidence(ev []EvidencePair) []EvidencePair {
	if b.o.Reveal {
		return ev
	}
	out := make([]EvidencePair, len(ev))
	for i, e := range ev {
		out[i] = e
		out[i].Value = b.red.Value(e.Value)
		if e.RefVal != "" {
			out[i].RefVal = b.red.Value(e.RefVal)
		}
	}
	return out
}

func (b *bola) trialFile(key, mode, from, to string, raw []byte) string {
	if b.o.Out == "" {
		return ""
	}
	suffix := ""
	if strings.HasPrefix(mode, "substitute:") {
		suffix = "-sub-" + strings.Trim(slugRe.ReplaceAllString(strings.ToLower(strings.TrimPrefix(mode, "substitute:")), "-"), "-")
	}
	// The host and a number keep two candidates of one endpoint, or two
	// hosts' of one path, from overwriting each other.
	_, host, _, _ := keyParts(key)
	b.trialN++
	name := fmt.Sprintf("trials/bola.%s.%s%s.n%d.%s-as-%s.http", slugRe.ReplaceAllString(strings.ToLower(host), "-"), slugKey(key), suffix, b.trialN, from, to)
	p := filepath.Join(b.o.Out, name)
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil || os.WriteFile(p, raw, 0o600) != nil {
		return ""
	}
	return name
}

// downgrade turns into unclear the refusals of a peer whose session died,
// answered after its last good probe began (the session may have died
// before the probe told).
func (b *bola) downgrade() {
	for _, p := range b.peers {
		why := p.deadWhy()
		if why == "" {
			continue
		}
		for i := range b.rep.Items {
			t := &b.rep.Items[i]
			if t.As == p.name && (t.Verdict == Enforced || t.Verdict == EnforcedParent) && !t.At.Before(p.goodAt) {
				t.Judgement = Judgement{Unclear, "refused, but B's session died near then: " + why}
			}
		}
	}
}

// bogusTarget is the leaf id of a request: the last one of the path (the
// object's), else the last one of the query or body, a header's last of all
// (a tenant is a parent): never the one that is last by byte offset.
func bogusTarget(ids []ParsedID) ParsedID {
	rank := func(id ParsedID) int {
		switch id.In {
		case "path":
			return 2
		case "header":
			return 0
		}
		return 1
	}
	target := ids[0]
	for _, id := range ids[1:] {
		if rank(id) > rank(target) || (rank(id) == rank(target) && id.Start > target.Start) {
			target = id
		}
	}
	return target
}
