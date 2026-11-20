package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/roles"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// AuthzOptions configure a run of authz.
type AuthzOptions struct {
	Root     string   // <out>/<host>, with diff.json
	Profiles string   // <profiles>/<host>: the roles' login snapshots
	Classes  []string // the diff classes to try
	Policy   Policy
	// AllowWrite lets writes be tried; ControlWrites sends the higher
	// role's write too (it then does what it does).
	AllowWrite, ControlWrites bool
	// Concurrency is how many items are tried at once (1: one at a time).
	// Within an item the order stays: the trials, then the controls.
	Concurrency int
	Sender      *Sender
	InScope     func(host string) bool
	Out         string // <root>/authz
	Now         time.Time
}

// DefaultClasses are the diff classes worth a trial.
var DefaultClasses = []string{roles.LowerOK, roles.ClientGated, roles.HigherOnly, roles.DeniedBelow, roles.ShapeDiffers, roles.NotCovered}

// AuthzReport is authz.json.
type AuthzReport struct {
	Host      string    `json:"host"`
	Roles     []string  `json:"roles"`
	Generated time.Time `json:"generated"`
	Sent      int       `json:"sent"`
	Stopped   string    `json:"stopped,omitempty"`
	// HostsBlocked are the hosts given up: a vendor blocked the client
	// there, a control request too (round 25H).
	HostsBlocked map[string]string `json:"hosts_blocked,omitempty"`
	Notes        []string          `json:"notes,omitempty"`
	Summary      map[string]int    `json:"summary"`
	Items        []AuthzItem       `json:"items"`
}

type AuthzItem struct {
	Key     string  `json:"key"`
	Class   string  `json:"class"`
	Sample  string  `json:"sample_role"`
	Request Ref     `json:"sample_request"`
	Kind    Kind    `json:"kind"`
	Why     string  `json:"kind_reason,omitempty"`
	Control *Brief  `json:"control,omitempty"`
	Trials  []Trial `json:"trials"`
}

type Ref struct {
	Run string `json:"run"`
	ID  int    `json:"id"`
}

type Brief struct {
	Status int `json:"status"`
	Size   int `json:"size"`
}

type Trial struct {
	Role      string    `json:"role"`
	Judgement           // verdict, reason
	Status    int       `json:"status,omitempty"`
	Size      int       `json:"size,omitempty"`
	File      string    `json:"file,omitempty"`
	Missing   []string  `json:"missing,omitempty"`
	Refreshed   []string  `json:"refreshed,omitempty"`
	Stale       []string  `json:"stale,omitempty"`
	Kept        []string  `json:"kept,omitempty"`
	KeptHeaders []string  `json:"kept_headers,omitempty"`
	At          time.Time `json:"at,omitzero"` // when the trial was answered
}

type roleCtx struct {
	name  string
	model *export.Model
	id    *Identity
	probe *export.Request // a request that answers 2xx only while the session lives
	login func(string) bool

	mu     sync.Mutex // the probe, one at a time; dead and goodAt
	dead   string
	goodAt time.Time // when the last probe that answered began: refusals answered before it stand
	// serial holds a role to one trial at a time: when its trials take a
	// credential fresh (a CSRF token a later one may undo), or the server
	// turns its identity cookie.
	serial  sync.Mutex
	rotates atomic.Bool
}

func (rc *roleCtx) deadWhy() string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.dead
}

type authz struct {
	o     AuthzOptions
	rep   *roles.Report
	roles []*roleCtx
	out   *AuthzReport
	// peer: the machinery serves authz -peers (bola.go): a pre-signed URL's
	// signature stays on the URL, and the sources a credential is taken from
	// are classified by ClassifyPeer.
	peer bool
	// secrets (peer mode) are the values of the peers' cookies, tokens and
	// storage: a parameter that holds one is a credential whatever its name.
	secrets map[string]bool
}

// maxExportParams is export.Params' cap: a request with that many may have
// more that were not read.
const maxExportParams = 200

// foreignParam (peer mode) says a parameter of the query or body is a
// credential: a sensitive name (a list's index ignored), a JWT, or a value
// of a peer's session. The ones that sign an URL are not.
func (a *authz) foreignParam(p export.Param) bool {
	if p.In != "query" && p.In != "json" && p.In != "form" && p.In != "multipart" {
		return false
	}
	if p.Value == "" || p.Value == "null" || isURLSignatureParam(lastKey(p.Name)) {
		return false
	}
	return traffic.Sensitive(lastKey(p.Name)) || jwtValueRe.MatchString(p.Value) || a.secrets[p.Value]
}

// identityFor: the identity has a cookie for the URL's host, or a header
// credential; without, a request under it would go as nobody.
func identityFor(rc *roleCtx, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return len(rc.id.Jar.Cookies(u)) > 0 || len(rc.id.Creds) > 0
}

// peerAlive is alive for authz -peers: whether the session lives, and
// whether that is known. A probe stopped by the budget, the run, a vendor's
// block or an error that is not the server's word leaves it unknown; a
// probe answered with an error in its body, or a page, where the recorded
// answer was JSON, is a dead session. (alive, the vertical test's, is as it
// was.)
func (a *authz) peerAlive(ctx context.Context, rc *roleCtx) (alive, known bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.dead != "" {
		return false, true
	}
	if a.o.Sender.DryRun() {
		return true, true
	}
	if rc.probe == nil {
		return false, false
	}
	began := time.Now()
	ans, err := a.send(ctx, rc, rc.probe, "probe", "")
	switch {
	case err != nil && (errors.Is(err, errStopped) || errors.Is(err, ErrBudget) || errors.Is(err, ErrScope) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		return false, false
	case err != nil:
		rc.dead = err.Error()
	case ans.Block != nil:
		return false, false
	case !ans.ok():
		rc.dead = fmt.Sprintf("%s answered %s", rc.probe.Key, describe(ans))
	case bodyErrors(ans.Body, nil) == errAll:
		rc.dead = fmt.Sprintf("%s answered 200 with an error in its body", rc.probe.Key)
	case kind(ans) != "json":
		rc.dead = fmt.Sprintf("%s answered a %s page, where it was recorded as JSON", rc.probe.Key, kind(ans))
	default:
		rc.goodAt = began
	}
	return rc.dead == "", true
}

// classify is what the policy says of a request about to be sent.
func (a *authz) classify(e traffic.Entry, held bool) Decision {
	if a.peer {
		return a.o.Policy.ClassifyPeer(e, held)
	}
	return a.o.Policy.Classify(e, held)
}

// signatureAt: under authz -peers a place that signs the URL is no
// credential to take fresh (the URL is the authority; another person's
// signature would make another URL).
func (a *authz) signatureAt(at string) bool {
	if !a.peer {
		return false
	}
	place, name, _ := strings.Cut(at, ":")
	switch place {
	case "query", "form":
		return isURLSignatureParam(name)
	case "body":
		return isURLSignatureParam(lastName(name))
	}
	return false
}

// Authz tries the higher roles' requests under the lower roles' identities
// (docs/gd5-replay-design.md, 4 and 8).
func Authz(ctx context.Context, o AuthzOptions) (*AuthzReport, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if len(o.Classes) == 0 {
		o.Classes = DefaultClasses
	}
	var rep roles.Report
	b, err := os.ReadFile(filepath.Join(o.Root, "diff.json"))
	if err != nil {
		return nil, fmt.Errorf("authz: %w (run jsharvest diff first)", err)
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("authz: diff.json: %w", err)
	}
	a := &authz{o: o, rep: &rep, out: &AuthzReport{Host: rep.Host, Roles: rep.Roles, Generated: o.Now.UTC(), Summary: map[string]int{}}}
	for _, name := range rep.Roles {
		m, err := export.Load(export.Options{Dir: filepath.Join(o.Root, name), Run: "all", InScope: o.InScope})
		if err != nil {
			return nil, fmt.Errorf("authz: role %s: %w", name, err)
		}
		var snap *session.Snapshot
		if o.Profiles != "" {
			if s, err := session.Load(filepath.Join(o.Profiles, name)); err == nil {
				snap = s
			}
		}
		entries := make([]traffic.Entry, len(m.Requests))
		for i, r := range m.Requests {
			entries[i] = r.Entry
		}
		rc := &roleCtx{name: name, model: m, id: NewIdentity(name, snap, entries, o.Now), login: loginTest(snap)}
		for _, n := range rc.id.Notes {
			a.out.Notes = append(a.out.Notes, name+": "+n)
		}
		a.roles = append(a.roles, rc)
	}
	a.pickProbes()
	a.allowHosts()
	for _, rc := range a.roles {
		if rc.probe == nil {
			if len(rc.id.Creds) > 0 || rc.hasCookies() {
				a.out.Notes = append(a.out.Notes, rc.name+": no request to check its session with: a dead session would read as enforced")
			}
			continue
		}
		if !a.alive(ctx, rc) {
			a.out.Notes = append(a.out.Notes, fmt.Sprintf("%s: its session is dead (%s): run jsharvest login -role %s", rc.name, rc.dead, rc.name))
		}
	}
	var todo []roles.Item
	for _, it := range rep.Items {
		if it.Layer == "endpoint" && slices.Contains(o.Classes, it.Class) {
			todo = append(todo, it)
		}
	}
	// Items at once (-concurrency), each in its slot: authz.json keeps the
	// diff's order, whatever finishes first.
	slots := make([]*AuthzItem, len(todo))
	errs := make([]error, len(todo))
	next := make(chan int)
	var wg sync.WaitGroup
	for range max(1, o.Concurrency) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				slots[i], errs[i] = a.item(ctx, todo[i])
			}
		}()
	}
	for i := range todo {
		if o.Sender.Stopped() != "" || ctx.Err() != nil {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
	for i, it := range slots {
		if errs[i] != nil {
			return nil, errs[i]
		}
		if it != nil {
			a.out.Items = append(a.out.Items, *it)
		}
	}
	a.downgrade()
	if s := o.Sender.Stopped(); s != "" {
		a.out.Stopped = s
	}
	a.out.HostsBlocked = o.Sender.BlockedHosts()
	a.out.Sent = o.Sender.Count()
	for _, it := range a.out.Items {
		for _, t := range it.Trials {
			a.out.Summary[string(t.Verdict)]++
		}
	}
	return a.out, nil
}

func (rc *roleCtx) hasCookies() bool {
	for _, r := range rc.model.Requests {
		if u, err := url.Parse(r.Entry.URL); err == nil && len(rc.id.Jar.Cookies(u)) > 0 {
			return true
		}
	}
	return false
}

var loginPathRe = regexp.MustCompile(`(?i)(^|/)(log-?in|sign-?in|auth|account/login|users/sign_in)(/|$|\?)`)

func loginTest(snap *session.Snapshot) func(string) bool {
	var loginPath string
	if snap != nil {
		if u, err := url.Parse(snap.LoginURL); err == nil {
			loginPath = strings.TrimRight(u.Path, "/")
		}
	}
	return func(loc string) bool {
		u, err := url.Parse(loc)
		if err != nil {
			return false
		}
		p := strings.TrimRight(u.Path, "/")
		return (loginPath != "" && p == loginPath) || loginPathRe.MatchString(u.Path)
	}
}

// keyParts splits a diff or export key: METHOD host/template [operation].
func keyParts(key string) (method, host, tmpl, op string) {
	method, rest, _ := strings.Cut(key, " ")
	hostPath, op, _ := strings.Cut(rest, " ")
	i := strings.Index(hostPath, "/")
	if i < 0 {
		return method, hostPath, "/", op
	}
	return method, hostPath[:i], hostPath[i:], op
}

var placeholderRe = regexp.MustCompile(`\\\{[^}]*\\\}`)

// matching are a role's requests to a diff item's endpoint.
func matching(m *export.Model, key string) []*export.Request {
	method, host, tmpl, op := keyParts(key)
	re := regexp.MustCompile("^" + placeholderRe.ReplaceAllString(regexp.QuoteMeta(strings.TrimRight(tmpl, "/")), `[^/]+`) + "/?$")
	var out []*export.Request
	for _, r := range m.Requests {
		if r.Entry.Hop > 0 || r.Entry.Method != method {
			continue
		}
		u, err := url.Parse(r.Entry.URL)
		if err != nil || u.Host != host || !re.MatchString(u.EscapedPath()) {
			continue
		}
		if _, _, _, rop := keyParts(r.Key); rop != op {
			continue
		}
		out = append(out, r)
	}
	return out
}

// pickProbes gives each role a request that tells its session lives: a GET
// it got a JSON 2xx for, that the diff says a lower role was refused.
func (a *authz) pickProbes() {
	for i, rc := range a.roles {
		for _, it := range a.rep.Items {
			if it.Layer != "endpoint" || it.States[rc.name] != roles.Used || !strings.HasPrefix(it.Key, "GET ") {
				continue
			}
			refusedBelow := false
			for _, low := range a.roles[:i] {
				if s := it.States[low.name]; s == roles.Denied || s == roles.Redirected {
					refusedBelow = true
				}
			}
			if !refusedBelow {
				continue
			}
			for _, r := range matching(rc.model, it.Key) {
				if resp := r.Entry.Response; resp != nil && resp.Status >= 200 && resp.Status < 300 && strings.Contains(resp.MIME, "json") && !r.Provisional {
					if a.o.Policy.Classify(r.Entry, false).Kind == Read {
						rc.probe = r
						break
					}
				}
			}
			if rc.probe != nil {
				break
			}
		}
	}
}

// allowHosts lets the run send to exactly the hosts of the samples it will
// try and of the probes, in scope.
func (a *authz) allowHosts() {
	hosts, recorded := map[string]bool{}, map[string]string{}
	add := func(r *export.Request) {
		u, err := url.Parse(r.Entry.URL)
		if err != nil || !a.o.InScope(u.Hostname()) {
			return
		}
		hosts[u.Host] = true
		if resp := r.Entry.Response; resp != nil && resp.RemoteIP != "" {
			recorded[u.Hostname()] = resp.RemoteIP
		}
	}
	for _, rc := range a.roles {
		if rc.probe != nil {
			add(rc.probe)
		}
	}
	for _, it := range a.rep.Items {
		if it.Layer == "endpoint" && slices.Contains(a.o.Classes, it.Class) {
			if _, r := a.sample(it); r != nil {
				add(r)
				for _, from := range r.Derived {
					for _, rc := range a.roles {
						if src := rc.model.Request(r.Run, from.Request); src != nil {
							add(src)
						}
					}
				}
			}
		}
	}
	a.o.Sender.Allow(hosts, recorded)
}

// alive sends a role's probe: its session lives while it answers 2xx.
func (a *authz) alive(ctx context.Context, rc *roleCtx) bool {
	rc.mu.Lock() // one probe of a role at a time; the others wait for its word
	defer rc.mu.Unlock()
	if rc.dead != "" {
		return false
	}
	if rc.probe == nil || a.o.Sender.DryRun() {
		return true
	}
	began := time.Now()
	ans, err := a.send(ctx, rc, rc.probe, "probe", "")
	switch {
	case errors.Is(err, errStopped), errors.Is(err, ErrBudget), errors.Is(err, context.Canceled):
		return true // the run stopped: no word of the session either way
	case err != nil:
		rc.dead = err.Error()
	case ans.Block != nil:
		// A vendor answered, not the application: no word of the session
		// (the Sender checks whether the host still answers).
		return true
	case !ans.ok():
		rc.dead = fmt.Sprintf("%s answered %s", rc.probe.Key, describe(ans))
	default:
		rc.goodAt = began
	}
	return rc.dead == ""
}

// send sends one of a role's requests as that role (credentials fresh).
func (a *authz) send(ctx context.Context, rc *roleCtx, r *export.Request, purpose, item string) (Answer, error) {
	raw, _, err := a.build(ctx, rc, rc, r, item)
	if err != nil {
		return Answer{}, err
	}
	return a.sendRaw(ctx, rc, raw, r.Entry.URL, purpose, item, nil)
}

func (a *authz) sendRaw(ctx context.Context, rc *roleCtx, raw []byte, rawURL, purpose, item string, note func(*Sent)) (Answer, error) {
	u, _ := url.Parse(rawURL)
	ans, err := a.o.Sender.Send(ctx, raw, u.Scheme, purpose, rc.name, item, note)
	if err == nil {
		gone, turned := updateJar(rc.id, u, ans)
		if turned {
			rc.rotates.Store(true) // its trials one at a time from now
		}
		if gone != "" {
			a.o.Sender.mu.Lock()
			a.o.Sender.stop(fmt.Sprintf("%s's cookie %s was deleted by %s", rc.name, gone, rawURL))
			a.o.Sender.mu.Unlock()
		}
	}
	return ans, err
}

// updateJar keeps the cookies an answer sets. It returns the name of an
// identity cookie the answer deleted, and whether it gave one of them
// another value (a session the server turns: a request in flight with the
// old one may be refused for it).
func updateJar(id *Identity, u *url.URL, ans Answer) (string, bool) {
	sc := ans.Header["set-cookie"]
	if sc == "" {
		return "", false
	}
	h := http.Header{}
	for _, l := range strings.Split(sc, "\n") {
		h.Add("Set-Cookie", l)
	}
	// A CDN's cookies (__cf_bm turns every half hour) are not the
	// session's: the Sender keeps them apart, per role (round 25K review);
	// one turning or going is no sign the login did.
	var cookies []*http.Cookie
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if !traffic.CDNCookie(c.Name) {
			cookies = append(cookies, c)
		}
	}
	if len(cookies) == 0 {
		return "", false
	}
	have := map[string]string{}
	for _, c := range id.Jar.Cookies(u) {
		have[c.Name] = c.Value
	}
	gone, turned := "", false
	for _, c := range cookies {
		old, ok := have[c.Name]
		switch {
		case ok && (c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now()))):
			gone = c.Name
		case ok && old != c.Value:
			turned = true
		}
	}
	id.Jar.SetCookies(u, cookies)
	return gone, turned
}

// build makes the request r of the role owner as the role as: its
// identity on it, and the credential links (a CSRF token) taken fresh by
// sending their sources as that role. It reports what it refreshed, what
// went stale, the credentials kept from owner, and those as lacks.
type built struct {
	refreshed, stale, kept, missing []string
}

func (a *authz) build(ctx context.Context, owner, as *roleCtx, r *export.Request, item string) ([]byte, built, error) {
	var b built
	raw, err := r.Raw()
	if err != nil {
		return nil, b, err
	}
	links := map[string]flow.LinkEnd{}
	keep := map[string]bool{}
	for at, from := range r.Derived {
		if !credentialLink(at, from) || a.signatureAt(at) {
			continue
		}
		links[at] = from
		if name, ok := strings.CutPrefix(at, "header:"); ok {
			keep[name] = true
		}
	}
	out, missing := Apply(raw, as.id, r.Entry.URL, keep)
	b.missing = missing
	ats := make([]string, 0, len(links))
	for at := range links {
		ats = append(ats, at)
	}
	sort.Strings(ats)
	for _, at := range ats {
		v, ok := a.fresh(ctx, owner, as, r, links[at], item)
		if !ok {
			b.stale = append(b.stale, at)
			if owner != as {
				out = dropCredential(out, at) // never the higher role's token under another identity
			}
			continue
		}
		patched, err := Patch(out, at, v)
		if err != nil {
			b.stale = append(b.stale, at)
			if owner != as {
				out = dropCredential(out, at)
			}
			continue
		}
		out = patched
		b.refreshed = append(b.refreshed, at)
	}
	// Credentials in the query or the body (an access_token) that nothing
	// refreshed are the owner's still. In vertical authz, strip what can be
	// stripped and hold back the trial if anything remains; in peer mode,
	// bola.go refuses to send whenever bt.kept is non-empty.
	if owner != as {
		if a.peer {
			for _, p := range export.Params(out) {
				if a.foreignParam(p) && !slices.Contains(b.refreshed, p.At()) {
					b.kept = append(b.kept, p.In+":"+p.Name)
				}
			}
			if len(export.Params(out)) >= maxExportParams {
				b.kept = append(b.kept, "params: 200 or more, not all checked for credentials")
			}
		} else {
			var dropped, kept []string
			out, dropped, kept = stripUnrefreshedParams(out, b.refreshed, isRawSensitiveParam)
			for _, d := range dropped {
				if !slices.Contains(b.stale, d) {
					b.stale = append(b.stale, d)
				}
			}
			b.kept = append(b.kept, kept...)
		}
	}
	return out, b, nil
}

func isRawSensitiveParam(p export.Param) bool {
	if p.In != "query" && p.In != "json" && p.In != "form" && p.In != "multipart" {
		return false
	}
	return traffic.Sensitive(lastKey(p.Name))
}

// stripUnrefreshedParams removes every unrefreshed credential parameter it can
// (up to 50 drops) and reports both what was dropped and any credential that
// could not be removed (e.g. multipart, duplicate keys, or >= maxExportParams).
func stripUnrefreshedParams(raw []byte, refreshed []string, isCred func(export.Param) bool) (out []byte, dropped []string, kept []string) {
	if len(export.Params(raw)) >= maxExportParams {
		return raw, nil, []string{"params: 200 or more, not all checked for credentials"}
	}
	out = raw
	for range 50 {
		changed := false
		for _, p := range export.Params(out) {
			if !isCred(p) || p.Value == "" || p.Value == "null" {
				continue
			}
			at := p.At()
			if at == "" || slices.Contains(refreshed, at) {
				continue
			}
			next := dropCredential(out, at)
			if bytes.Equal(next, out) {
				continue
			}
			out = next
			if !slices.Contains(dropped, at) {
				dropped = append(dropped, at)
			}
			changed = true
			break
		}
		if !changed {
			break
		}
	}
	for _, p := range export.Params(out) {
		if !isCred(p) || p.Value == "" || p.Value == "null" {
			continue
		}
		if at := p.At(); at != "" && slices.Contains(refreshed, at) {
			continue
		}
		kept = append(kept, p.In+":"+p.Name)
	}
	return out, dropped, kept
}

// strip takes every credential off a request: its identity's headers and
// cookies, and the credentials in its query and body. It returns nil when a
// credential cannot be safely removed.
func strip(raw []byte, rawURL string, derived map[string]flow.LinkEnd) []byte {
	if len(export.Params(raw)) >= maxExportParams {
		return nil
	}
	out, _ := Apply(raw, NoIdentity(), rawURL, nil)
	for at, from := range derived {
		if credentialLink(at, from) {
			out = dropCredential(out, at)
		}
	}
	out, _, kept := stripUnrefreshedParams(out, nil, isRawSensitiveParam)
	if len(kept) > 0 {
		return nil
	}
	return out
}

// dropCredential takes a credential out of a request when it could not be
// taken fresh: a header goes, a parameter is left empty.
func dropCredential(raw []byte, at string) []byte {
	if name, ok := strings.CutPrefix(at, "header:"); ok {
		head := bytes.Index(raw, []byte("\r\n\r\n"))
		if head < 0 {
			return raw
		}
		lines := strings.Split(string(raw[:head]), "\r\n")
		kept := lines[:1]
		for _, l := range lines[1:] {
			if n, _, _ := strings.Cut(l, ":"); !strings.EqualFold(strings.TrimSpace(n), name) {
				kept = append(kept, l)
			}
		}
		return SetLength(append([]byte(strings.Join(kept, "\r\n")+"\r\n\r\n"), raw[head+4:]...))
	}
	v := ""
	if strings.HasPrefix(at, "body:") {
		for _, p := range export.Params(raw) {
			if p.At() == at && (p.Start == 0 || raw[p.Start-1] != '"') {
				v = "null" // a number's place: an empty string is no JSON there
			}
		}
	}
	if out, err := Patch(raw, at, v); err == nil {
		return out
	}
	return raw
}

func lastName(n string) string {
	n = strings.TrimPrefix(n, "$.")
	if i := strings.LastIndex(n, "."); i >= 0 {
		n = n[i+1:]
	}
	return n
}

// credentialLink reports whether a link carries a credential: a value a
// replay as another role must take fresh, where an id must stay.
func credentialLink(at string, from flow.LinkEnd) bool {
	if strings.HasPrefix(from.At, "cookie:") {
		return true
	}
	place, name, _ := strings.Cut(at, ":")
	switch place {
	case "header":
		return credential(name)
	case "query", "form":
		return traffic.Sensitive(name)
	case "body":
		return traffic.Sensitive(lastName(name))
	}
	return false
}

// fresh takes a value anew: a cookie from the role's jar, or the value at
// the source's place in its answer, the source sent as the role. A source
// that writes is never sent again: its recorded value is no fresh one.
func (a *authz) fresh(ctx context.Context, owner, as *roleCtx, r *export.Request, from flow.LinkEnd, item string) (string, bool) {
	if name, ok := strings.CutPrefix(from.At, "cookie:"); ok {
		u, _ := url.Parse(r.Entry.URL)
		for _, c := range as.id.Jar.Cookies(u) {
			if c.Name == name {
				return c.Value, true
			}
		}
	}
	src := owner.model.Request(r.Run, from.Request)
	if src == nil || a.classify(src.Entry, src.Held).Kind != Read {
		return "", false
	}
	raw, err := src.Raw()
	if err != nil {
		return "", false
	}
	raw, missing := Apply(raw, as.id, src.Entry.URL, nil)
	if len(missing) > 0 {
		return "", false
	}
	if owner != as {
		// The source is the higher role's (or peer A's) request: put the lower
		// role's identity on it, and leave none of the owner's credentials in
		// its query or body.
		if a.peer && !identityFor(as, src.Entry.URL) {
			return "", false
		}
		pred := isRawSensitiveParam
		if a.peer {
			pred = a.foreignParam
		}
		var kept []string
		raw, _, kept = stripUnrefreshedParams(raw, nil, pred)
		if len(kept) > 0 {
			return "", false
		}
	}
	ans, err := a.sendRaw(ctx, as, raw, src.Entry.URL, "source", item, nil)
	if err != nil || !ans.ok() {
		return "", false
	}
	if name, ok := strings.CutPrefix(from.At, "cookie:"); ok {
		u, _ := url.Parse(r.Entry.URL)
		for _, c := range as.id.Jar.Cookies(u) {
			if c.Name == name {
				return c.Value, true
			}
		}
		return "", false
	}
	e := traffic.Entry{Response: &traffic.Response{Headers: ans.Header, MIME: ans.Header["content-type"], Body: traffic.MakeBody(ans.Body, 4<<20)}}
	for _, v := range flow.ResponseValues(e) {
		if v.At == from.At {
			return v.V, true
		}
	}
	return "", false
}

// item tries one diff item.
func (a *authz) item(ctx context.Context, it roles.Item) (*AuthzItem, error) {
	sample, sr := a.sample(it)
	if sample == nil {
		return nil, nil
	}
	held := false
	for _, s := range it.States {
		held = held || s == roles.Held
	}
	d := a.o.Policy.Classify(sr.Entry, held || sr.Held)
	out := &AuthzItem{Key: it.Key, Class: it.Class, Sample: sample.name, Request: Ref{sr.Run, sr.Entry.ID}, Kind: d.Kind, Why: d.Reason}
	var trials []*roleCtx
	for _, rc := range a.roles {
		if rc == sample {
			break
		}
		trials = append(trials, rc)
	}
	skip := ""
	switch {
	case d.Kind == Never || d.Kind == Excluded:
		skip = string(d.Kind) + ": " + d.Reason
	case d.Kind == Destructive:
		skip = "destructive (" + d.Reason + "): authz never sends it; replay one flow with -allow-destructive"
	case d.Kind == Write && !a.o.AllowWrite:
		skip = "a write (" + d.Reason + "): -allow-write to try it"
	}
	if skip != "" {
		for _, rc := range trials {
			out.Trials = append(out.Trials, Trial{Role: rc.name, Judgement: Judgement{Skipped, skip}})
		}
		return out, nil
	}
	write := d.Kind == Write
	if why := sample.deadWhy(); why != "" {
		for _, rc := range trials {
			out.Trials = append(out.Trials, Trial{Role: rc.name, Judgement: Judgement{Unclear, "the higher role's session is dead: " + why}})
		}
		return out, nil
	}

	// The trials first: a shared cache must not hold the higher role's
	// answer when they come.
	type pending struct {
		rc  *roleCtx
		t   Trial
		ans Answer
		b   built
	}
	var ps []*pending
	for _, rc := range trials {
		p := &pending{rc: rc, t: Trial{Role: rc.name}}
		ps = append(ps, p)
		if why := rc.deadWhy(); why != "" {
			p.t.Judgement = Judgement{Unclear, "the role's session is dead: " + why}
			continue
		}
		release := a.exclusive(rc, sr)
		raw, b, err := a.build(ctx, sample, rc, sr, it.Key)
		if err != nil {
			release()
			return nil, err
		}
		p.b = b
		p.t.Refreshed, p.t.Stale, p.t.Kept, p.t.Missing = b.refreshed, b.stale, b.kept, b.missing
		p.t.KeptHeaders = customHeaders(raw)
		if len(b.missing) > 0 {
			release()
			p.t.Judgement = Judgement{Unclear, "no equivalent credential: " + strings.Join(b.missing, ", ")}
			continue
		}
		if len(b.kept) > 0 {
			release()
			p.t.Judgement = Judgement{Unclear, "the higher role's credential cannot be replaced: " + strings.Join(b.kept, ", ")}
			continue
		}
		// Never write a trial file that still carries the higher role's credential.
		p.t.File = a.trialFile(it.Key, rc.name, raw)
		ans, err := a.sendRaw(ctx, rc, raw, sr.Entry.URL, "trial", it.Key, func(s *Sent) { s.Refreshed, s.Stale = b.refreshed, b.stale })
		release()
		p.t.At = time.Now()
		if err != nil {
			if errors.Is(err, ErrBudget) || errors.Is(err, errStopped) || errors.Is(err, ErrScope) {
				p.t.Judgement = Judgement{Skipped, err.Error()}
				continue
			}
			return nil, err
		}
		p.ans = ans
		p.t.Status, p.t.Size = ans.Status, len(ans.Body)
	}
	var controls []Answer
	if !write || a.o.ControlWrites {
		n := 2
		if write {
			n = 1
		}
		for range n {
			release := a.exclusive(sample, sr)
			raw, b, err := a.build(ctx, sample, sample, sr, it.Key)
			if err != nil {
				release()
				return nil, err
			}
			ans, err := a.sendRaw(ctx, sample, raw, sr.Entry.URL, "control", it.Key, func(s *Sent) { s.Refreshed, s.Stale = b.refreshed, b.stale })
			release()
			if err != nil {
				break
			}
			controls = append(controls, ans)
		}
		if len(controls) > 0 {
			out.Control = &Brief{Status: controls[0].Status, Size: len(controls[0].Body)}
		}
	}
	var noID *Answer
	for _, p := range ps {
		if p.t.Verdict != "" {
			continue
		}
		if a.o.Sender.DryRun() {
			p.t.Judgement = Judgement{Skipped, "dry run"}
			continue
		}
		c := Case{Write: write && !a.o.ControlWrites, Trial: p.ans, Controls: controls, Stale: len(p.b.stale) > 0, Kept: len(p.b.kept) > 0, IsLogin: p.rc.login}
		p.t.Judgement = Judge(c)
		if p.t.Verdict == Bypass && noID == nil && !write {
			raw, _ := sr.Raw()
			if bare := strip(raw, sr.Entry.URL, sr.Derived); bare != nil {
				if ans, err := a.o.Sender.Send(ctx, bare, schemeOf(sr.Entry.URL), "no-identity", "(none)", it.Key, nil); err == nil {
					noID = &ans
				}
			}
		}
		if p.t.Verdict == Bypass && noID != nil {
			c.NoIdentity = noID
			p.t.Judgement = Judge(c)
		}
		if p.t.Verdict == Enforced && !a.alive(ctx, p.rc) {
			p.t.Judgement = Judgement{Unclear, "refused, and the role's session is dead now: " + p.rc.deadWhy()}
		}
	}
	for _, p := range ps {
		out.Trials = append(out.Trials, p.t)
	}
	return out, nil
}

// downgrade turns into unclear the refusals of a role whose session died,
// answered after its last good probe began: the session may have died
// before the probe told. Those answered before it stand: the session lived
// after them. It runs once all items are done (they finish in any order).
func (a *authz) downgrade() {
	for _, rc := range a.roles {
		why := rc.deadWhy()
		if why == "" {
			continue
		}
		for i := range a.out.Items {
			for j := range a.out.Items[i].Trials {
				t := &a.out.Items[i].Trials[j]
				if t.Role == rc.name && t.Verdict == Enforced && !t.At.Before(rc.goodAt) {
					t.Judgement = Judgement{Unclear, "refused, but the role's session died near then: " + why}
				}
			}
		}
	}
}

// exclusive holds a role to one trial at a time when that is needed: its
// request takes a credential fresh (a later one could undo the token), or
// the server turns the role's cookie. It returns the release.
func (a *authz) exclusive(rc *roleCtx, r *export.Request) func() {
	needs := rc.rotates.Load()
	for at, from := range r.Derived {
		if credentialLink(at, from) {
			needs = true
		}
	}
	if !needs {
		return func() {}
	}
	rc.serial.Lock()
	return rc.serial.Unlock
}

// sample is the role whose request an item is tried from: the one it
// belongs to, else the highest that used it, with a request to replay.
func (a *authz) sample(it roles.Item) (*roleCtx, *export.Request) {
	try := func(rc *roleCtx) *export.Request {
		if s := it.States[rc.name]; s != roles.Used && s != roles.Held {
			return nil
		}
		if reqs := matching(rc.model, it.Key); len(reqs) > 0 {
			return export.Best(reqs)
		}
		return nil
	}
	// A shape that differs is the higher role's: its extra parameters are
	// what to try.
	shape := it.Class == roles.ShapeDiffers || slices.Contains(it.Also, roles.ShapeDiffers)
	if it.Native != "" && !shape {
		for _, rc := range a.roles {
			if rc.name == it.Native {
				if r := try(rc); r != nil {
					return rc, r
				}
			}
		}
	}
	for i := len(a.roles) - 1; i > 0; i-- {
		if r := try(a.roles[i]); r != nil {
			return a.roles[i], r
		}
	}
	return nil, nil
}

func (a *authz) trialFile(key, role string, raw []byte) string {
	if a.o.Out == "" {
		return ""
	}
	name := fmt.Sprintf("trials/%s.%s.http", slugKey(key), role)
	p := filepath.Join(a.o.Out, name)
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil || os.WriteFile(p, raw, 0o600) != nil {
		return ""
	}
	return name
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugKey(k string) string {
	method, _, tmpl, op := keyParts(k)
	s := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(method+"-"+tmpl+"-"+op), "-"), "-")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func schemeOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Scheme
	}
	return "https"
}
