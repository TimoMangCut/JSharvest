package flow

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/marker"
)

type Options struct {
	Run       string
	Quiet     time.Duration // an action's window ends this long after its last request
	MaxWindow time.Duration // and at most this long after it started
	// ThirdParty reports whether a script URL is outside the target's
	// scope; its frames are not the application's.
	ThirdParty func(url string) bool
	// DropEmpty leaves out the gestures that sent nothing. A crawl's
	// explore tries every control of a page, and most send nothing; a
	// person's clicks in watch are kept, empty or not.
	DropEmpty bool
}

func (o *Options) defaults() {
	if o.Quiet <= 0 {
		o.Quiet = 1500 * time.Millisecond
	}
	if o.MaxWindow <= 0 {
		o.MaxWindow = 10 * time.Second
	}
	if o.ThirdParty == nil {
		o.ThirdParty = func(string) bool { return false }
	}
}

// gestureGap is the widest gap between the events of one gesture:
// pointerup, mouseup and click share a time stamp; keydown, click and
// submit of an Enter in a form come about 2 ms apart.
const gestureGap = 5.0 // ms

// nestGap: an event the page reported within this much wall time of the
// one before, in its document, was dispatched inside it (the submit a
// click causes). Its time stamp may be later by more than gestureGap: a
// trusted input's is when the browser took it, and a busy page dispatches
// it late. No person, and not explore, acts twice within it.
const nestGap = 2 * time.Millisecond

// A hover or scroll of explore's is noted just before its input is sent
// (see engine's explore): the events it causes come within stepGap of it.
// The pointer's coming onto an element and pressing it (wrapped, not
// reported) belong to the click that comes within pressGap after them.
const (
	stepGap  = 1000.0 // ms
	pressGap = 500.0  // ms; explore waits longer than this between actions
)

var pressTypes = map[string]bool{"mousedown": true, "pointerdown": true, "touchstart": true,
	"mouseover": true, "mouseenter": true, "pointerover": true, "pointerenter": true}

// gap is how long after a gesture's last event a tag still belongs to it.
func gap(a *action) float64 {
	if a.types["hover"] || a.types["scroll"] {
		return stepGap
	}
	return gestureGap
}

// action is a gesture of the user (or the page), a navigation, or the
// background bucket of a page.
type action struct {
	id      string
	lane    int // the tab: an action owns only its own tab's requests
	kind    string
	label   string
	trusted bool
	element *Element
	page    string
	wall    time.Time
	doc     string
	ts0     float64 // time stamps of the first and last event, in the doc's clock
	ts1     float64
	wall1   time.Time // the latest event's wall time, for nestGap
	types   map[string]bool
	tags    map[string]bool

	last   time.Time // its latest request, for its window
	next   time.Time // when the next action that closes its window began
	refs   []Ref
	bgOf   string // for a background bucket: the action that started the work
	isBg   bool
	ended  time.Time
	closes bool // whether it closes the window of the one before
}

var kindOf = map[string]string{
	"submit": "submit", "click": "click", "dblclick": "click", "pointerup": "click", "mouseup": "click",
	"change": "change", "keydown": "key", "input": "input", "popstate": "nav", "hashchange": "nav",
	// No page reports these: explore adds them for what it does that no
	// tagged event names (see engine's explore).
	"hover": "hover", "scroll": "scroll",
}

// kindRank orders the kinds a gesture can be named by.
var kindRank = map[string]int{"submit": 0, "click": 1, "change": 2, "nav": 3, "key": 4, "input": 5, "hover": 6, "scroll": 7}

// gestures groups events into gestures: events of one document whose time
// stamps are at most gestureGap apart.
func gestures(events []Event) []*action {
	type ev struct {
		Event
		doc string
		ts  float64
	}
	var evs []ev
	for _, e := range events {
		doc, ts, _, ok := tagParts(e.Tag)
		if !ok {
			continue
		}
		evs = append(evs, ev{e, doc, ts})
	}
	// Each document's events together, in its own clock: a gesture is one
	// document's, and the events of another (another tab's, at the same
	// moments) must not come between its events and split it. Build orders
	// the gestures by wall time after.
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].Lane != evs[j].Lane {
			return evs[i].Lane < evs[j].Lane
		}
		if evs[i].doc != evs[j].doc {
			return evs[i].doc < evs[j].doc
		}
		return evs[i].ts < evs[j].ts
	})
	var out []*action
	var cur *action
	var best int
	for _, e := range evs {
		if cur == nil || e.doc != cur.doc || e.Lane != cur.lane || (e.ts-cur.ts1 > gestureGap && e.Wall.Sub(cur.wall1) > nestGap) {
			cur = &action{lane: e.Lane, doc: e.doc, ts0: e.ts, ts1: e.ts, wall: e.Wall, page: e.URL,
				types: map[string]bool{}, tags: map[string]bool{}, kind: "", closes: true}
			out = append(out, cur)
			best = math.MaxInt
		}
		cur.ts1, cur.wall1 = e.ts, e.Wall
		cur.types[e.Type] = true
		cur.tags[e.Tag] = true
		cur.trusted = cur.trusted || e.Trusted
		// The gesture is named by its highest kind; within a kind, by the
		// event that describes its element (pointerup and mouseup come
		// before the click, and only the click does).
		k := kindOf[e.Type]
		if r, ok := kindRank[k]; ok && (r < best || (r == best && cur.element == nil && e.Element != nil)) {
			best, cur.kind, cur.element = r, k, e.Element
			if e.URL != "" {
				cur.page = e.URL
			}
		}
		if e.Wall.Before(cur.wall) {
			cur.wall = e.Wall
		}
	}
	for _, a := range out {
		if a.kind == "" {
			a.kind = "click"
		}
		// Only what the user did ends the window of the action before:
		// the page clicking for itself is part of the work under way, and
		// typing goes on while the work of a click comes in.
		a.closes = a.trusted && a.kind != "input" && a.kind != "key"
		a.label = gestureLabel(a)
	}
	return out
}

func gestureLabel(a *action) string {
	if a.kind == "nav" {
		return "nav " + a.page
	}
	e := a.element
	if e == nil {
		return a.kind
	}
	what := e.Role
	if what == "" {
		what = e.Tag
	}
	switch {
	case e.Label != "":
		return fmt.Sprintf("%s %q", what, e.Label)
	case e.ID != "":
		return what + "#" + e.ID
	case e.Selector != "":
		return e.Selector
	}
	return what
}

// Build groups the run's requests under the actions that caused them.
func Build(events []Event, reqs []Request, o Options) []Flow {
	o.defaults()
	acts := gestures(events)
	for i := range reqs {
		r := &reqs[i]
		if r.MainDocument {
			acts = append(acts, &action{lane: r.Lane, kind: "load", label: "load " + r.URL, trusted: true, page: r.URL,
				wall: r.Time, closes: true, types: map[string]bool{}, tags: map[string]bool{}})
		}
	}
	sort.SliceStable(acts, func(i, j int) bool { return acts[i].wall.Before(acts[j].wall) })
	for i, a := range acts {
		a.id = fmt.Sprintf("a%d", i+1)
		a.last = a.wall
		for _, b := range acts[i+1:] {
			if b.closes && b.lane == a.lane {
				a.next = b.wall
				break
			}
		}
	}
	// Tags and documents are a tab's: the same names in two tabs are not
	// the same document.
	byTag := map[string]*action{}
	byDoc := map[string][]*action{}
	for _, a := range acts {
		for t := range a.tags {
			byTag[laneKey(a.lane, t)] = a
		}
		if a.doc != "" {
			byDoc[laneKey(a.lane, a.doc)] = append(byDoc[laneKey(a.lane, a.doc)], a)
		}
	}
	// A tag with no event of its own (a form's submit inside a shadow root,
	// an event type the reporter does not hear) belongs to the gesture just
	// before it, in its document.
	findTag := func(lane int, tag string) *action {
		if a := byTag[laneKey(lane, tag)]; a != nil {
			return a
		}
		doc, ts, typ, ok := tagParts(tag)
		if !ok {
			return nil
		}
		if typ, _, _ = strings.Cut(typ, ":"); pressTypes[typ] {
			// The pointer comes onto an element and presses before the
			// click: the click just after it.
			for _, a := range byDoc[laneKey(lane, doc)] {
				if a.ts0 >= ts && a.ts0-ts <= pressGap && (a.types["click"] || a.types["mouseup"] || a.types["pointerup"]) {
					return a
				}
			}
		}
		var best *action
		for _, a := range byDoc[laneKey(lane, doc)] {
			if a.ts0 <= ts+0.001 && ts-a.ts1 <= gap(a) {
				best = a
			}
		}
		return best
	}

	order := make([]int, len(reqs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return reqs[order[i]].Time.Before(reqs[order[j]].Time) })

	owner := make([]*action, len(reqs))
	how := make([]string, len(reqs))
	bgStarted := map[int]*action{} // background work an action started
	pending := []int{}
	for _, i := range order {
		r := &reqs[i]
		if r.Internal {
			continue
		}
		tagged, interval, none := chainOwner(r.Chain, func(tag string) *action { return findTag(r.Lane, tag) })
		switch {
		case none:
			// background: a timer set outside any action
		case tagged != nil && interval:
			bgStarted[i] = tagged
		case tagged != nil:
			owner[i], how[i] = tagged, Causal
			if r.Time.After(tagged.last) {
				tagged.last = r.Time
			}
		case interval:
			// background: a timer no action started
		default:
			if typ := attributeHandler(r); typ != "" && len(r.Chain) == 0 {
				if a := lastWithType(acts, r.Lane, typ, r.Time, o.MaxWindow); a != nil {
					owner[i], how[i] = a, Handler
					if r.Time.After(a.last) {
						a.last = r.Time
					}
					break
				}
			}
			// No stack to go by (a worker, a navigation), a chain whose tag
			// was lost or never set (a handler the tagger did not wrap, a
			// document without it): by time.
			pending = append(pending, i)
		}
	}

	// Work repeating on a timer is background even when an action started
	// it, or when the timer's chain lost its link.
	periodicBg := periodic(reqs, order, owner, bgStarted, acts, o)
	for _, i := range order {
		if periodicBg[i] && owner[i] != nil && how[i] == Causal {
			bgStarted[i] = owner[i]
			owner[i], how[i] = nil, ""
		}
	}
	for _, i := range pending {
		r := &reqs[i]
		if periodicBg[i] {
			continue
		}
		if a := windowOwner(acts, r.Lane, r.Time, o); a != nil {
			owner[i], how[i] = a, Window
			if r.Time.After(a.last) {
				a.last = r.Time
			}
		}
	}

	// Background buckets: one per page, and one per action that started
	// background work.
	bgs := map[string]*action{}
	bucket := func(lane int, page string, by *action) *action {
		key := page
		if lane != 0 {
			key = fmt.Sprintf("t%d|%s", lane, page)
		}
		if by != nil {
			key = "by " + by.id
		}
		b := bgs[key]
		if b == nil {
			b = &action{lane: lane, kind: "background", label: "background", page: page, isBg: true}
			if by != nil {
				b.bgOf, b.label, b.page = by.id, "background started by "+by.label, by.page
			}
			bgs[key] = b
		}
		return b
	}
	for _, i := range order {
		r := &reqs[i]
		if r.Internal || owner[i] != nil {
			continue
		}
		b := bucket(r.Lane, pageOf(r), bgStarted[i])
		owner[i] = b
		if b.wall.IsZero() || r.Time.Before(b.wall) {
			b.wall = r.Time
		}
	}
	for i, a := range owner {
		if a != nil {
			a.refs = append(a.refs, Ref{ID: reqs[i].ID, How: how[i]})
			if e := reqs[i].End; e.After(a.ended) {
				a.ended = e
			}
		}
	}

	templates := endpointTemplates(reqs, o)
	links := dependsOn(reqs)
	byID := map[int]int{}
	for i, r := range reqs {
		byID[r.ID] = i
	}

	all := slices.Clone(acts)
	keys := make([]string, 0, len(bgs))
	for k := range bgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for n, k := range keys {
		b := bgs[k]
		b.id = fmt.Sprintf("bg%d", n+1)
		all = append(all, b)
	}
	var out []Flow
	for _, a := range all {
		if len(a.refs) == 0 && (a.kind == "input" || a.kind == "key" || a.isBg || (o.DropEmpty && a.kind != "load")) {
			continue // typing that sent nothing
		}
		f := Flow{
			Run: o.Run, Action: a.id, Kind: a.kind, Tab: a.lane, Label: a.label, Trusted: a.trusted && !a.isBg, Element: a.element,
			Page: a.page, Started: a.wall, Ended: a.ended, StartedBy: a.bgOf, Requests: a.refs,
			Attribution: map[string]int{},
		}
		if f.Ended.Before(f.Started) {
			f.Ended = f.Started
		}
		if f.Requests == nil {
			f.Requests = []Ref{}
		}
		in := map[int]bool{}
		eps := map[string]*Endpoint{}
		var epOrder []string
		for _, ref := range a.refs {
			in[ref.ID] = true
			if ref.How != "" {
				f.Attribution[ref.How]++
			}
			r := reqs[byID[ref.ID]]
			if isWrite(r) {
				f.Writes = append(f.Writes, r.ID)
			}
			u, err := url.Parse(r.URL)
			if err != nil {
				continue
			}
			k := r.Method + " " + u.Host + " " + templates[byID[ref.ID]]
			ep := eps[k]
			if ep == nil {
				ep = &Endpoint{Method: r.Method, Host: u.Host, Template: templates[byID[ref.ID]]}
				eps[k] = ep
				epOrder = append(epOrder, k)
			}
			ep.Requests = append(ep.Requests, r.ID)
			if p := u.EscapedPath(); !slices.Contains(ep.Samples, p) && len(ep.Samples) < 5 {
				ep.Samples = append(ep.Samples, p)
			}
			if r.Outcome != "ok" && !slices.Contains(ep.Outcomes, r.Outcome) {
				ep.Outcomes = append(ep.Outcomes, r.Outcome)
			}
		}
		for _, k := range epOrder {
			ep := eps[k]
			if len(ep.Samples) == 1 && ep.Samples[0] == ep.Template {
				ep.Samples = nil
			}
			f.Endpoints = append(f.Endpoints, *ep)
		}
		for _, l := range links {
			if in[l.Request] {
				f.DependsOn = append(f.DependsOn, l)
			}
		}
		if len(f.Attribution) == 0 {
			f.Attribution = nil
		}
		out = append(out, f)
	}
	return out
}

// chainOwner reads a request's async chain: the action whose tag it
// carries (the nearest trusted one, or else the nearest), and whether a
// repeating timer lies between the request and that action, which makes
// the request background work the action started.
//
// The page's tagger names a timer an action set "jsh:<tag>:setTimeout" or
// "jsh:<tag>:setInterval" (see capture's tagScript); the latter is a
// repeating timer as surely as a bare "setInterval" link.
func chainOwner(chain []string, find func(string) *action) (owner *action, interval, none bool) {
	// The tagger's task names start with marker.TaskPrefix (default runs:
	// "pf8d1e7b:", older runs: "jsh:"): read as one.
	if slices.ContainsFunc(chain, func(d string) bool {
		_, ok := marker.CutTaskPrefix(d)
		return ok && !strings.HasPrefix(d, marker.LegacyTaskPrefix)
	}) {
		norm := make([]string, len(chain))
		for i, d := range chain {
			if rest, ok := marker.CutTaskPrefix(d); ok {
				d = marker.LegacyTaskPrefix + rest
			}
			norm[i] = d
		}
		chain = norm
	}
	var first, trusted *action
	firstAt, trustedAt, noneAt := -1, -1, -1
	for i, d := range chain {
		if !strings.HasPrefix(d, "jsh:") {
			continue
		}
		if strings.HasPrefix(d, "jsh:none:") {
			// A timer set outside a handler's synchronous run: after an await
			// in it, or outside any action. A tag further down still wins.
			if noneAt < 0 {
				noneAt = i
			}
			continue
		}
		tag := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(d, "jsh:"), ":setTimeout"), ":setInterval")
		a := find(tag)
		if a == nil {
			continue
		}
		if first == nil {
			first, firstAt = a, i
		}
		if a.trusted && trusted == nil {
			trusted, trustedAt = a, i
		}
	}
	at := firstAt
	owner = first
	if trusted != nil {
		owner, at = trusted, trustedAt
	}
	if owner == nil && noneAt >= 0 {
		// Only timers no action set: nothing the user did.
		return nil, strings.HasSuffix(chain[noneAt], ":setInterval") || slices.Contains(chain[:noneAt], "setInterval"), true
	}
	limit := len(chain)
	if owner != nil {
		limit = at + 1
	}
	interval = slices.ContainsFunc(chain[:limit], func(d string) bool {
		return d == "setInterval" || (strings.HasPrefix(d, "jsh:") && strings.HasSuffix(d, ":setInterval"))
	})
	return owner, interval, false
}

var onAttrRe = regexp.MustCompile(`^on([a-z]+)$`)

// attributeHandler returns the event type of an HTML attribute handler
// (<button onclick="…">) at the bottom of a request's stack: the tagger
// cannot wrap those, and Chrome names their function after the attribute.
func attributeHandler(r *Request) string {
	if len(r.Stack) == 0 || strings.Contains(r.Target, "worker") {
		return "" // a worker's onmessage is not an element's handler
	}
	m := onAttrRe.FindStringSubmatch(r.Stack[len(r.Stack)-1].Func)
	if m == nil || kindOf[m[1]] == "" {
		return ""
	}
	return m[1]
}

// lastWithType is the latest gesture before t, within max, that had an
// event of the given type.
func lastWithType(acts []*action, lane int, typ string, t time.Time, max time.Duration) *action {
	var best *action
	for _, a := range acts {
		if a.wall.After(t) {
			break
		}
		if a.lane == lane && a.types[typ] && t.Sub(a.wall) <= max {
			best = a
		}
	}
	return best
}

// windowOwner is the action whose window holds t: the last action that
// began before t, if the next one has not begun and it has not gone quiet.
func windowOwner(acts []*action, lane int, t time.Time, o Options) *action {
	var cand *action
	for _, a := range acts {
		if a.wall.After(t) {
			break
		}
		if a.closes && a.lane == lane {
			cand = a
		}
	}
	if cand == nil {
		return nil
	}
	if !cand.next.IsZero() && !t.Before(cand.next) {
		return nil
	}
	if t.Sub(cand.wall) > o.MaxWindow {
		return nil
	}
	// A page load runs its scripts when it can, so it is not held to the
	// quiet rule; the next action, or the longest window, ends it.
	if cand.kind != "load" && t.Sub(cand.last) > o.Quiet {
		return nil
	}
	return cand
}

// periodic marks the requests that repeat on a timer: three or more of the
// same method and shape, at roughly even intervals with idle time between
// them (not one request awaiting the last, as an upload in chunks does),
// either under one action (a poll it started) or under none, and then with
// at least one outside every action's first moments (not a button clicked
// at a steady pace).
func periodic(reqs []Request, order []int, owner []*action, started map[int]*action, acts []*action, o Options) map[int]bool {
	nearAction := func(lane int, t time.Time) bool {
		for _, a := range acts {
			if a.closes && a.lane == lane && !t.Before(a.wall) && t.Sub(a.wall) <= o.Quiet {
				return true
			}
		}
		return false
	}
	groups := map[string][]int{}
	for _, i := range order {
		r := reqs[i]
		u, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		// Under an action, a poll it started, with the ticks already known
		// as its background work (an interval's first tick looks like a
		// delay); otherwise any request with no tag (pending, or background
		// already), so that a poll whose chain was lost on a few ticks is
		// still seen as the poll it is.
		who := "-"
		switch {
		case owner[i] != nil:
			who = owner[i].id
		case started[i] != nil:
			who = started[i].id
		}
		k := strconv.Itoa(r.Lane) + " " + who + " " + r.Method + " " + u.Host + ByShape(u.EscapedPath())
		groups[k] = append(groups[k], i)
	}
	out := map[int]bool{}
	for _, idx := range groups {
		if len(idx) < 3 {
			continue
		}
		var gaps, idle []float64
		for n := 1; n < len(idx); n++ {
			prev, cur := reqs[idx[n-1]], reqs[idx[n]]
			gaps = append(gaps, cur.Time.Sub(prev.Time).Seconds())
			idle = append(idle, cur.Time.Sub(prev.End).Seconds())
		}
		mean, sd := meanSD(gaps)
		meanIdle, _ := meanSD(idle)
		if mean < 0.2 || sd > 0.35*mean || meanIdle < 0.5*mean {
			continue
		}
		if owner[idx[0]] == nil && started[idx[0]] == nil && !slices.ContainsFunc(idx, func(i int) bool { return !nearAction(reqs[i].Lane, reqs[i].Time) }) {
			continue
		}
		for _, i := range idx {
			out[i] = true
		}
	}
	return out
}

// laneKey names a tag or a document within its tab.
func laneKey(lane int, name string) string {
	if lane == 0 {
		return name
	}
	return strconv.Itoa(lane) + "|" + name
}

func meanSD(xs []float64) (float64, float64) {
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	var v float64
	for _, x := range xs {
		v += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(v / float64(len(xs)))
}

func pageOf(r *Request) string {
	if r.Page != "" {
		return r.Page
	}
	return r.URL
}

func isWrite(r Request) bool {
	switch strings.ToUpper(r.Method) {
	case "GET", "HEAD", "OPTIONS":
		// Held back by the guard as a write; a navigation explore kept the
		// page from making only names a page.
		return strings.HasPrefix(r.Outcome, "held_back") && r.Outcome != "held_back:explore-navigation"
	}
	return true
}
