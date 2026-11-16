package flow

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

var t0 = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

// ev makes an event of document "D" at time stamp ts (ms), reported at
// wall time t0+ts.
func ev(typ string, ts float64, trusted bool, id string) Event {
	return Event{Tag: fmt.Sprintf("D:%g:%s", ts, typ), Type: typ, Wall: at(int(ts)), Trusted: trusted, Top: true,
		URL: "http://app/", Element: &Element{Tag: "button", ID: id, Label: id}}
}

func tag(e Event) string { return "jsh:" + e.Tag }

func req(id, ms int, method, path string, chain ...string) Request {
	return Request{ID: id, Time: at(ms), End: at(ms + 20), Target: "page", Page: "http://app/", Method: method,
		URL: "http://app" + path, ResourceType: "Fetch", Outcome: "ok", Chain: chain,
		Stack: []Frame{{URL: "http://app/app.js", Func: "apiClient", Line: 3, Col: 9}}}
}

func flowsByAction(fs []Flow) map[string][]int {
	out := map[string][]int{}
	for _, f := range fs {
		key := f.Kind + " " + f.Label
		if f.StartedBy != "" {
			key = "background by " + f.StartedBy
		}
		for _, r := range f.Requests {
			out[key] = append(out[key], r.ID)
		}
	}
	return out
}

func TestBuildAttribution(t *testing.T) {
	events, reqs := attributionCase()
	fs := Build(events, reqs, Options{Run: "r"})
	got := flowsByAction(fs)
	want := map[string][]int{
		"load load http://app/":       {1, 2},
		"click button \"search\"":     {3, 4, 15},
		"submit button \"profile\"":   {5, 6, 7},
		"click button \"outer\"":      {8},
		"click button \"legacy\"":     {11},
		"click button \"export\"":     {12},
		"click button \"start-poll\"": {17},
		"background by a5":            {9, 10, 18},
		"background background":       {13, 14, 19},
	}
	for k, ids := range want {
		g := got[k]
		slices.Sort(g)
		if !slices.Equal(g, ids) {
			t.Errorf("%s: %v, want %v", k, g, ids)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected flow %s: %v", k, got[k])
		}
	}
	// One gesture each: Enter gave one action, the nested click none.
	n := 0
	for _, f := range fs {
		if f.Kind != "background" && f.Kind != "load" {
			n++
		}
	}
	if n != 6 {
		t.Errorf("%d user actions, want 6", n)
	}
	for _, f := range fs {
		for _, r := range f.Requests {
			wantHow := map[int]string{2: Window, 11: Handler, 12: Window, 15: Window}[r.ID]
			if wantHow == "" && f.Kind != "background" {
				wantHow = Causal
			}
			if f.Kind == "load" && r.ID == 1 {
				wantHow = Window
			}
			if r.How != wantHow {
				t.Errorf("request %d: how %q, want %q", r.ID, r.How, wantHow)
			}
		}
	}
}

// attributionCase is TestBuildAttribution's page: every way a request comes
// to an action.
func attributionCase() ([]Event, []Request) {
	load := Request{ID: 1, Time: at(0), End: at(50), Target: "page", Page: "http://app/", Method: "GET", URL: "http://app/",
		ResourceType: "Document", Outcome: "ok", MainDocument: true}
	search := ev("click", 2000, true, "search")
	// Enter in a form: keydown, a click on the submit button, then submit.
	enterKey, enterClick, enterSubmit := ev("keydown", 4000, true, "q"), ev("click", 4002, true, "save"), ev("submit", 4003, true, "profile")
	// The app clicks something for itself inside the user's click.
	outer, inner := ev("click", 6000, true, "outer"), ev("click", 6001.5, false, "inner")
	poll := ev("click", 8000, true, "start-poll")
	legacy := ev("click", 12000, true, "legacy")
	export := ev("click", 14000, true, "export")
	events := []Event{search, enterKey, enterClick, enterSubmit, outer, inner, poll, legacy, export}

	reqs := []Request{
		load,
		req(2, 300, "GET", "/api/me"), // page start, no async parent: the load's window
		req(3, 2050, "GET", "/api/search", tag(search)),
		req(4, 2400, "GET", "/api/search/more", "setTimeout", tag(search)),
		req(5, 4050, "GET", "/api/csrf", tag(enterSubmit)),
		req(6, 4100, "POST", "/api/profile", "await", tag(enterSubmit)),
		// The submit's own tag lost (a shadow root's submit: no event of its own).
		req(7, 4120, "GET", "/api/shadow", "jsh:D:4003.4:submit"),
		req(8, 6050, "GET", "/api/nested", tag(inner), tag(outer)),
		// A poll the click started: every tick under a setInterval.
		req(9, 9000, "GET", "/api/status", "setInterval", tag(poll)),
		req(10, 10000, "GET", "/api/status", "setInterval", tag(poll)),
		// The tagger's own timer links: a delay is the action's, a repeating
		// timer is background work it started.
		req(17, 9500, "GET", "/api/delayed", tag(poll)+":setTimeout"),
		req(18, 11000, "GET", "/api/status", tag(poll)+":setInterval"),
		// An HTML attribute handler: its frame is "onclick", no async parent.
		{ID: 11, Time: at(12010), End: at(12030), Page: "http://app/", Method: "GET", URL: "http://app/api/legacy", Outcome: "ok",
			Stack: []Frame{{URL: "http://app/app.js", Func: "legacyLoad"}, {URL: "http://app/", Func: "onclick"}}},
		// A worker's request: its stack ends in onmessage, which is no
		// element's handler, and has no async parent.
		{ID: 12, Time: at(14100), End: at(14120), Target: "worker", Method: "GET", URL: "http://app/api/export", Outcome: "ok",
			Stack: []Frame{{URL: "http://app/export-worker.js", Func: "onmessage", Line: 1, Col: 21}}},
		// Noise: a page timer, and a late load-time timeout with no tag.
		req(13, 2100, "GET", "/api/notifications", "setInterval"),
		req(14, 4110, "GET", "/api/notifications", "setInterval"),
		// A bare timer link, no tag: the tagger was not there (it names every
		// timer it sees), so by time: inside the search's window.
		req(15, 2200, "GET", "/api/late", "setTimeout"),
		// A timer set outside any action, inside a user's click's time.
		req(19, 2060, "GET", "/api/late2", "jsh:none:D:setTimeout"),
		// jsharvest's own request is left out.
		{ID: 16, Time: at(5000), Method: "GET", URL: "http://app/x.js", Internal: true},
	}
	return events, reqs
}

// inLane is a case moved to another tab: shift later, its request ids
// plus 100, its document named doc.
func inLane(events []Event, reqs []Request, lane int, shift time.Duration, doc string) ([]Event, []Request) {
	var es []Event
	for _, e := range events {
		e.Lane, e.Wall = lane, e.Wall.Add(shift)
		e.Tag = strings.Replace(e.Tag, "D:", doc+":", 1)
		es = append(es, e)
	}
	var rs []Request
	for _, r := range reqs {
		r.Lane, r.ID, r.Time, r.End = lane, r.ID+100*lane, r.Time.Add(shift), r.End.Add(shift)
		r.Chain = slices.Clone(r.Chain)
		for i, c := range r.Chain {
			r.Chain[i] = strings.Replace(c, "D:", doc+":", 1)
		}
		rs = append(rs, r)
	}
	return es, rs
}

// byTab keys a run's flows by tab, then as flowsByAction does, with the
// request ids of the tab's own numbering and a background's starter
// named by its label.
func byTab(fs []Flow) map[int]map[string][]int {
	label := map[string]string{}
	for _, f := range fs {
		label[f.Action] = f.Kind + " " + f.Label
	}
	out := map[int]map[string][]int{}
	for _, f := range fs {
		key := f.Kind + " " + f.Label
		if f.StartedBy != "" {
			key = "background by " + label[f.StartedBy]
		}
		if out[f.Tab] == nil {
			out[f.Tab] = map[string][]int{}
		}
		for _, r := range f.Requests {
			out[f.Tab][key] = append(out[f.Tab][key], r.ID-100*f.Tab)
		}
		slices.Sort(out[f.Tab][key])
	}
	return out
}

// TestLanes: tabs at work at once (crawl -tabs). The same page in three
// tabs, their times interleaved, gives each tab what the page alone gives:
// a request goes to an action of its own tab only, by tag, handler, window
// or timer. The third tab's document has the first's name, its tags the
// same text: a tag is a tab's.
func TestLanes(t *testing.T) {
	events, reqs := attributionCase()
	alone := byTab(Build(events, reqs, Options{Run: "r"}))[0]
	var allE []Event
	var allR []Request
	for lane, c := range []struct {
		shift time.Duration
		doc   string
	}{{0, "D"}, {700 * time.Millisecond, "E"}, {0, "D"}} {
		es, rs := inLane(events, reqs, lane, c.shift, c.doc)
		allE, allR = append(allE, es...), append(allR, rs...)
	}
	fs := Build(allE, allR, Options{Run: "r"})
	got := byTab(fs)
	for lane := range 3 {
		if fmt.Sprint(got[lane]) != fmt.Sprint(alone) {
			t.Errorf("tab %d:\n%v\nwant\n%v", lane, got[lane], alone)
		}
	}
	ids := map[string]bool{}
	actions := map[int][]string{} // user actions by tab, those that sent nothing too
	for _, f := range fs {
		if ids[f.Action] {
			t.Errorf("action id %s twice", f.Action)
		}
		ids[f.Action] = true
		if f.Kind != "background" && f.Kind != "load" {
			actions[f.Tab] = append(actions[f.Tab], f.Kind+" "+f.Label)
		}
	}
	// One gesture each, as alone (TestBuildAttribution): another tab's
	// events at the same moments do not split a gesture.
	for lane := range 3 {
		if len(actions[lane]) != 6 {
			t.Errorf("tab %d: %d user actions, want 6: %q", lane, len(actions[lane]), actions[lane])
		}
	}
}

// TestLanesWindow: a request with no stack goes to the window of its own
// tab's action, not to another tab's that began just before it; three tabs
// loading a page each at -page-rate, each asking /api/config, are no timer.
func TestLanesWindow(t *testing.T) {
	var reqs []Request
	for lane := range 3 {
		ms := 500 * lane
		reqs = append(reqs,
			Request{ID: 10*lane + 1, Lane: lane, Time: at(ms), End: at(ms + 50), Target: "page", Page: "http://app/p", Method: "GET",
				URL: fmt.Sprintf("http://app/p%d", lane), ResourceType: "Document", Outcome: "ok", MainDocument: true},
			// Lane 0's comes after lane 1's page began.
			Request{ID: 10*lane + 2, Lane: lane, Time: at(ms + 700), End: at(ms + 720), Target: "page", Page: fmt.Sprintf("http://app/p%d", lane),
				Method: "GET", URL: "http://app/api/config", ResourceType: "Fetch", Outcome: "ok"})
	}
	for _, f := range Build(nil, reqs, Options{Run: "r"}) {
		if f.Kind != "load" {
			t.Errorf("flow %s %q: %v", f.Kind, f.Label, f.Requests)
			continue
		}
		want := fmt.Sprintf("[{%d window} {%d window}]", 10*f.Tab+1, 10*f.Tab+2)
		if fmt.Sprint(f.Requests) != want {
			t.Errorf("tab %d: %v, want %s", f.Tab, f.Requests, want)
		}
	}
}

// TestLanesNotPeriodic: three tabs that load a page each at -page-rate and
// ask /api/config two seconds later send three requests half a second
// apart; those of three tabs are no timer, each is its page load's.
func TestLanesNotPeriodic(t *testing.T) {
	var reqs []Request
	for lane := range 3 {
		ms := 500 * lane
		page := fmt.Sprintf("http://app/p%d", lane)
		reqs = append(reqs,
			Request{ID: 10*lane + 1, Lane: lane, Time: at(ms), End: at(ms + 50), Target: "page", Page: page, Method: "GET",
				URL: page, ResourceType: "Document", Outcome: "ok", MainDocument: true},
			Request{ID: 10*lane + 2, Lane: lane, Time: at(ms + 2000), End: at(ms + 2020), Target: "page", Page: page,
				Method: "GET", URL: "http://app/api/config", ResourceType: "Fetch", Outcome: "ok"})
	}
	for _, f := range Build(nil, reqs, Options{Run: "r"}) {
		want := fmt.Sprintf("[{%d window} {%d window}]", 10*f.Tab+1, 10*f.Tab+2)
		if f.Kind != "load" || fmt.Sprint(f.Requests) != want {
			t.Errorf("tab %d %s: %v, want %s", f.Tab, f.Kind, f.Requests, want)
		}
	}
}

// TestLanesPollNearOtherTab: a poll of tab 0 with no stack, every second,
// is a timer even when each tick comes just after a page load of tab 1:
// only its own tab's actions make a tick look like an action's work.
func TestLanesPollNearOtherTab(t *testing.T) {
	reqs := []Request{{ID: 1, Time: at(0), End: at(50), Target: "page", Page: "http://app/a", Method: "GET",
		URL: "http://app/a", ResourceType: "Document", Outcome: "ok", MainDocument: true}}
	for n := range 4 {
		ms := 2000 + 1000*n
		reqs = append(reqs,
			Request{ID: 10 + n, Lane: 1, Time: at(ms - 100), End: at(ms - 50), Target: "page", Page: "http://app/b", Method: "GET",
				URL: fmt.Sprintf("http://app/b%d", n), ResourceType: "Document", Outcome: "ok", MainDocument: true},
			Request{ID: 20 + n, Time: at(ms), End: at(ms + 20), Target: "page", Page: "http://app/a", Method: "GET",
				URL: "http://app/api/status", ResourceType: "Fetch", Outcome: "ok"})
	}
	for _, f := range Build(nil, reqs, Options{Run: "r"}) {
		if f.Tab == 0 && f.Kind == "load" && len(f.Requests) != 1 {
			t.Errorf("the poll went to the page load: %v", f.Requests)
		}
		if f.Tab == 0 && f.Kind == "background" && len(f.Requests) != 4 {
			t.Errorf("background: %v, want the four ticks", f.Requests)
		}
	}
}

// TestNestedLateTimeStamp: a busy page dispatches a click late; its time
// stamp is when the browser took it, the submit it causes is stamped when
// made, 12 ms on. Reported in the same millisecond, they are one gesture.
// Two clicks 12 ms apart, reported 12 ms apart, are two.
func TestNestedLateTimeStamp(t *testing.T) {
	click, submit := ev("click", 1000, true, "save"), ev("submit", 1012, true, "profile")
	submit.Wall = click.Wall
	fs := Build([]Event{click, submit}, []Request{req(1, 1020, "POST", "/api/profile", tag(submit))}, Options{Run: "r"})
	if len(fs) != 1 || fs[0].Kind != "submit" || len(fs[0].Requests) != 1 {
		t.Errorf("nested: %+v", fs)
	}
	a, b := ev("click", 1000, true, "a"), ev("click", 1012, true, "b")
	if fs := Build([]Event{a, b}, nil, Options{Run: "r"}); len(fs) != 2 {
		t.Errorf("two clicks: %d flows", len(fs))
	}
}

// A user action closes the window of the one before; the page clicking
// for itself does not.
func TestWindowClosedByNextAction(t *testing.T) {
	a, b := ev("click", 1000, true, "a"), ev("click", 1200, true, "b")
	reqs := []Request{
		{ID: 1, Time: at(1100), Target: "worker", Method: "GET", URL: "http://app/w1", Outcome: "ok"},
		{ID: 2, Time: at(1300), Target: "worker", Method: "GET", URL: "http://app/w2", Outcome: "ok"},
		{ID: 3, Time: at(9000), Target: "worker", Method: "GET", URL: "http://app/w3", Outcome: "ok"}, // quiet by then
	}
	got := flowsByAction(Build([]Event{a, b}, reqs, Options{}))
	if !slices.Equal(got["click button \"a\""], []int{1}) || !slices.Equal(got["click button \"b\""], []int{2}) ||
		!slices.Equal(got["background background"], []int{3}) {
		t.Errorf("%v", got)
	}
}

func TestTemplatesInFlows(t *testing.T) {
	var events []Event
	var reqs []Request
	for i, id := range []string{"42", "108", "7"} {
		e := ev("click", float64(1000*(i+1)), true, "open")
		events = append(events, e)
		r := req(i+1, 1000*(i+1)+10, "GET", "/api/items/"+id, tag(e))
		r.Stack = []Frame{{URL: "http://app/app.js", Func: "apiClient", Line: 3, Col: 9}, {URL: "http://app/app.js", Func: "open", Line: 20, Col: 4}}
		reqs = append(reqs, r)
	}
	// apiClient is on top of three endpoints, so it is a hub.
	for i, p := range []string{"/api/a", "/api/b", "/api/c"} {
		reqs = append(reqs, req(10+i, 20000+i, "GET", p))
	}
	frames := appFrames(reqs, func(string) bool { return false })
	if !strings.Contains(frames[0], "#open:20:4") {
		t.Errorf("app frame %q, want the open() call, not the apiClient hub", frames[0])
	}
	for _, f := range Build(events, reqs, Options{}) {
		for _, ep := range f.Endpoints {
			if strings.HasPrefix(ep.Template, "/api/items") && ep.Template != "/api/items/{id}" {
				t.Errorf("template %q", ep.Template)
			}
		}
	}
}

func TestDependsOn(t *testing.T) {
	csrfResp := traffic.Entry{URL: "http://app/api/csrf", Method: "GET", Response: &traffic.Response{
		MIME: "application/json", Headers: map[string]string{"set-cookie": "sid=Sx81kQ2z; Path=/", "content-type": "application/json"},
		Body: traffic.Body{Body: `{"csrf":"3caf6efd146fc1a5","limit":100,"year":2026,"kind":"profile","order_id":88123}`}}}
	post := traffic.Entry{URL: "http://app/api/orders/88123?limit=100&year=2026&kind=profile", Method: "POST",
		Headers: map[string]string{"x-csrf-token": "3caf6efd146fc1a5", "cookie": "sid=Sx81kQ2z", "content-type": "application/json"},
		Body:    traffic.Body{Body: `{"note":"profile"}`}}
	reqs := []Request{
		{ID: 1, Time: at(0), End: at(10), Method: "GET", URL: csrfResp.URL, Provides: ResponseValues(csrfResp)},
		{ID: 2, Time: at(20), End: at(30), Method: "POST", URL: post.URL, Uses: RequestValues(post)},
		// Started before the response ended: cannot carry its values.
		{ID: 3, Time: at(5), End: at(40), Method: "POST", URL: post.URL, Uses: RequestValues(post)},
	}
	links := dependsOn(reqs)
	var got []string
	for _, l := range links {
		got = append(got, fmt.Sprintf("%d %s <- %d %s", l.Request, l.At, l.From.Request, l.From.At))
	}
	slices.Sort(got)
	want := []string{"2 header:x-csrf-token <- 1 json:$.csrf", "2 path:3 <- 1 json:$.order_id"}
	if !slices.Equal(got, want) {
		t.Errorf("links:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestWorth(t *testing.T) {
	for v, want := range map[string]bool{
		"3caf6efd146fc1a5": true, "88123": true, "Sx81kQ2z": true, "eyJhbGciOi.x.y": true,
		"100": false, "2026": false, "profile": false, "true": false, "abc": false, "hello world": false,
	} {
		if worth(v) != want {
			t.Errorf("worth(%q) = %v", v, !want)
		}
	}
}

// Findings of the code review, each as it failed.
func TestReviewCases(t *testing.T) {
	click := ev("click", 1000, true, "save")
	typing := ev("keydown", 1500, true, "q")
	other := ev("click", 30000, true, "other")
	reqs := []Request{
		// 1. A timer set after an await in the handler: named "none", but
		// the click's tag is further down.
		req(1, 1200, "POST", "/api/create", "jsh:none:D:setTimeout", "setTimeout", "await", tag(click)),
		// 2. A chain with no tag at all, inside the click's window.
		req(2, 1100, "POST", "/api/untagged", "await"),
		// 9. A worker's request after the user began typing: still the click's.
		{ID: 3, Time: at(1600), End: at(1620), Target: "worker", Method: "GET", URL: "http://app/api/export", Outcome: "ok"},
	}
	fs := Build([]Event{click, typing, other}, reqs, Options{})
	got := flowsByAction(fs)
	if g := got["click button \"save\""]; !slices.Equal(g, []int{1, 2, 3}) {
		t.Errorf("save: %v, want [1 2 3] (%v)", g, got)
	}
	_ = other
}

func TestChunkedUploadNotPeriodic(t *testing.T) {
	up := ev("click", 1000, true, "upload")
	var reqs []Request
	for n := 0; n < 4; n++ {
		r := req(n+1, 1100+600*n, "PUT", fmt.Sprintf("/api/upload/%d", n), "await", tag(up))
		r.End = r.Time.Add(590 * time.Millisecond)
		reqs = append(reqs, r)
	}
	got := flowsByAction(Build([]Event{up}, reqs, Options{}))
	if g := got["click button \"upload\""]; !slices.Equal(g, []int{1, 2, 3, 4}) {
		t.Errorf("upload: %v (%v)", g, got)
	}
}

func TestSteadyClicksNotPeriodic(t *testing.T) {
	// A worker feature used three times at a steady pace: each request in
	// its click's first moments, so not a poll.
	var events []Event
	var reqs []Request
	for n := 0; n < 3; n++ {
		events = append(events, ev("click", float64(1000+3000*n), true, "export"))
		reqs = append(reqs, Request{ID: n + 1, Time: at(1050 + 3000*n), End: at(1070 + 3000*n), Target: "worker",
			Method: "GET", URL: "http://app/api/export", Outcome: "ok"})
	}
	for _, f := range Build(events, reqs, Options{}) {
		if f.Kind == "background" {
			t.Errorf("export clicks taken for a poll: %+v", f.Requests)
		}
	}
}

func TestIntervalFirstFiringIsADelay(t *testing.T) {
	// RxJS's delay: an interval's first firing, which the tagger names
	// setTimeout; only later firings are named setInterval.
	c := ev("click", 1000, true, "find")
	reqs := []Request{req(1, 1300, "GET", "/api/find", tag(c)+":setTimeout", "setInterval", tag(c))}
	got := flowsByAction(Build([]Event{c}, reqs, Options{}))
	if !slices.Equal(got["click button \"find\""], []int{1}) {
		t.Errorf("%v", got)
	}
}

func TestPollFirstTickIsBackground(t *testing.T) {
	// A click that starts a poll: the interval's first tick is named like a
	// delay, the later ones as a repeating timer; all ticks are the poll.
	c := ev("click", 1000, true, "live")
	reqs := []Request{
		req(1, 1010, "POST", "/api/live/start", tag(c)),
		req(2, 1710, "GET", "/api/live/tick", tag(c)+":setTimeout"),
		req(3, 2410, "GET", "/api/live/tick", tag(c)+":setInterval"),
		req(4, 3110, "GET", "/api/live/tick", tag(c)+":setInterval"),
	}
	got := flowsByAction(Build([]Event{c}, reqs, Options{}))
	if !slices.Equal(got["click button \"live\""], []int{1}) || len(got["background by a1"]) != 3 {
		t.Errorf("%v", got)
	}
}

// A click comes as pointerup, mouseup and click with one time stamp; only
// the click describes its element, which names the gesture.
func TestGestureNamedByDescribedEvent(t *testing.T) {
	click := ev("click", 1000, true, "save")
	up := Event{Tag: "D:1000:pointerup", Type: "pointerup", Wall: at(1000), Trusted: true, Top: true, URL: "http://app/"}
	mouse := up
	mouse.Tag, mouse.Type = "D:1000:mouseup", "mouseup"
	fs := Build([]Event{up, mouse, click}, []Request{req(1, 1010, "POST", "/api/save", tag(click))}, Options{})
	for _, f := range fs {
		if f.Kind == "click" {
			if f.Element == nil || f.Element.ID != "save" || f.Label != `button "save"` {
				t.Fatalf("click named %q, element %+v", f.Label, f.Element)
			}
			return
		}
	}
	t.Fatalf("no click flow in %+v", fs)
}

// Explore's steps: a hover it notes before moving the pointer, the
// handlers it triggers (wrapped, not reported), a press before a click,
// a navigation it kept the page from, and controls that send nothing.
func TestExploreSteps(t *testing.T) {
	hover := Event{Tag: "D:1000:hover", Type: "hover", Wall: at(1000), Trusted: true, Top: true, URL: "http://app/",
		Element: &Element{Tag: "div", ID: "menu", Label: "Menu"}}
	click := ev("click", 3000, true, "save")
	empty := ev("click", 5000, true, "nothing")
	events := []Event{hover, click, empty}
	held := req(5, 3010, "GET", "/elsewhere")
	held.Outcome = "held_back:explore-navigation"
	reqs := []Request{
		// The mouseenter handler, 3 ms after the note, and a timer it set.
		req(1, 1003, "GET", "/api/menu", "jsh:D:1003:mouseenter"),
		req(2, 1300, "GET", "/api/menu-later", "jsh:D:1003:mouseenter:setTimeout"),
		// An IntersectionObserver callback: no tag.
		req(3, 1100, "GET", "/api/lazy"),
		// A mousedown handler of the click's own gesture, 2 ms before it.
		req(4, 2998, "POST", "/api/press", "jsh:D:2998:mousedown"),
		held,
	}
	fs := Build(events, reqs, Options{DropEmpty: true})
	got := flowsByAction(fs)
	if !slices.Equal(got[`hover div "Menu"`], []int{1, 2, 3}) {
		t.Errorf("hover: %v", got)
	}
	if !slices.Equal(got[`click button "save"`], []int{4, 5}) {
		t.Errorf("click: %v", got)
	}
	for _, f := range fs {
		if f.Label == `button "nothing"` {
			t.Error("an empty gesture kept with DropEmpty")
		}
		if f.Label == `button "save"` && !slices.Equal(f.Writes, []int{4}) {
			t.Errorf("writes %v: a held navigation is no write", f.Writes)
		}
	}
	// Without DropEmpty (watch), the empty click stays.
	if !slices.ContainsFunc(Build(events, reqs, Options{}), func(f Flow) bool { return f.Label == `button "nothing"` }) {
		t.Error("watch lost an empty click")
	}
}

// A mousedown handler's request comes in the second after an explore hover
// of another element: it is the click's, which comes right after it.
func TestPressAfterHover(t *testing.T) {
	hover := Event{Tag: "D:1000:hover", Type: "hover", Wall: at(1000), Trusted: true, Top: true, URL: "http://app/",
		Element: &Element{Tag: "div", ID: "intent", Label: "Hover"}}
	click := ev("click", 1900, true, "press")
	reqs := []Request{
		req(1, 1003, "GET", "/api/intent", "jsh:D:1003:mouseenter"),
		req(2, 1899, "GET", "/api/press", "jsh:D:1899:mousedown"),
		req(3, 1898, "GET", "/api/enter", "jsh:D:1898:mouseenter"),
	}
	got := flowsByAction(Build([]Event{hover, click}, reqs, Options{DropEmpty: true}))
	if !slices.Equal(got[`hover div "Hover"`], []int{1}) || !slices.Equal(got[`click button "press"`], []int{2, 3}) {
		t.Fatalf("%v", got)
	}
}

// Round 25I: the tagger names its tasks with marker.TaskPrefix; flows read
// them as they read the older "jsh:" names.
func TestTaskPrefixRead(t *testing.T) {
	click := ev("click", 1000, true, "save")
	for _, p := range []string{marker.TaskPrefix, marker.LegacyTaskPrefix} {
		reqs := []Request{
			req(1, 1200, "POST", "/api/create", p+"none:D:setTimeout", "setTimeout", "await", p+click.Tag),
			req(2, 9000, "GET", "/api/poll", p+"none:D:setInterval"),
		}
		got := flowsByAction(Build([]Event{click}, reqs, Options{}))
		if g := got["click button \"save\""]; !slices.Equal(g, []int{1}) {
			t.Errorf("prefix %q: save %v (%v)", p, g, got)
		}
	}
}
