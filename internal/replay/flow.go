package replay

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// FlowOptions configure the replay of one flow.
type FlowOptions struct {
	Model  *export.Model
	Run    string // the flow's run; the newest with that action when ""
	Action string // the flow's action id (a8, bg1)
	As     *Identity
	// Owner is the role the flow was recorded as: a credential it carried
	// that cannot be taken fresh is never sent as another role.
	Owner  string
	Policy Policy
	// AllowWrite sends writes; AllowDestructive destructive ones too.
	AllowWrite, AllowDestructive bool
	// KeepIDs takes only credentials fresh (a CSRF token), and keeps the
	// recorded ids and other values earlier responses gave.
	KeepIDs bool
	Sender  *Sender
	InScope func(host string) bool
}

// Step is one request of a flow's replay.
type Step struct {
	ID        int       `json:"id"`
	Role      string    `json:"as"`
	Purpose   string    `json:"purpose"` // prerequisite, step
	Method    string    `json:"method"`
	Endpoint  string    `json:"endpoint"`
	Kind      Kind      `json:"kind"`
	Sent      bool      `json:"sent"`
	Skipped   string    `json:"skipped,omitempty"`
	Recorded  int64     `json:"recorded_status,omitempty"`
	Status    int       `json:"status,omitempty"`
	Error     string    `json:"error,omitempty"`
	Blocked   string    `json:"blocked,omitempty"` // a vendor answered, not the application (round 25H)
	Refreshed []string  `json:"refreshed,omitempty"`
	Stale     []string  `json:"stale,omitempty"`
	Missing   []string  `json:"missing,omitempty"`
	Time      time.Time `json:"ts"`
}

// FlowResult is summary.json of a replay.
type FlowResult struct {
	Run     string `json:"run"`
	Action  string `json:"action"`
	Label   string `json:"label"`
	As      string `json:"as"`
	Steps   []Step `json:"steps"`
	Stopped string `json:"stopped,omitempty"`
	// HostsBlocked are the hosts given up (round 25H).
	HostsBlocked map[string]string `json:"hosts_blocked,omitempty"`
}

// ReplayFlow sends a flow's requests again, in order, after the ones of
// other flows whose answers they took values from; each value an earlier
// answer gave is taken from that answer anew.
func ReplayFlow(ctx context.Context, o FlowOptions) (*FlowResult, error) {
	m := o.Model
	run, f := o.Run, (*flow.Flow)(nil)
	for i := len(m.Runs) - 1; i >= 0 && f == nil; i-- {
		if run != "" && m.Runs[i] != run {
			continue
		}
		fs := m.Flows[m.Runs[i]]
		for j := range fs {
			if fs[j].Action == o.Action {
				run, f = m.Runs[i], &fs[j]
			}
		}
	}
	if f == nil {
		return nil, fmt.Errorf("replay: no flow %s", o.Action)
	}
	res := &FlowResult{Run: run, Action: f.Action, Label: f.Label, As: o.As.Role}

	// The flow's requests, and the sources of their values in other flows,
	// once each, in time order.
	steps := map[int]string{}
	var need func(id int, purpose string, depth int)
	need = func(id int, purpose string, depth int) {
		r := m.Request(run, id)
		if r == nil || depth > 5 {
			return
		}
		if _, ok := steps[id]; ok {
			return
		}
		steps[id] = purpose
		for _, from := range r.Derived {
			// A source of another flow, or of this one without a raw file
			// of its own (the page whose <meta> held the token).
			if src := m.Request(run, from.Request); src != nil && (src.Flow != f || !src.File) {
				need(from.Request, "prerequisite", depth+1)
			}
		}
	}
	once := map[string]bool{}
	for _, ref := range f.Requests {
		r := m.Request(run, ref.ID)
		if r == nil || r.Entry.Hop > 0 || !r.File {
			continue
		}
		if f.Kind == "background" {
			if once[r.Key] {
				continue
			}
			once[r.Key] = true
		}
		need(ref.ID, "step", 0)
	}
	ids := make([]int, 0, len(steps))
	for id := range steps {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return m.Request(run, ids[i]).Entry.Time.Before(m.Request(run, ids[j]).Entry.Time)
	})

	answers := map[int]Answer{}
	sent := map[int]bool{}
	for _, id := range ids {
		r := m.Request(run, id)
		st := Step{ID: id, Role: o.As.Role, Purpose: steps[id], Method: r.Entry.Method, Endpoint: r.Key, Time: time.Now().UTC()}
		if resp := r.Entry.Response; resp != nil && !r.Held {
			st.Recorded = resp.Status
		}
		d := o.Policy.Classify(r.Entry, r.Held)
		st.Kind = d.Kind
		switch {
		case d.Kind == Never || d.Kind == Excluded:
			st.Skipped = d.Reason
		case d.Kind == Destructive && !(o.AllowDestructive && o.AllowWrite):
			st.Skipped = "destructive (" + d.Reason + "): -allow-write -allow-destructive to send it"
		case d.Kind == Write && !o.AllowWrite:
			st.Skipped = "a write (" + d.Reason + "): -allow-write to send it"
		}
		u, _ := url.Parse(r.Entry.URL)
		if st.Skipped == "" && (u == nil || !o.InScope(u.Hostname())) {
			st.Skipped = "out of scope"
		}
		if st.Skipped != "" {
			res.Steps = append(res.Steps, st)
			continue
		}
		raw, err := r.Raw()
		if err != nil {
			return nil, err
		}
		keep := map[string]bool{}
		links := map[string]flow.LinkEnd{}
		for at, from := range r.Derived {
			if !sent[from.Request] && !strings.HasPrefix(from.At, "cookie:") {
				continue // its source was not sent again: the recorded value is all there is
			}
			if o.KeepIDs && !credentialLink(at, from) {
				continue
			}
			links[at] = from
			if name, ok := strings.CutPrefix(at, "header:"); ok {
				keep[name] = true
			}
		}
		var unrefreshed []string
		for at, from := range r.Derived {
			if _, ok := links[at]; !ok && credentialLink(at, from) {
				st.Stale = append(st.Stale, at) // a credential no source gave anew
				unrefreshed = append(unrefreshed, at)
			}
		}
		raw, st.Missing = Apply(raw, o.As, r.Entry.URL, keep)
		if o.Owner != o.As.Role {
			for _, at := range unrefreshed {
				raw = dropCredential(raw, at)
			}
		}
		ats := make([]string, 0, len(links))
		for at := range links {
			ats = append(ats, at)
		}
		sort.Strings(ats)
		for _, at := range ats {
			from := links[at]
			v, ok := valueAt(o.As, r.Entry.URL, answers[from.Request], from.At)
			if !ok {
				st.Stale = append(st.Stale, at)
				if o.Owner != o.As.Role && credentialLink(at, from) {
					raw = dropCredential(raw, at)
				}
				continue
			}
			patched, err := Patch(raw, at, v)
			if err != nil {
				st.Stale = append(st.Stale, at)
				if o.Owner != o.As.Role && credentialLink(at, from) {
					raw = dropCredential(raw, at)
				}
				continue
			}
			raw = patched
			st.Refreshed = append(st.Refreshed, at)
		}
		if o.Owner != o.As.Role {
			var dropped, kept []string
			raw, dropped, kept = stripUnrefreshedParams(raw, st.Refreshed, isRawSensitiveParam)
			for _, d := range dropped {
				if !slices.Contains(st.Stale, d) {
					st.Stale = append(st.Stale, d)
				}
			}
			if len(kept) > 0 {
				st.Skipped = "higher role credential cannot be stripped: " + strings.Join(kept, ", ")
				res.Steps = append(res.Steps, st)
				continue
			}
		}
		ans, err := o.Sender.Send(ctx, raw, u.Scheme, st.Purpose, o.As.Role, f.Action, func(s *Sent) { s.Refreshed, s.Stale = st.Refreshed, st.Stale })
		if err != nil {
			if errors.Is(err, ErrBudget) || errors.Is(err, errStopped) || errors.Is(err, ErrScope) {
				st.Skipped = err.Error()
				res.Steps = append(res.Steps, st)
				continue
			}
			return nil, err
		}
		if gone, _ := updateJar(o.As, u, ans); gone != "" {
			o.Sender.mu.Lock()
			o.Sender.stop("the identity's cookie " + gone + " was deleted")
			o.Sender.mu.Unlock()
		}
		st.Sent, st.Status, st.Error = true, ans.Status, ans.Err
		st.Blocked = ans.Block.String()
		answers[id], sent[id] = ans, true
		res.Steps = append(res.Steps, st)
	}
	res.Stopped = o.Sender.Stopped()
	res.HostsBlocked = o.Sender.BlockedHosts()
	return res, nil
}

// valueAt reads the value at a place of an answer, or of the identity's
// cookies.
func valueAt(id *Identity, rawURL string, ans Answer, at string) (string, bool) {
	if name, ok := strings.CutPrefix(at, "cookie:"); ok {
		if u, err := url.Parse(rawURL); err == nil {
			for _, c := range id.Jar.Cookies(u) {
				if c.Name == name {
					return c.Value, true
				}
			}
		}
		return "", false
	}
	if !ans.ok() {
		return "", false
	}
	e := traffic.Entry{Response: &traffic.Response{Headers: ans.Header, MIME: ans.Header["content-type"], Body: traffic.MakeBody(ans.Body, 4<<20)}}
	for _, v := range flow.ResponseValues(e) {
		if v.At == at {
			return v.V, true
		}
	}
	return "", false
}
