package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// asker is the driver's side of the 4.3d gate: an MCP client of jsharvest
// mcp that, after each step, asks last_action what the step sent, as an AI
// agent driving the browser would, and checks the answer against the
// truth.
type asker struct {
	cs     *mcp.ClientSession
	guard  bool
	cases  int
	passed int
	wrong  []string
	some   int // a request id to read back with get_request
	writes []stepWrite
	steps  []*askedStep
	owner  map[string]*askedStep // by action id: the step whose answer gave it
}

// askedStep is what the answers said a step sent: the answer right after
// it, and the late requests later answers gave for its actions.
type askedStep struct {
	i       int
	s       flowStep
	actions []string
	got     []askedRequest
	settled bool
}

// stepWrite is a write a step must have sent, and the actions the answer
// gave for that step: blocked must name one of them.
type stepWrite struct {
	step    int
	key     string
	actions []string
}

type askedRequest struct {
	ID      int    `json:"id"`
	Method  string `json:"method"`
	URL     string `json:"url"`
	Outcome string `json:"outcome"`
	How     string `json:"how"`
}

type askedAction struct {
	Action   string         `json:"action"`
	Kind     string         `json:"kind"`
	Label    string         `json:"label"`
	Requests []askedRequest `json:"requests"`
}

type askedLast struct {
	Live    bool          `json:"live"`
	Settled bool          `json:"settled"`
	Actions []askedAction `json:"actions"`
	Late    []askedAction `json:"late"`
	Note    string        `json:"note"`
}

func newAsker(cmdline string, guard bool) (*asker, error) {
	cmd := exec.Command("sh", "-c", "exec "+cmdline)
	cmd.Stderr = os.Stderr
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "testbed-drive"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return nil, fmt.Errorf("mcp: %w", err)
	}
	a := &asker{cs: cs, guard: guard, owner: map[string]*askedStep{}}
	// The first answer is the latest action, the page's load: from here
	// on, each answer is what came after the one before.
	first, err := a.last()
	if err != nil {
		cs.Close()
		return nil, err
	}
	if !first.Live {
		cs.Close()
		return nil, fmt.Errorf("mcp: no watch is recording (%s)", first.Note)
	}
	return a, nil
}

func (a *asker) close() { a.cs.Close() }

func (a *asker) call(name string, args map[string]any, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res, err := a.cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return fmt.Errorf("mcp %s: %w", name, err)
	}
	if len(res.Content) == 0 {
		return fmt.Errorf("mcp %s: empty answer", name)
	}
	text, _ := res.Content[0].(*mcp.TextContent)
	if text == nil {
		return fmt.Errorf("mcp %s: not text", name)
	}
	if res.IsError {
		return fmt.Errorf("mcp %s: %s", name, text.Text)
	}
	return json.Unmarshal([]byte(text.Text), out)
}

func (a *asker) last() (askedLast, error) {
	var out askedLast
	err := a.call("last_action", map[string]any{"wait_ms": 10000}, &out)
	return out, err
}

func requestKey(method, raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return method + " " + u.RequestURI()
	}
	return method + " " + raw
}

func (a *asker) step(i int, s flowStep) {
	asked := time.Now()
	out, err := a.last()
	took := time.Since(asked)
	if err != nil {
		a.wrong = append(a.wrong, fmt.Sprintf("step %d: %v", i, err))
		return
	}
	st := &askedStep{i: i, s: s, settled: out.Settled}
	a.steps = append(a.steps, st)
	var labels []string
	for _, act := range out.Actions {
		labels = append(labels, act.Action+" "+act.Kind+" "+act.Label)
		st.actions = append(st.actions, act.Action)
		st.got = append(st.got, act.Requests...)
		a.owner[act.Action] = st
	}
	keys := a.late(out)
	for _, r := range st.got {
		keys = append(keys, requestKey(r.Method, r.URL))
		if a.some == 0 && r.Method != "" {
			a.some = r.ID
		}
	}
	fmt.Printf("  mcp: %v -> %v (settled %v in %.1fs)\n", labels, keys, out.Settled, took.Seconds())
}

// late puts the late requests of an answer under the steps whose actions
// sent them.
func (a *asker) late(out askedLast) []string {
	var keys []string
	for _, act := range out.Late {
		st := a.owner[act.Action]
		for _, r := range act.Requests {
			k := requestKey(r.Method, r.URL)
			if st == nil {
				keys = append(keys, "late of unknown "+act.Action+": "+k)
				continue
			}
			st.got = append(st.got, r)
			keys = append(keys, fmt.Sprintf("late of step %d: %s", st.i, k))
		}
	}
	return keys
}

// judge checks what the answers gave for a step against the truth.
func (a *asker) judge(st *askedStep) {
	i, s := st.i, st.s
	if s.Expect == nil {
		return
	}
	a.cases++
	ok := st.settled
	if !ok {
		a.wrong = append(a.wrong, fmt.Sprintf("step %d (%s %s): the answer did not settle", i, s.Do, s.Selector))
	}
	want := slices.Clone(s.Expect)
	got := st.got
	if a.guard {
		// What the guard answered for changes what follows: check the
		// writes only.
		want = slices.DeleteFunc(want, func(k string) bool { return strings.HasPrefix(k, "GET ") })
		got = slices.DeleteFunc(slices.Clone(got), func(r askedRequest) bool { return r.Method == "GET" })
		for _, k := range want {
			a.writes = append(a.writes, stepWrite{step: i, key: k, actions: st.actions})
		}
	}
	for _, r := range got {
		k := requestKey(r.Method, r.URL)
		j := slices.IndexFunc(want, func(p string) bool { return expectMatch(p, k) })
		switch {
		case j < 0:
			a.wrong = append(a.wrong, fmt.Sprintf("step %d (%s %s): answer has %s", i, s.Do, s.Selector, k))
			ok = false
		case s.How != "" && r.How != s.How:
			a.wrong = append(a.wrong, fmt.Sprintf("step %d (%s %s): %s traced by %q, want %s", i, s.Do, s.Selector, k, r.How, s.How))
			want = slices.Delete(want, j, j+1)
			ok = false
		default:
			want = slices.Delete(want, j, j+1)
		}
	}
	for _, k := range want {
		a.wrong = append(a.wrong, fmt.Sprintf("step %d (%s %s): answer misses %s", i, s.Do, s.Selector, k))
		ok = false
	}
	if ok {
		a.passed++
	}
}

// finish checks the other tools once the steps are done.
func (a *asker) finish() error {
	// The last step's late requests, if any.
	var tail askedLast
	if err := a.call("last_action", map[string]any{"wait_ms": 4000}, &tail); err != nil {
		a.wrong = append(a.wrong, err.Error())
	}
	if keys := a.late(tail); len(keys) > 0 {
		fmt.Printf("  mcp: at the end %v\n", keys)
	}
	for _, st := range a.steps {
		a.judge(st)
	}
	var eps struct {
		Total int `json:"total"`
	}
	if err := a.call("endpoints", nil, &eps); err != nil || eps.Total == 0 {
		a.wrong = append(a.wrong, fmt.Sprintf("endpoints: %d, %v", eps.Total, err))
	}
	if a.some > 0 {
		var req struct {
			Flows   []string `json:"flows"`
			Request struct {
				ID       int    `json:"id"`
				Method   string `json:"method"`
				Headers  map[string]string
				Response *struct {
					Status int `json:"status"`
				} `json:"response"`
			} `json:"request"`
		}
		err := a.call("get_request", map[string]any{"id": a.some}, &req)
		if err != nil || req.Request.ID != a.some || req.Request.Method == "" || len(req.Request.Headers) == 0 || len(req.Flows) == 0 {
			a.wrong = append(a.wrong, fmt.Sprintf("get_request %d: %+v, %v", a.some, req, err))
		}
	}
	var blocked struct {
		Total   int `json:"total"`
		Blocked []struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Action string `json:"action"`
		} `json:"blocked"`
	}
	if err := a.call("blocked", map[string]any{"limit": 500}, &blocked); err != nil {
		a.wrong = append(a.wrong, err.Error())
	}
	if !a.guard && blocked.Total != 0 {
		a.wrong = append(a.wrong, fmt.Sprintf("blocked: %d with the guard off", blocked.Total))
	}
	for _, w := range a.writes {
		if !slices.ContainsFunc(blocked.Blocked, func(b struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Action string `json:"action"`
		}) bool {
			return expectMatch(w.key, requestKey(b.Method, b.URL)) && slices.Contains(w.actions, b.Action)
		}) {
			a.wrong = append(a.wrong, fmt.Sprintf("step %d: blocked has no %s under %v", w.step, w.key, w.actions))
		}
	}
	fmt.Printf("mcp: %d/%d steps answered right; blocked %d\n", a.passed, a.cases, blocked.Total)
	for _, w := range a.wrong {
		fmt.Println("MCP WRONG", w)
	}
	if len(a.wrong) > 0 {
		return fmt.Errorf("mcp check failed")
	}
	fmt.Println("mcp: ok")
	return nil
}
