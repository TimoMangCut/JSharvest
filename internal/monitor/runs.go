// Package monitor tells what changed in a target between two periodic
// crawls: endpoints new or gone, parameters new, statuses that turned,
// scripts; ranked, so that the new admin endpoint comes before the
// rebuilt bundle. It reads the output and sends nothing to the target.
// See docs/gd5-monitor-design.md.
package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"
)

// run is what monitor reads of a line of runs.jsonl.
type run struct {
	RunID    string          `json:"run_id"`
	Target   string          `json:"target"`
	Mode     string          `json:"mode"`
	ExitCode int             `json:"exit_code"`
	Started  time.Time       `json:"started"`
	Config   json.RawMessage `json:"config"`
	Scripts  []string        `json:"scripts"`
	Blocked  struct {
		Blocked bool `json:"blocked"`
	} `json:"blocked"`
	Session *struct {
		Restored int  `json:"restored"`
		Relogins int  `json:"relogins"`
		Lost     bool `json:"lost"`
	} `json:"session"`
	Frontier *struct {
		Visited int            `json:"visited"`
		Queued  int            `json:"queued"`
		Listed  map[string]int `json:"listed"`
	} `json:"frontier"`
	Resolver struct {
		Stopped string `json:"stopped"`
	} `json:"resolver"`
	HTTP *struct {
		Stopped string `json:"stopped"`
	} `json:"http"`
}

// eligible reports whether a run is a crawl monitor takes: a crawl (not a
// watch, whose tab a person drives), ended well, that says its scripts. A
// crawl of the HTTP engine is one too; its config says its engine, so it
// does not compare with a browser's.
func (r run) eligible() bool {
	return (r.Mode == "launch" || r.Mode == "attach" || r.Mode == "http") && r.ExitCode == 0 && r.Scripts != nil
}

func readRuns(dir string) []run {
	f, err := os.Open(filepath.Join(dir, "runs.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []run
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r run
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.RunID != "" {
			out = append(out, r)
		}
	}
	return out
}

// RoleSnap is a role's part of a snapshot: its new runs, and what tells
// whether they compare with the baseline's.
type RoleSnap struct {
	Role   string   `json:"role"`
	Runs   []string `json:"runs"`
	Target string   `json:"target,omitempty"`
	// Targets are the runs' start URLs: a batch's many, a crawl's one.
	Targets []string        `json:"targets,omitempty"`
	Config  json.RawMessage `json:"config,omitempty"`
	Pages   int             `json:"pages"`
	// Partial says why the runs saw less than they could: a limit, a
	// challenge, a session lost and put back.
	Partial []string `json:"partial,omitempty"`
	// Session says the session was lost and put back: refusals of then
	// say nothing of the server's checks.
	Session bool `json:"session_events,omitempty"`
	// Comparable: the role's runs compare with its baseline (or, the
	// first, saw what they could): this snapshot can be a baseline.
	Comparable bool   `json:"comparable"`
	Why        string `json:"why_not,omitempty"`
}

// takeRole gathers a role's eligible runs that no earlier snapshot took.
func takeRole(dir, role string, taken map[string]bool) *RoleSnap {
	rs := &RoleSnap{Role: role}
	for _, r := range readRuns(dir) {
		if !r.eligible() || taken[r.RunID] {
			continue
		}
		rs.Runs = append(rs.Runs, r.RunID)
		rs.Target = r.Target
		rs.Targets = appendNew(rs.Targets, r.Target)
		if rs.Config == nil {
			rs.Config = r.Config
		} else if !reflect.DeepEqual(normJSON(rs.Config), normJSON(r.Config)) {
			rs.Partial = appendNew(rs.Partial, "the runs had other configs")
		}
		if r.Frontier != nil {
			rs.Pages += r.Frontier.Visited
			if r.Frontier.Listed["limit"] > 0 || r.Frontier.Queued > 0 {
				rs.Partial = appendNew(rs.Partial, "the crawl hit its page limit")
			}
		} else {
			rs.Pages++
		}
		if r.Blocked.Blocked {
			rs.Partial = appendNew(rs.Partial, "a challenge or block page answered")
		}
		if r.Resolver.Stopped != "" {
			rs.Partial = appendNew(rs.Partial, "the chunk resolver stopped: "+r.Resolver.Stopped)
		}
		if r.HTTP != nil && r.HTTP.Stopped != "" {
			rs.Partial = appendNew(rs.Partial, "the HTTP crawl stopped: "+r.HTTP.Stopped)
		}
		if s := r.Session; s != nil && (s.Restored > 0 || s.Relogins > 0 || s.Lost) {
			rs.Session = true
			rs.Partial = appendNew(rs.Partial, "the session was lost during the run")
		}
	}
	if len(rs.Runs) == 0 {
		return nil
	}
	slices.Sort(rs.Targets)
	return rs
}

func normJSON(b json.RawMessage) any {
	var v any
	json.Unmarshal(b, &v)
	return v
}

func appendNew(xs []string, x string) []string {
	if slices.Contains(xs, x) {
		return xs
	}
	return append(xs, x)
}

// comparable says why a role's runs do not compare with the baseline's
// ("" when they do): another config, a partial run, far fewer pages.
func comparable(cur, base *RoleSnap) string {
	switch {
	case base == nil:
		return "no baseline for the role"
	case len(cur.Partial) > 0:
		return cur.Partial[0]
	case !slices.Equal(cur.Targets, base.Targets):
		return "other start URLs (a batch and a crawl, or another target)"
	case !reflect.DeepEqual(normJSON(cur.Config), normJSON(base.Config)):
		return "another crawl config"
	case base.Pages > 0 && cur.Pages*5 < base.Pages*4:
		return fmt.Sprintf("%d pages visited, the baseline %d", cur.Pages, base.Pages)
	}
	return ""
}
