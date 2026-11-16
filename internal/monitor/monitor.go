package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Snapshot is a file of monitor/snapshots: the runs it took, by role,
// and whether each role's compare with its baseline. What the runs saw is
// read again from them when compared, with the code of then.
type Snapshot struct {
	ID    string      `json:"id"`
	Taken time.Time   `json:"taken"`
	Roles []*RoleSnap `json:"roles"`
}

// role returns a snapshot's part for a role.
func (s *Snapshot) role(name string) *RoleSnap {
	for _, r := range s.Roles {
		if r.Role == name {
			return r
		}
	}
	return nil
}

type Options struct {
	Root    string // <out>/<host>
	InScope func(host string) bool
	Keep    int  // snapshots kept; the baselines always
	Known   int  // comparable snapshots whose content is "known" (3)
	DryRun  bool // write nothing
	Now     time.Time
}

// Result is a run of monitor.
type Result struct {
	Snapshot *Snapshot
	Changes  []Change
	// Baseline says the snapshot is the first of some role: nothing to
	// compare that role with yet.
	Baseline []string
	Nothing  bool // no new run since the last snapshot
	Notes    []string
}

func (o Options) dir() string { return filepath.Join(o.Root, "monitor") }

// Run takes a snapshot of the runs since the last one, and compares it
// with each role's baseline.
func Run(o Options) (*Result, error) {
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.Known <= 0 {
		o.Known = 3
	}
	snaps, err := loadSnapshots(o.dir())
	if err != nil {
		return nil, err
	}
	taken := map[string]map[string]bool{}
	for _, s := range snaps {
		for _, r := range s.Roles {
			if taken[r.Role] == nil {
				taken[r.Role] = map[string]bool{}
			}
			for _, id := range r.Runs {
				taken[r.Role][id] = true
			}
		}
	}
	res := &Result{}
	cur := &Snapshot{Taken: o.Now}
	ents, err := os.ReadDir(o.Root)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !e.IsDir() || e.Name() == "archive" || e.Name() == "monitor" {
			continue
		}
		dir := filepath.Join(o.Root, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "runs.jsonl")); err != nil {
			continue
		}
		if rs := takeRole(dir, e.Name(), taken[e.Name()]); rs != nil {
			cur.Roles = append(cur.Roles, rs)
		}
	}
	if len(cur.Roles) == 0 {
		res.Nothing = true
		return res, nil
	}
	h := sha256.New()
	for _, r := range cur.Roles {
		fmt.Fprintln(h, r.Role, r.Runs)
	}
	cur.ID = o.Now.Format("20060102T150405Z") + "-" + hex.EncodeToString(h.Sum(nil))[:8]
	res.Snapshot = cur

	var all []Change
	for _, rs := range cur.Roles {
		dir := filepath.Join(o.Root, rs.Role)
		base, known := baselines(snaps, rs.Role, o.Known)
		rc := &roleCompare{role: rs.Role, session: rs.Session}
		if rc.cur, err = build(dir, rs.Runs, rs.Target, o.InScope); err != nil {
			return nil, err
		}
		if base == nil {
			rs.Comparable = len(rs.Partial) == 0
			if !rs.Comparable {
				rs.Why = rs.Partial[0]
			}
			res.Baseline = append(res.Baseline, rs.Role)
			continue
		}
		rc.partial = comparable(rs, base.role(rs.Role))
		rs.Comparable, rs.Why = rc.partial == "", rc.partial
		if rc.base, err = build(dir, base.role(rs.Role).Runs, rs.Target, o.InScope); err != nil {
			return nil, err
		}
		for _, k := range known {
			c, err := build(dir, k.role(rs.Role).Runs, rs.Target, o.InScope)
			if err != nil {
				return nil, err
			}
			rc.known = append(rc.known, c)
		}
		if !rs.Comparable {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: not comparable (%s): what looks gone is info only, and this snapshot is no baseline", rs.Role, rc.partial))
		}
		all = append(all, compareRole(rc)...)
	}
	res.Changes = merge(all)
	if o.DryRun {
		return res, nil
	}
	if err := save(o.dir(), cur); err != nil {
		return nil, err
	}
	prune(o.dir(), append(snaps, cur), o.Keep)
	return res, nil
}

// baselines are a role's latest comparable snapshot, and the Known latest
// comparable ones (the baseline first).
func baselines(snaps []*Snapshot, role string, n int) (*Snapshot, []*Snapshot) {
	var out []*Snapshot
	for i := len(snaps) - 1; i >= 0 && len(out) < n; i-- {
		if r := snaps[i].role(role); r != nil && r.Comparable {
			out = append(out, snaps[i])
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out[0], out
}

func loadSnapshots(dir string) ([]*Snapshot, error) {
	files, err := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))
	if err != nil {
		return nil, err
	}
	var out []*Snapshot
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var s Snapshot
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, &s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Taken.Before(out[j].Taken) })
	return out, nil
}

func save(dir string, s *Snapshot) error {
	if err := os.MkdirAll(filepath.Join(dir, "snapshots"), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "snapshots", s.ID+".json"), append(b, '\n'), 0o600)
}

// prune keeps the newest keep snapshots, and every role's baseline and
// the comparable ones "known" is built from, whatever their age.
func prune(dir string, snaps []*Snapshot, keep int) {
	if keep <= 0 || len(snaps) <= keep {
		return
	}
	hold := map[string]bool{}
	roles := map[string]bool{}
	for _, s := range snaps {
		for _, r := range s.Roles {
			roles[r.Role] = true
		}
	}
	for role := range roles {
		_, known := baselines(snaps, role, 3)
		for _, k := range known {
			hold[k.ID] = true
		}
	}
	for i, s := range snaps {
		if i < len(snaps)-keep && !hold[s.ID] {
			os.Remove(filepath.Join(dir, "snapshots", s.ID+".json"))
		}
	}
}
