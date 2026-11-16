// Package results reads a target's output directory while a watch may
// still be writing it: the request log, the flows, and the watch's state.
// It never writes there, apart from the watch's state file, which the
// engine writes through WriteLive.
package results

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

const (
	LiveFile     = "watch.json"
	PartialFlows = "flows.partial.jsonl"
)

// Live is watch.json: a watch that is running, and how far its flows
// snapshot goes. Everything recorded before Updated is in the snapshot.
type Live struct {
	Run      string    `json:"run"`
	PID      int       `json:"pid"`
	Tab      string    `json:"tab"`
	Started  time.Time `json:"started"`
	Updated  time.Time `json:"updated"`
	Guard    bool      `json:"guard"`
	Requests int       `json:"requests"`
	Actions  int       `json:"actions"`
	// LastEvent is when the watch last heard of something done in the
	// tab, by its own clock: typing that sends nothing makes no flow, but
	// still counts as activity.
	LastEvent time.Time `json:"last_event,omitzero"`
	// Scope is the run's -scope: rdn or fqdn.
	Scope string `json:"scope,omitempty"`
}

// ScopeMode is the -scope the directory's data was gathered with: the
// running watch's, or else the last run's (run.json); rdn when neither
// says.
func ScopeMode(dir string) string {
	if l, ok := ReadLive(dir); ok && l.Scope != "" {
		return l.Scope
	}
	var r struct {
		Scope string `json:"scope"`
	}
	if b, err := os.ReadFile(filepath.Join(dir, "run.json")); err == nil && json.Unmarshal(b, &r) == nil && r.Scope != "" {
		return r.Scope
	}
	return "rdn"
}

// WriteLive replaces dir's watch.json. It is 0600: the tab's URL may carry
// a token.
func WriteLive(dir string, l Live) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, LiveFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, LiveFile))
}

// RemoveLive says the watch is over.
func RemoveLive(dir string) {
	os.Remove(filepath.Join(dir, LiveFile))
}

// ReadLive returns dir's watch.json, and whether its process still runs: a
// watch that was killed leaves the file behind.
func ReadLive(dir string) (*Live, bool) {
	b, err := os.ReadFile(filepath.Join(dir, LiveFile))
	if err != nil {
		return nil, false
	}
	var l Live
	if json.Unmarshal(b, &l) != nil || l.Run == "" {
		return nil, false
	}
	return &l, alive(l.PID)
}

func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// Req is what the index keeps of one line of requests.jsonl; the line
// itself is read again from its offset when asked for.
type Req struct {
	Run          string
	ID           int
	Time         time.Time
	Target       string
	Page         string
	Method       string
	URL          string
	ResourceType string
	Status       int64
	MIME         string
	Outcome      string
	Initiator    string // the top frame, url:line:col, or the initiator's URL
	Body         string // small UTF-8 JSON object request body (<= 16 KB), for parameter values
	Internal     bool   // made by jsharvest (the resolver), not the page
	Challenge    bool   // made by a bot challenge, or on a challenge page: not the target's
	off          int64
	n            int
}

// Dir is one output directory, <output>/<host>/<role>. Its methods are
// safe for concurrent use.
type Dir struct {
	Path string

	mu   sync.Mutex
	off  int64 // how far requests.jsonl has been indexed
	reqs map[string]map[int]*Req
	runs map[string]bool // every run seen, in any file
	full fileCache       // flows.jsonl, by run
	part fileCache       // flows.partial.jsonl, by run
}

type fileCache struct {
	size  int64
	mtime time.Time
	byRun map[string][]flow.Flow
}

func Open(path string) *Dir {
	return &Dir{Path: path, reqs: map[string]map[int]*Req{}, runs: map[string]bool{}}
}

// Refresh indexes what was appended to requests.jsonl since the last call,
// up to its last whole line: the line being written is left for later.
func (d *Dir) Refresh() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := os.Open(filepath.Join(d.Path, "requests.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() < d.off {
		// Replaced or cut: start over.
		d.off, d.reqs = 0, map[string]map[int]*Req{}
	}
	if _, err := f.Seek(d.off, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil // EOF, or a line still being written
		}
		at := d.off
		d.off += int64(len(line))
		if q, ok := index(line); ok {
			q.off, q.n = at, len(line)
			if d.reqs[q.Run] == nil {
				d.reqs[q.Run] = map[int]*Req{}
			}
			d.reqs[q.Run][q.ID] = q
			d.runs[q.Run] = true
		}
	}
}

// index decodes the fields the index keeps, skipping the bodies.
func index(line []byte) (*Req, bool) {
	var e struct {
		Run          string    `json:"run"`
		ID           int       `json:"id"`
		Time         time.Time `json:"ts"`
		Target       string    `json:"target"`
		Page         string    `json:"page"`
		Method       string    `json:"method"`
		URL          string    `json:"url"`
		ResourceType string    `json:"resource_type"`
		Outcome      string    `json:"outcome"`
		Body          string `json:"body"`
		BodyBase64    bool   `json:"body_base64"`
		BodyTruncated bool   `json:"body_truncated"`
		Response      *struct {
			Status int64  `json:"status"`
			MIME   string `json:"mime"`
		} `json:"response"`
		Initiator *traffic.Initiator `json:"initiator"`
		Tags      []string           `json:"tags"`
	}
	if json.Unmarshal(line, &e) != nil || e.Run == "" {
		return nil, false
	}
	q := &Req{Run: e.Run, ID: e.ID, Time: e.Time, Target: e.Target, Page: e.Page, Method: e.Method, URL: e.URL,
		ResourceType: e.ResourceType, Outcome: e.Outcome, Internal: slices.Contains(e.Tags, "jsharvest"),
		Challenge: slices.Contains(e.Tags, "challenge")}
	if !e.BodyBase64 && !e.BodyTruncated && len(e.Body) > 0 && len(e.Body) <= 16<<10 && strings.HasPrefix(strings.TrimSpace(e.Body), "{") {
		q.Body = e.Body
	}
	if e.Response != nil {
		q.Status, q.MIME = e.Response.Status, e.Response.MIME
	}
	if in := e.Initiator; in != nil {
		switch {
		case len(in.Stack) > 0:
			f := in.Stack[0]
			q.Initiator = fmt.Sprintf("%s:%d:%d", f.URL, f.Line, f.Col)
		case in.URL != "":
			q.Initiator = in.URL
		}
	}
	return q, true
}

// Request returns the index's entry for a request of a run.
func (d *Dir) Request(run string, id int) (*Req, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	q, ok := d.reqs[run][id]
	return q, ok
}

// Requests returns a run's requests in id order.
func (d *Dir) Requests(run string) []*Req {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*Req, 0, len(d.reqs[run]))
	for _, q := range d.reqs[run] {
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Entry reads a request's whole line again.
func (d *Dir) Entry(run string, id int) (traffic.Entry, error) {
	var e traffic.Entry
	q, ok := d.Request(run, id)
	if !ok {
		return e, fmt.Errorf("no request %d in run %s", id, run)
	}
	f, err := os.Open(filepath.Join(d.Path, "requests.jsonl"))
	if err != nil {
		return e, err
	}
	defer f.Close()
	b := make([]byte, q.n)
	if _, err := f.ReadAt(b, q.off); err != nil {
		return e, err
	}
	if err := json.Unmarshal(b, &e); err != nil || e.Run != run || e.ID != id {
		return e, fmt.Errorf("request %d of run %s: the log changed; ask again", id, run)
	}
	return e, nil
}

// Flows returns a run's flows: from flows.jsonl once the run has ended,
// or from the snapshot of a watch (partial) until then. A watch that was
// killed leaves its last snapshot, which is partial for good.
func (d *Dir) Flows(run string) (fs []flow.Flow, partial bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.load(&d.full, "flows.jsonl"); err != nil {
		return nil, false, err
	}
	if fs, ok := d.full.byRun[run]; ok {
		return fs, false, nil
	}
	if err := d.load(&d.part, PartialFlows); err != nil {
		return nil, false, err
	}
	fs, ok := d.part.byRun[run]
	return fs, ok, nil
}

// load reads a flows file again when it changed.
func (d *Dir) load(c *fileCache, name string) error {
	p := filepath.Join(d.Path, name)
	st, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		*c = fileCache{}
		return nil
	}
	if err != nil {
		return err
	}
	if c.byRun != nil && st.Size() == c.size && st.ModTime().Equal(c.mtime) {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	byRun := map[string][]flow.Flow{}
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var f flow.Flow
		if len(line) == 0 || json.Unmarshal(line, &f) != nil {
			continue // a line being appended
		}
		byRun[f.Run] = append(byRun[f.Run], f)
		d.runs[f.Run] = true
	}
	*c = fileCache{size: st.Size(), mtime: st.ModTime(), byRun: byRun}
	return nil
}

// Runs lists the runs seen in the directory's files, oldest first (run ids
// are UTC time stamps, so they sort by time).
func (d *Dir) Runs() []string {
	d.mu.Lock()
	d.load(&d.full, "flows.jsonl")
	d.load(&d.part, PartialFlows)
	out := make([]string, 0, len(d.runs))
	for r := range d.runs {
		out = append(out, r)
	}
	known := maps.Clone(d.runs)
	d.mu.Unlock()
	// d.runs is read under the lock only: a Refresh or a Flows in
	// another goroutine (jsharvest mcp) writes it (architecture review
	// 2026-11-13).
	if l, _ := ReadLive(d.Path); l != nil && !known[l.Run] {
		out = append(out, l.Run)
	}
	sort.Strings(out)
	return out
}

// Latest returns the run a question is about by default: the running
// watch's, else the newest one.
func (d *Dir) Latest() string {
	if l, ok := ReadLive(d.Path); ok {
		return l.Run
	}
	runs := d.Runs()
	if len(runs) == 0 {
		return ""
	}
	return runs[len(runs)-1]
}

// RunInfo is a line of runs.jsonl, as far as a question needs it.
type RunInfo struct {
	RunID    string    `json:"run_id"`
	Target   string    `json:"target"`
	Mode     string    `json:"mode"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended"`
	Requests int       `json:"requests"`
	ExitCode int       `json:"exit_code"`
}

// Finished reads runs.jsonl: the runs that ended.
func (d *Dir) Finished() []RunInfo {
	b, err := os.ReadFile(filepath.Join(d.Path, "runs.jsonl"))
	if err != nil {
		return nil
	}
	var out []RunInfo
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var r RunInfo
		if len(line) > 0 && json.Unmarshal(line, &r) == nil && r.RunID != "" {
			out = append(out, r)
		}
	}
	return out
}

// Offset is how far requests.jsonl has been indexed: it grows with every
// Refresh that read new requests.
func (d *Dir) Offset() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.off
}

// Updated is when the directory last changed, by its logs' times.
func (d *Dir) Updated() time.Time {
	var t time.Time
	for _, name := range []string{"requests.jsonl", "flows.jsonl", PartialFlows, LiveFile, "run.json"} {
		if st, err := os.Stat(filepath.Join(d.Path, name)); err == nil && st.ModTime().After(t) {
			t = st.ModTime()
		}
	}
	return t
}

// Dirs lists the output directories under root: <root>/<host>/<role>
// with a request log, a flows file, a run, or a watch.
func Dirs(root string) []string {
	var out []string
	hosts, _ := os.ReadDir(root)
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		roles, _ := os.ReadDir(filepath.Join(root, h.Name()))
		for _, r := range roles {
			p := filepath.Join(root, h.Name(), r.Name())
			if !r.IsDir() {
				continue
			}
			for _, name := range []string{"requests.jsonl", "flows.jsonl", PartialFlows, LiveFile, "run.json"} {
				if _, err := os.Stat(filepath.Join(p, name)); err == nil {
					out = append(out, p)
					break
				}
			}
		}
	}
	return out
}

// HostRole splits a directory's path into its host and role.
func HostRole(p string) (host, role string) {
	role = filepath.Base(p)
	host = filepath.Base(filepath.Dir(p))
	return host, strings.TrimSpace(role)
}
