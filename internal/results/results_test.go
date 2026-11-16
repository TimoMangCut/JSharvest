package results

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func line(t *testing.T, e traffic.Entry) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func appendFile(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func writeFlows(t *testing.T, p string, fs ...flow.Flow) {
	t.Helper()
	var s string
	for _, f := range fs {
		b, _ := json.Marshal(f)
		s += string(b) + "\n"
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The watch appends while the index reads: a line not yet whole is left
// for the next Refresh, and a log started over is read again.
func TestRefreshFollowsTheLog(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "requests.jsonl")
	r1 := line(t, traffic.Entry{Run: "R1", ID: 1, Method: "GET", URL: "http://app/a", Outcome: "ok"})
	r2 := line(t, traffic.Entry{Run: "R1", ID: 2, Method: "POST", URL: "http://app/b", Outcome: "held_back:write",
		Initiator: &traffic.Initiator{Type: "script", Stack: []traffic.Frame{{URL: "http://app/app.js", Line: 4, Col: 2}}}})
	r3 := line(t, traffic.Entry{Run: "R1", ID: 3, Method: "GET", URL: "http://app/c", Outcome: "ok",
		Response: &traffic.Response{Status: 404, Body: traffic.Body{Body: "nope"}}})
	appendFile(t, p, r1+r2+r3[:10])
	d := Open(dir)
	if err := d.Refresh(); err != nil {
		t.Fatal(err)
	}
	if n := len(d.Requests("R1")); n != 2 {
		t.Fatalf("indexed %d requests, want 2 (the third is half written)", n)
	}
	if q, _ := d.Request("R1", 2); q.Initiator != "http://app/app.js:4:2" || q.Outcome != "held_back:write" {
		t.Fatalf("request 2 indexed as %+v", q)
	}
	appendFile(t, p, r3[10:])
	d.Refresh()
	e, err := d.Entry("R1", 3)
	if err != nil || e.Response == nil || e.Response.Status != 404 || e.Response.Body.Body != "nope" {
		t.Fatalf("entry 3: %+v, %v", e, err)
	}

	// Started over, shorter: indexed again from the start.
	os.WriteFile(p, []byte(line(t, traffic.Entry{Run: "R2", ID: 1, Method: "GET", URL: "http://app/z"})), 0o600)
	d.Refresh()
	if len(d.Requests("R2")) != 1 || len(d.Requests("R1")) != 0 {
		t.Fatalf("after the log started over: R1 %d, R2 %d", len(d.Requests("R1")), len(d.Requests("R2")))
	}
	if _, err := d.Entry("R2", 1); err != nil {
		t.Fatal(err)
	}
}

// A run's flows come from flows.jsonl once it ended, from the watch's
// snapshot until then; the latest run is the running watch's.
func TestFlowsAndLatest(t *testing.T) {
	dir := t.TempDir()
	writeFlows(t, filepath.Join(dir, "flows.jsonl"), flow.Flow{Run: "R1", Action: "a1", Kind: "load"})
	writeFlows(t, filepath.Join(dir, PartialFlows), flow.Flow{Run: "R2", Action: "a1", Kind: "load"}, flow.Flow{Run: "R2", Action: "a2", Kind: "click"})
	d := Open(dir)
	if fs, partial, _ := d.Flows("R1"); len(fs) != 1 || partial {
		t.Fatalf("R1: %d flows, partial %v", len(fs), partial)
	}
	if fs, partial, _ := d.Flows("R2"); len(fs) != 2 || !partial {
		t.Fatalf("R2: %d flows, partial %v", len(fs), partial)
	}

	// A watch of a run that sorts first, still running, is the latest.
	WriteLive(dir, Live{Run: "R0", PID: os.Getpid(), Updated: time.Now()})
	if got := d.Latest(); got != "R0" {
		t.Fatalf("latest with a live watch: %s", got)
	}
	if st, _ := os.Stat(filepath.Join(dir, LiveFile)); st.Mode().Perm() != 0o600 {
		t.Fatalf("watch.json mode %v", st.Mode().Perm())
	}
	// Its process is gone: the newest run is.
	WriteLive(dir, Live{Run: "R0", PID: 0})
	if got := d.Latest(); got != "R2" {
		t.Fatalf("latest after the watch died: %s", got)
	}
	RemoveLive(dir)
	if l, _ := ReadLive(dir); l != nil {
		t.Fatal("watch.json still there")
	}

	// The run ended: its flows were appended, and win over the snapshot.
	appendFile(t, filepath.Join(dir, "flows.jsonl"), func() string {
		b, _ := json.Marshal(flow.Flow{Run: "R2", Action: "a1", Kind: "load"})
		return string(b) + "\n"
	}())
	if fs, partial, _ := d.Flows("R2"); len(fs) != 1 || partial {
		t.Fatalf("R2 after it ended: %d flows, partial %v", len(fs), partial)
	}
}

func TestDirs(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"a.test/anon", "a.test/admin", "b.test/anon", "c.test/empty"} {
		os.MkdirAll(filepath.Join(root, p), 0o755)
	}
	os.WriteFile(filepath.Join(root, "a.test/anon/requests.jsonl"), nil, 0o600)
	os.WriteFile(filepath.Join(root, "a.test/admin/run.json"), nil, 0o600)
	os.WriteFile(filepath.Join(root, "b.test/anon", LiveFile), nil, 0o600)
	if got := Dirs(root); len(got) != 3 {
		t.Fatalf("dirs %v", got)
	}
	if h, r := HostRole(filepath.Join(root, "a.test", "admin")); h != "a.test" || r != "admin" {
		t.Fatalf("host %s role %s", h, r)
	}
}

// The scope a directory was gathered with: the watch's while it runs, else
// the last run's, else rdn (Reviewer NEW-4.6-03).
func TestScopeMode(t *testing.T) {
	dir := t.TempDir()
	if m := ScopeMode(dir); m != "rdn" {
		t.Fatalf("empty: %q", m)
	}
	os.WriteFile(filepath.Join(dir, "run.json"), []byte(`{"run_id":"r1","scope":"fqdn"}`), 0o600)
	if m := ScopeMode(dir); m != "fqdn" {
		t.Fatalf("run.json: %q", m)
	}
}

// Architecture review 2026-11-13: Runs reads the run set under the lock
// only; jsharvest mcp calls it while Flows and Refresh fill it.
func TestRunsConcurrentWithFlows(t *testing.T) {
	dir := t.TempDir()
	writeFlows(t, filepath.Join(dir, "flows.jsonl"), flow.Flow{Run: "R1", Action: "a1", Kind: "load"})
	WriteLive(dir, Live{Run: "R9", PID: os.Getpid(), Updated: time.Now()})
	d := Open(dir)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				if i%2 == 0 {
					d.Runs()
				} else {
					writeFlows(t, filepath.Join(dir, PartialFlows), flow.Flow{Run: fmt.Sprintf("P%d-%d", i, j), Action: "a1", Kind: "load"})
					d.Flows("R1")
				}
			}
		}()
	}
	wg.Wait()
}
