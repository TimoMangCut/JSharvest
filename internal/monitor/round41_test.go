package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRound41MonitorSkipsCorruptSnapshot(t *testing.T) {
	root := t.TempDir()
	anon := filepath.Join(root, "anon")
	if err := os.MkdirAll(anon, 0o700); err != nil {
		t.Fatal(err)
	}
	runs := `{"run_id":"R1","mode":"http","exit_code":0,"scripts":[],"target":"https://app.example.test/","started":"2026-11-20T00:00:00Z"}` + "\n" +
		`{"run_id":"R2","mode":"http","exit_code":0,"scripts":[],"target":"https://app.example.test/","started":"2026-11-20T01:00:00Z"}` + "\n" +
		`{"run_id":"R3","mode":"http","exit_code":0,"scripts":[],"target":"https://app.example.test/","started":"2026-11-20T02:00:00Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(anon, "runs.jsonl"), []byte(runs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(anon, "index.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	monDir := filepath.Join(root, "monitor")
	if err := save(monDir, &Snapshot{
		ID:    "20261120T000500Z-aaaa1111",
		Taken: time.Date(2026, 11, 20, 0, 5, 0, 0, time.UTC),
		Roles: []*RoleSnap{{Role: "anon", Target: "https://app.example.test/", Runs: []string{"R1"}, Comparable: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := save(monDir, &Snapshot{
		ID:    "20261120T010500Z-bbbb2222",
		Taken: time.Date(2026, 11, 20, 1, 5, 0, 0, time.UTC),
		Roles: []*RoleSnap{{Role: "anon", Target: "https://app.example.test/", Runs: []string{"R2"}, Comparable: true}},
	}); err != nil {
		t.Fatal(err)
	}

	badPath := filepath.Join(monDir, "snapshots", "20261120T013000Z-corrupt.json")
	if err := os.WriteFile(badPath, []byte(`{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. DryRun skips the corrupt snapshot without renaming it on disk.
	resDry, err := Run(Options{Root: root, InScope: func(string) bool { return true }, DryRun: true})
	if err != nil {
		t.Fatalf("DryRun failed on corrupt snapshot: %v", err)
	}
	if resDry.SkippedSnapshots != 1 {
		t.Fatalf("DryRun SkippedSnapshots=%d, want 1", resDry.SkippedSnapshots)
	}
	if _, err := os.Stat(badPath); err != nil {
		t.Fatalf("DryRun removed or renamed corrupt snapshot: %v", err)
	}
	if _, err := os.Stat(badPath + ".corrupt"); !os.IsNotExist(err) {
		t.Fatalf("DryRun created .corrupt file")
	}

	// 2. Normal Run skips it, renames it to .corrupt, and completes cleanly.
	res, err := Run(Options{Root: root, InScope: func(string) bool { return true }})
	if err != nil {
		t.Fatalf("Run failed on corrupt snapshot: %v", err)
	}
	if res.SkippedSnapshots != 1 || res.Nothing {
		t.Fatalf("unexpected Run result: skipped=%d nothing=%v", res.SkippedSnapshots, res.Nothing)
	}
	if _, err := os.Stat(badPath + ".corrupt"); err != nil {
		t.Fatalf("expected %s.corrupt to exist: %v", badPath, err)
	}
}

func TestRound41MonitorSaveAndPendingAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "monitor")
	s := &Snapshot{ID: "20261120T030000Z-12345678", Taken: time.Now().UTC()}
	if err := save(dir, s); err != nil {
		t.Fatal(err)
	}
	snapPath := filepath.Join(dir, "snapshots", s.ID+".json")
	st, err := os.Stat(snapPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot stat err=%v mode=%o, want 0600", err, st.Mode().Perm())
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "snapshots"))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".snap-") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}

	p := &Payload{ID: "snap-1", Target: "app.example.test", Counts: map[string]int{High: 1}}
	if err := Pending(dir, p); err != nil {
		t.Fatal(err)
	}
	pendPath := filepath.Join(dir, "pending-webhook.json")
	pst, err := os.Stat(pendPath)
	if err != nil || pst.Mode().Perm() != 0o600 {
		t.Fatalf("pending stat err=%v mode=%o, want 0600", err, pst.Mode().Perm())
	}
	// ReadPending leaves the file on disk until ClearPending is called.
	if got := ReadPending(dir); got == nil || got.ID != "snap-1" {
		t.Fatalf("ReadPending=%+v", got)
	}
	if _, err := os.Stat(pendPath); err != nil {
		t.Fatalf("ReadPending removed pending-webhook.json before delivery")
	}
	ClearPending(dir)
	if _, err := os.Stat(pendPath); !os.IsNotExist(err) {
		t.Fatalf("ClearPending left pending-webhook.json behind")
	}
}
