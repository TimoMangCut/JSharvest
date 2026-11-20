package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/lock"
)

func TestRound41MonitorLockAndDryRun(t *testing.T) {
	out := t.TempDir()
	anon := filepath.Join(out, "app.example.test", "anon")
	if err := os.MkdirAll(anon, 0o700); err != nil {
		t.Fatal(err)
	}
	runs := `{"run_id":"R1","mode":"http","exit_code":0,"scripts":[],"target":"https://app.example.test/","started":"2026-11-20T00:00:00Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(anon, "runs.jsonl"), []byte(runs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(anon, "index.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	monDir := filepath.Join(out, "app.example.test", "monitor")
	// 1. -dry-run must not create monitor/ or .jsharvest.lock.
	if err := runMonitor([]string{"-o", out, "-target", "app.example.test", "-dry-run"}); err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if _, err := os.Stat(monDir); !os.IsNotExist(err) {
		t.Fatalf("-dry-run created %s on disk", monDir)
	}

	// 2. While locked by another writer, non-dry-run fails clearly with "in use",
	// whereas -dry-run still works without taking the lock.
	held, err := lock.Acquire("monitor", 0, monDir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	err = runMonitor([]string{"-o", out, "-target", "app.example.test"})
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("second writer got err=%v, want 'in use'", err)
	}
	if err := runMonitor([]string{"-o", out, "-target", "app.example.test", "-dry-run"}); err != nil {
		t.Fatalf("-dry-run failed while writer lock held: %v", err)
	}
}
