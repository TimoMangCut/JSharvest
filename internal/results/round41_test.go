package results

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestRound41FinishedSkipsCorruptAndReadsRecoveredRuns(t *testing.T) {
	dir := t.TempDir()
	runsPath := filepath.Join(dir, "runs.jsonl")

	// Simulate an empty 0-byte runs.jsonl first: AppendOpen must not prepend a blank line.
	if err := os.WriteFile(runsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f1, err := traffic.AppendOpen(runsPath)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(RunInfo{RunID: "20261121T080000.000Z", Requests: 3})
	_, _ = f1.Write(append(b1, '\n'))
	// Now simulate a crash mid-line on run 2 (no trailing newline).
	_, _ = f1.Write([]byte(`{"run_id":"20261121T080100.000Z","requests":`))
	_ = f1.Close()

	// Next run opens runs.jsonl via AppendOpen: isolates the truncated fragment and writes run 3 cleanly.
	f2, err := traffic.AppendOpen(runsPath)
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := json.Marshal(RunInfo{RunID: "20261121T080200.000Z", Requests: 9})
	_, _ = f2.Write(append(b3, '\n'))
	_ = f2.Close()

	got := Open(dir).Finished()
	if len(got) != 2 || got[0].RunID != "20261121T080000.000Z" || got[1].RunID != "20261121T080200.000Z" {
		t.Fatalf("Finished() = %+v, want 2 clean runs around truncated crash line", got)
	}
}
