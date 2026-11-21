package browser

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRound41StaleProfileSweep(t *testing.T) {
	tmp := t.TempDir()
	now := time.Now()
	old := now.Add(-30 * time.Hour)

	mkProfile := func(name string, mtime time.Time) string {
		d := filepath.Join(tmp, name)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(d, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return d
	}

	staleNoLock := mkProfile("jsharvest-profile-nolock", old)
	staleDeadPID := mkProfile("jsharvest-profile-dead", old)
	if err := os.Symlink("host-999999999", filepath.Join(staleDeadPID, "SingletonLock")); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(staleDeadPID, old, old)

	fresh := mkProfile("jsharvest-profile-fresh", now.Add(-1*time.Hour))

	staleLivePID := mkProfile("jsharvest-profile-live", old)
	if err := os.Symlink(fmt.Sprintf("host-%d", os.Getpid()), filepath.Join(staleLivePID, "SingletonLock")); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(staleLivePID, old, old)

	unrelated := mkProfile("other-temp-dir", old)

	sweepStaleProfiles(tmp, now)

	for _, gone := range []string{staleNoLock, staleDeadPID} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be swept, stat err=%v", gone, err)
		}
	}
	for _, kept := range []string{fresh, staleLivePID, unrelated} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("expected %s to remain, stat err=%v", kept, err)
		}
	}
}
