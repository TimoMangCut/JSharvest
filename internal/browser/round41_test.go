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

	myHost, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname: %v", err)
	}

	staleNoLock := mkProfile("jsharvest-profile-nolock", old)
	staleDeadPID := mkProfile("jsharvest-profile-dead", old)
	if err := os.Symlink(fmt.Sprintf("%s-999999999", myHost), filepath.Join(staleDeadPID, "SingletonLock")); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(staleDeadPID, old, old)

	fresh := mkProfile("jsharvest-profile-fresh", now.Add(-1*time.Hour))

	staleLivePID := mkProfile("jsharvest-profile-live", old)
	if err := os.Symlink(fmt.Sprintf("%s-%d", myHost, os.Getpid()), filepath.Join(staleLivePID, "SingletonLock")); err != nil {
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

func TestRound41StaleProfileForeignHostnameKept(t *testing.T) {
	tmp := t.TempDir()
	now := time.Now()
	old := now.Add(-30 * time.Hour)

	foreign := filepath.Join(tmp, "jsharvest-profile-foreign")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	// PID 999999999 is dead on the local host, but the hostname belongs to a
	// different container/host sharing /tmp: must NOT be deleted.
	if err := os.Symlink("other-container.example-999999999", filepath.Join(foreign, "SingletonLock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(foreign, old, old); err != nil {
		t.Fatal(err)
	}

	sweepStaleProfiles(tmp, now)

	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("expected foreign-host profile %s to be kept, stat err=%v", foreign, err)
	}
}
