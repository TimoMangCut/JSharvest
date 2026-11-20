package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/session"
)

func TestRound41ReloginFailureKeepsSnapshotAndStorage(t *testing.T) {
	dir := t.TempDir()
	k := testKeeper(dir)
	if err := k.login.Snapshot.Save(dir); err != nil {
		t.Fatal(err)
	}
	diskBefore, err := os.ReadFile(filepath.Join(dir, session.File))
	if err != nil {
		t.Fatal(err)
	}
	prevSnap := k.login.Snapshot
	k.dirty = true

	// Build a candidate snapshot with new storage on the same origin: must not
	// overwrite prevSnap.Storage via shallow map aliasing.
	cand := k.buildReloginSnapshot(
		prevSnap.Cookies,
		[]*network.Cookie{ck("app.test", "sid", "bad-login")},
		&originStorage{origin: "http://app.test", Storage: session.Storage{Local: map[string]string{"rt": "corrupted-login-page"}}},
	)
	if got := prevSnap.Storage["http://app.test"].Local["rt"]; got != "old" {
		t.Fatalf("buildReloginSnapshot mutated prevSnap.Storage in place: got %q, want \"old\"", got)
	}

	// 1. Verify fails: disk bytes, in-memory snapshot, and dirty flag must stay untouched.
	var sawDuringVerify string
	k.mu.Lock()
	ok, why := k.finishRelogin(cand, func() (bool, string) {
		sawDuringVerify = k.snapCopy().Cookies[0].Value
		return false, "check URL returned 401"
	})
	k.mu.Unlock()
	if ok || why == "" {
		t.Fatalf("expected finishRelogin failure, got ok=%v why=%q", ok, why)
	}
	if sawDuringVerify != "bad-login" {
		t.Fatalf("verify did not see candidate snapshot: saw %q", sawDuringVerify)
	}
	diskAfterFail, err := os.ReadFile(filepath.Join(dir, session.File))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diskBefore, diskAfterFail) {
		t.Fatalf("failed relogin modified %s on disk", session.File)
	}
	if k.login.Snapshot != prevSnap || !k.dirty || k.stats.Saved {
		t.Fatalf("failed relogin did not restore state: snapSame=%v dirty=%v saved=%v",
			k.login.Snapshot == prevSnap, k.dirty, k.stats.Saved)
	}
	if got := k.snapCopy().Storage["http://app.test"].Local["rt"]; got != "old" {
		t.Fatalf("restored snapshot storage=%q, want \"old\"", got)
	}

	// 2. Verify succeeds: new snapshot is persisted to disk and dirty cleared.
	good := k.buildReloginSnapshot(
		prevSnap.Cookies,
		[]*network.Cookie{ck("app.test", "sid", "verified-good")},
		&originStorage{origin: "http://app.test", Storage: session.Storage{Local: map[string]string{"rt": "verified-rt"}}},
	)
	k.mu.Lock()
	ok, why = k.finishRelogin(good, func() (bool, string) { return true, "" })
	k.mu.Unlock()
	if !ok || why != "" {
		t.Fatalf("expected finishRelogin success, got ok=%v why=%q", ok, why)
	}
	loaded, err := session.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Cookies[0].Value != "verified-good" || loaded.Storage["http://app.test"].Local["rt"] != "verified-rt" {
		t.Fatalf("persisted snapshot mismatch: %+v", loaded)
	}
	if k.dirty || !k.stats.Saved {
		t.Fatalf("expected dirty=false saved=true, got dirty=%v saved=%v", k.dirty, k.stats.Saved)
	}
}
