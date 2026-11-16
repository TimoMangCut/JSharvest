package engine

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/session"
)

func ck(domain, name, val string) *network.Cookie {
	return &network.Cookie{Domain: domain, Name: name, Value: val, Path: "/"}
}

func testKeeper(profile string) *keeper {
	snap := &session.Snapshot{Cookies: []*network.Cookie{ck("app.test", "sid", "old")},
		Signs:   session.Signs{Cookies: []string{"sid"}, Keys: []string{"app.test|sid"}},
		Storage: map[string]session.Storage{"http://app.test": {Local: map[string]string{"rt": "old"}}}}
	k := newKeeper(nil, &Login{Profile: profile, Snapshot: snap})
	k.target = "http://app.test/"
	k.apiWait = time.Millisecond
	return k
}

func rotated() session.Refresh {
	return session.Refresh{Cookies: []*network.Cookie{ck("app.test", "sid", "new")},
		Storage: map[string]session.Storage{"http://app.test": {Local: map[string]string{"rt": "new"}}}}
}

// A: the rotated token reaches the snapshot only from a living session.
func TestKeeperApplyOnlyWhileAlive(t *testing.T) {
	k := testKeeper("")
	if !k.apply(rotated(), k.Epoch(), time.Now()) {
		t.Fatal("a living session was not refreshed")
	}
	if k.snapCopy().Storage["http://app.test"].Local["rt"] != "new" || k.stats.Refreshed != 1 {
		t.Error("not taken")
	}
	// Logged out: the sign cookie is gone.
	k = testKeeper("")
	if k.apply(session.Refresh{Cookies: []*network.Cookie{ck("app.test", "x", "y")}}, k.Epoch(), time.Now()) {
		t.Error("refreshed from a logged-out browser")
	}
	// A recovery began since the read.
	k = testKeeper("")
	ep := k.Epoch()
	k.epoch.Add(1)
	if k.apply(rotated(), ep, time.Now()) {
		t.Error("refreshed across a recovery")
	}
	// Recovering, lost.
	k = testKeeper("")
	k.setRecovering(true)
	if k.apply(rotated(), k.Epoch(), time.Now()) {
		t.Error("refreshed while recovering")
	}
	k = testKeeper("")
	k.stats.Lost = true
	if k.apply(rotated(), k.Epoch(), time.Now()) {
		t.Error("refreshed a lost session")
	}
	if k.snapCopy().Cookies[0].Value != "old" {
		t.Error("snapshot changed")
	}
}

func TestKeeperSaveStateOnlyIfNotLost(t *testing.T) {
	dir := t.TempDir()
	k := testKeeper(dir)
	k.login.Snapshot.Steps = "s.json"
	if err := k.login.Snapshot.Save(dir); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, session.File))
	os.WriteFile(filepath.Join(dir, session.File), []byte(strings.Replace(string(raw), `"target"`, `"future_field": 7, "target"`, 1)), 0o600)

	k.apply(rotated(), k.Epoch(), time.Now())
	k.stats.Lost = true
	if k.saveState() {
		t.Fatal("a lost session was written")
	}
	if s, _ := session.Load(dir); s.Cookies[0].Value != "old" {
		t.Fatal("file changed by a lost session")
	}
	k.stats.Lost = false
	if !k.saveState() || !k.stats.Saved {
		t.Fatal("not saved")
	}
	s, _ := session.Load(dir)
	if s.Cookies[0].Value != "new" || s.Storage["http://app.test"].Local["rt"] != "new" || s.Steps != "s.json" {
		t.Errorf("got %+v", s)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, session.File))
	if !strings.Contains(string(raw), "future_field") {
		t.Error("a field of the file was dropped")
	}
	if k.saveState() {
		t.Error("written again with nothing new")
	}
}

// B: the count.
func TestAPIWatchCounts(t *testing.T) {
	var w apiWatch
	for range apiThreshold - 1 {
		if w.note(401, apiThreshold) {
			t.Fatal("early")
		}
	}
	if w.note(403, apiThreshold) || w.note(500, apiThreshold) || w.note(302, apiThreshold) {
		t.Fatal("a status other than 401 moved the count")
	}
	if !w.note(401, apiThreshold) {
		t.Fatal("threshold not reached")
	}
	if w.note(401, apiThreshold) {
		t.Error("triggered again while confirming")
	}
	w.done()
	// One 2xx resets.
	for range apiThreshold - 1 {
		w.note(401, apiThreshold)
	}
	w.note(204, apiThreshold)
	for range apiThreshold - 1 {
		if w.note(401, apiThreshold) {
			t.Fatal("a 2xx did not reset")
		}
	}
}

func TestCountsAPI(t *testing.T) {
	const target = "http://app.test/"
	for _, c := range []struct {
		url   string
		guard bool
		want  bool
	}{
		{"http://app.test/api/x", false, true},
		{"http://app.test/api/x", true, false}, // guard's own answer
		{"http://other.test/api/x", false, false},
		{"https://app.test/api/x", false, false},
	} {
		if got := countsAPI(target, "", c.url, c.guard); got != c.want {
			t.Errorf("%s guard=%v: %v", c.url, c.guard, got)
		}
	}
	if !countsAPI(target, "https://app.test/p", "https://app.test/api", false) {
		t.Error("the page's origin")
	}
}

func feed(k *keeper, status, n int) {
	for range n {
		k.apiStatus(nil, "http://app.test/api/x", status, false)
	}
}

func TestAPI401Gone(t *testing.T) {
	k := testKeeper("")
	k.apiGoneFn = func(*engine) bool { return true }
	feed(k, 401, apiThreshold)
	if !k.takeAPILost() {
		t.Fatal("no verdict")
	}
	if k.takeAPILost() {
		t.Error("the verdict stays after it was taken: recover would run twice")
	}
	a := k.stats.API
	if a.Triggers != 1 || a.Confirmed != 1 || a.NotConfirmed != 0 {
		t.Errorf("%+v", a)
	}
	// After it was handled, a new run counts from zero.
	feed(k, 401, apiThreshold-1)
	if k.takeAPILost() {
		t.Error("early")
	}
}

func TestAPI401AliveNoRecover(t *testing.T) {
	k := testKeeper("")
	var asked sync.WaitGroup
	asked.Add(1)
	k.apiGoneFn = func(*engine) bool { asked.Done(); return false }
	feed(k, 401, apiThreshold+3) // the extra 401s do not start a second confirmation
	if k.takeAPILost() {
		t.Fatal("recovered a session the server says is alive")
	}
	a := k.stats.API
	if a.Triggers != 1 || a.Confirmed != 0 || a.NotConfirmed != 1 {
		t.Errorf("%+v", a)
	}
	if n := len(k.stats.Events); n != 1 || k.stats.Events[0].Outcome != "not-confirmed" {
		t.Errorf("events %+v", k.stats.Events)
	}
}

func TestAPI403AndGuardNeverTrigger(t *testing.T) {
	k := testKeeper("")
	k.apiGoneFn = func(*engine) bool { t.Error("asked the server"); return true }
	feed(k, 403, 20)
	for range 20 {
		k.apiStatus(nil, "http://app.test/api/x", 401, true)
		k.apiStatus(nil, "http://other.test/api/x", 401, false)
	}
	if k.takeAPILost() || k.stats.API != nil {
		t.Error("triggered")
	}
}

// A 2xx of the guard's own (a made-up 200 {}) must not reset a real run.
func TestAPIGuardTwoXXDoesNotReset(t *testing.T) {
	k := testKeeper("")
	k.apiGoneFn = func(*engine) bool { return true }
	feed(k, 401, apiThreshold-1)
	k.apiStatus(nil, "http://app.test/api/w", 200, true)
	feed(k, 401, 1)
	if !k.takeAPILost() {
		t.Error("the guard's 200 reset the count")
	}
}

// C: one keeper for each host with a login; none without.
func TestHostKeepers(t *testing.T) {
	var h hostKeepers
	l := &Login{Snapshot: &session.Snapshot{}}
	a1, a2, b := h.forPage("a.test", l), h.forPage("a.test", l), h.forPage("b.test", l)
	if a1 == nil || a1 != a2 || a1 == b {
		t.Error("keepers are not one for each host")
	}
	if h.forPage("c.test", nil) != nil {
		t.Error("anon page got a keeper")
	}
}

func TestKeeperJoinFirstOnly(t *testing.T) {
	k := testKeeper("")
	e1, e2 := &engine{}, &engine{}
	if !k.join(e1) || k.join(e2) {
		t.Error("only the first tab attaches to the workers")
	}
	if k.first() != e1 || len(k.tabList()) != 2 {
		t.Error("tabs")
	}
}

// The last read stops the app first, and reads without its scripts.
func TestFinalizeStopsBeforeReading(t *testing.T) {
	dir := t.TempDir()
	k := testKeeper(dir)
	if err := k.login.Snapshot.Save(dir); err != nil {
		t.Fatal(err)
	}
	var calls []string
	e := &engine{}
	k.finalOps = &finalOps{
		stop:   func(*engine) error { calls = append(calls, "stop"); return nil },
		resume: func(*engine) { calls = append(calls, "resume") },
		read: func(_ *engine, origins []string) (session.Refresh, error) {
			calls = append(calls, "read")
			if len(origins) != 1 || origins[0] != "http://app.test" {
				t.Errorf("origins %v", origins)
			}
			return rotated(), nil
		},
	}
	k.finalize(e)
	if got := strings.Join(calls, ","); got != "stop,read,resume" {
		t.Fatalf("calls %s", got)
	}
	s, _ := session.Load(dir)
	if s.Storage["http://app.test"].Local["rt"] != "new" || s.Cookies[0].Value != "new" {
		t.Errorf("not saved: %+v", s)
	}
}

// A failed stop or read leaves the old way (false), and resumes what it stopped.
func TestFinalReadFallsBack(t *testing.T) {
	k := testKeeper("")
	resumed := 0
	k.finalOps = &finalOps{
		stop:   func(*engine) error { return nil },
		resume: func(*engine) { resumed++ },
		read:   func(*engine, []string) (session.Refresh, error) { return session.Refresh{}, os.ErrInvalid },
	}
	if k.finalRead(&engine{}) || resumed != 1 {
		t.Errorf("resumed %d", resumed)
	}
	k.finalOps.stop = func(*engine) error { return os.ErrInvalid }
	if k.finalRead(&engine{}) {
		t.Error("read with the app running")
	}
}

// install: the snapshot's keys go over the browser's until the first page
// is checked; a key the snapshot lacks is never touched.
func TestInstallOverridesStorageUntilFirstCheck(t *testing.T) {
	k := testKeeper("")
	snap := k.snapCopy()
	over, rest := snap.OverrideScript(), snap.RestoreScript()
	if strings.Contains(over, "getItem(k) === null") || !strings.Contains(rest, "getItem(k) === null") {
		t.Error("scripts: override must set unconditionally, restore only the absent")
	}
	for _, bad := range []string{"removeItem", "clear()"} {
		if strings.Contains(over, bad) {
			t.Errorf("override script touches other keys: %s", bad)
		}
	}
	k.override.Store(true)
	k.mu.Lock()
	k.endOverride()
	k.mu.Unlock()
	if k.override.Load() {
		t.Error("override stays after the first page")
	}
}
