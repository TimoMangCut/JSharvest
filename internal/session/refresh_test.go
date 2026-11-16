package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
)

func ck(domain, name, val string) *network.Cookie {
	return &network.Cookie{Domain: domain, Name: name, Value: val, Path: "/"}
}

func inApp(h string) bool { return h == "app.test" }

func base() *Snapshot {
	return &Snapshot{Cookies: []*network.Cookie{ck("app.test", "sid", "old"), ck("cdn.other", "t", "x")},
		Signs:   Signs{Cookies: []string{"sid"}, Keys: []string{"app.test|sid"}},
		Storage: map[string]Storage{"http://app.test": {Local: map[string]string{"rt": "old"}}}}
}

func TestRefreshTakesRotatedState(t *testing.T) {
	s := base()
	now := time.Unix(100, 0)
	ok, why := s.Refresh(Refresh{Cookies: []*network.Cookie{ck("app.test", "sid", "new")},
		Storage: map[string]Storage{"http://app.test": {Local: map[string]string{"rt": "new"}}, "http://other.test": {Local: map[string]string{"z": "1"}}}}, inApp, now)
	if !ok {
		t.Fatal(why)
	}
	if len(s.Cookies) != 2 || s.Cookies[0].Value != "new" || s.Cookies[1].Name != "t" {
		t.Errorf("cookies: %+v", s.Cookies)
	}
	if s.Storage["http://app.test"].Local["rt"] != "new" {
		t.Error("storage not rotated")
	}
	if _, in := s.Storage["http://other.test"]; in {
		t.Error("an origin the snapshot did not know was added")
	}
	if !s.Saved.Equal(now) {
		t.Error("saved time")
	}
}

func TestRefreshNeverTakesLoggedOut(t *testing.T) {
	s := base()
	if ok, _ := s.Refresh(Refresh{Cookies: []*network.Cookie{ck("app.test", "other", "v")}}, inApp, time.Now()); ok {
		t.Fatal("took a state without the sign cookie")
	}
	if ok, _ := s.Refresh(Refresh{Cookies: []*network.Cookie{ck("app.test", "sid", "")}}, inApp, time.Now()); ok {
		t.Fatal("took an empty sign cookie")
	}
	if s.Cookies[0].Value != "old" {
		t.Error("snapshot changed by a refused refresh")
	}
	nosign := &Snapshot{Cookies: []*network.Cookie{ck("app.test", "a", "b")}}
	if ok, _ := nosign.Refresh(Refresh{Cookies: []*network.Cookie{ck("app.test", "a", "c")}}, inApp, time.Now()); ok {
		t.Fatal("refreshed a snapshot with no signs")
	}
}

func TestRefreshEmptyStorageKeepsOld(t *testing.T) {
	s := base()
	s.Refresh(Refresh{Cookies: []*network.Cookie{ck("app.test", "sid", "n")}, Storage: map[string]Storage{"http://app.test": {}}}, inApp, time.Now())
	if s.Storage["http://app.test"].Local["rt"] != "old" {
		t.Error("an empty read replaced the saved storage")
	}
}

func TestSaveStateKeepsOtherFields(t *testing.T) {
	dir := t.TempDir()
	disk := base()
	disk.Steps, disk.UserAgent = "steps.json", "UA"
	if err := disk.Save(dir); err != nil {
		t.Fatal(err)
	}
	// A field this code does not know, as another tool may add.
	raw, _ := os.ReadFile(filepath.Join(dir, File))
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["x_other_tool"] = "^/x"
	raw, _ = json.Marshal(m)
	os.WriteFile(filepath.Join(dir, File), raw, 0o600)

	mem := base()
	mem.Steps = "" // memory lacks what disk has
	mem.Refresh(Refresh{Cookies: []*network.Cookie{ck("app.test", "sid", "new")}}, inApp, time.Now())
	if err := mem.SaveState(dir); err != nil {
		t.Fatal(err)
	}
	got, _ := Load(dir)
	if got.Steps != "steps.json" || got.UserAgent != "UA" || got.Cookies[0].Value != "new" {
		t.Errorf("got %+v", got)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, File))
	if !strings.Contains(string(raw), `"x_other_tool"`) {
		t.Error("an unknown field was dropped")
	}
	if st, _ := os.Stat(filepath.Join(dir, File)); st.Mode().Perm() != 0o600 {
		t.Error("mode")
	}
	_ = raw
}

// A login kept in localStorage (no sign cookie) is refreshed while its keys
// are there, and not once a logout removed one (plan-28 4.3, constraint 1).
func TestRefreshStorageSigns(t *testing.T) {
	o := "https://app.example"
	snap := &Snapshot{Storage: map[string]Storage{o: {Local: map[string]string{"access_token": "old", "refresh_token": "r1"}}}}
	ok, why := snap.Refresh(Refresh{Storage: map[string]Storage{o: {Local: map[string]string{"access_token": "new", "refresh_token": "r2"}}}}, nil, time.Now())
	if !ok || snap.Storage[o].Local["refresh_token"] != "r2" {
		t.Fatalf("rotated token not taken: %v %s %v", ok, why, snap.Storage)
	}
	ok, _ = snap.Refresh(Refresh{Storage: map[string]Storage{o: {Local: map[string]string{"theme": "dark"}}}}, nil, time.Now())
	if ok || snap.Storage[o].Local["refresh_token"] != "r2" {
		t.Fatalf("a logged-out read was taken: %v", snap.Storage)
	}
	ok, _ = snap.Refresh(Refresh{Storage: map[string]Storage{"https://other.example": {Local: map[string]string{"x": "1"}}}}, nil, time.Now())
	if ok {
		t.Fatal("a read of no known origin was taken")
	}
}
