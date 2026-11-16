package session

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/marker"
)

func cookie(domain, name, value string, expires float64) *network.Cookie {
	return &network.Cookie{Domain: domain, Name: name, Value: value, Path: "/", Expires: expires, Session: expires <= 0}
}

func TestSignsAndMissing(t *testing.T) {
	before := []*network.Cookie{cookie("app.test", "lang", "en", 0), cookie("app.test", "session", "anon", 0)}
	after := []*network.Cookie{cookie("app.test", "lang", "en", 0), cookie("app.test", "session", "s3cr3t", 0),
		cookie(".app.test", "role", "admin", 0), cookie("app.test", "empty", "", 0)}
	signs := NewCookies(before, after)
	if !slices.Equal(signs, []string{"role", "session"}) {
		t.Fatalf("signs %v: the login set session (changed) and role (new); lang did not change", signs)
	}
	s := &Snapshot{Signs: Signs{Cookies: signs}}
	if miss := s.Missing(after); len(miss) != 0 {
		t.Fatalf("missing %v", miss)
	}
	wiped := []*network.Cookie{cookie("app.test", "lang", "en", 0), cookie("app.test", "session", "", 0)}
	if miss := s.Missing(wiped); !slices.Equal(miss, []string{"role", "session"}) {
		t.Fatalf("after a wipe: %v", miss)
	}
}

func TestParams(t *testing.T) {
	exp := float64(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	s := &Snapshot{Cookies: []*network.Cookie{cookie("app.test", "session", "x", 0), cookie(".app.test", "keep", "y", exp)}}
	p := s.Params()
	if p[0].Expires != 0 || p[1].Expires.Float64() != exp || p[1].Domain != ".app.test" {
		t.Fatalf("%+v %+v", p[0], p[1])
	}
}

func TestRestoreScript(t *testing.T) {
	s := &Snapshot{Storage: map[string]Storage{"http://app.test": {Local: map[string]string{"auth": "tok"}, Session: map[string]string{"tab": "1"}}}}
	src := s.RestoreScript()
	for _, want := range []string{`"http://app.test"`, `"auth":"tok"`, "getItem(k) === null", marker.Internal} {
		if !strings.Contains(src, want) {
			t.Fatalf("no %q in %s", want, src)
		}
	}
	if (&Snapshot{}).RestoreScript() != "" {
		t.Fatal("a script with nothing to put back")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	s := &Snapshot{Target: "http://app.test/", Role: "admin", Signs: Signs{Cookies: []string{"session"}}}
	if Exists(dir) {
		t.Fatal("exists before")
	}
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, File)); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	got, err := Load(dir)
	if err != nil || got.Role != "admin" || !Exists(dir) {
		t.Fatal(got, err)
	}
}

func TestReadSteps(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "steps.json")
	os.WriteFile(p, []byte(`[{"do":"goto","url":"http://app.test/login"},{"do":"type","selector":"#p","text":"${JSH_TEST_PASS}"},{"do":"click","selector":"#go"}]`), 0o600)
	os.Unsetenv("JSH_TEST_PASS")
	if _, err := ReadSteps(p); err == nil || !strings.Contains(err.Error(), "JSH_TEST_PASS") {
		t.Fatalf("a missing variable: %v", err)
	}
	t.Setenv("JSH_TEST_PASS", "hunter22")
	steps, err := ReadSteps(p)
	if err != nil || len(steps) != 3 || expand(steps[1].Text) != "hunter22" {
		t.Fatal(steps, err)
	}
	os.WriteFile(p, []byte(`[{"do":"submit"}]`), 0o600)
	if _, err := ReadSteps(p); err == nil {
		t.Fatal("an unknown step")
	}
}

// A sign cookie gone from its own domain is missing, though another host of
// the target still has one of that name (Reviewer NEW-4.6-02).
func TestMissingByDomain(t *testing.T) {
	before := []*network.Cookie{cookie("sub.app.test", "session", "other", 0)}
	after := []*network.Cookie{cookie("sub.app.test", "session", "other", 0), cookie("app.test", "session", "s3cr3t", 0)}
	s := &Snapshot{Signs: Signs{Cookies: NewCookies(before, after), Keys: NewCookieKeys(before, after)}}
	if len(s.Missing(after)) != 0 {
		t.Fatal("missing right after the login")
	}
	wiped := []*network.Cookie{cookie("sub.app.test", "session", "other", 0)}
	if miss := s.Missing(wiped); !slices.Equal(miss, []string{"session"}) {
		t.Fatalf("the login's own session cookie is gone: %v", miss)
	}
	// A snapshot saved before the keys: by name, as it was.
	old := &Snapshot{Signs: Signs{Cookies: []string{"session"}}}
	if len(old.Missing(wiped)) != 0 {
		t.Fatal("an old snapshot reads names only")
	}
}
