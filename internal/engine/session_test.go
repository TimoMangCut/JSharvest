package engine

import (
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/session"
)

// Round 25N review: a request of a page sent to the login page is a sign
// the session ended on the server while the page loaded (the frontier's
// -tabs race: one tab's page ended it while another's chunk was asked).
func TestIsLoginRedirect(t *testing.T) {
	const login = "http://app.test/login"
	for _, c := range []struct {
		login, target, from, to string
		want                    bool
	}{
		{login, "http://app.test/", "http://app.test/members/d-chunk.js", "http://app.test/login?next=%2Fmembers%2Fd-chunk.js", true},
		{login, "http://app.test/", "http://app.test/api/me", "http://app.test/login/", true},
		// Another host's login page, a redirect within the login, a redirect elsewhere.
		{login, "http://app.test/", "http://app.test/x.js", "http://sso.test/login", false},
		{login, "http://app.test/", "http://app.test/login", "http://app.test/login?step=2", false},
		{login, "http://app.test/", "http://app.test/old", "http://app.test/new", false},
		// A crawl of the login page, and a login page at "/".
		{login, "http://app.test/login", "http://app.test/x", "http://app.test/login", false},
		{"http://app.test/", "http://app.test/", "http://app.test/x", "http://app.test/", false},
		{"", "http://app.test/", "http://app.test/x", "http://app.test/login", false},
	} {
		if got := isLoginRedirect(c.login, c.target, c.from, c.to); got != c.want {
			t.Errorf("isLoginRedirect(%s, %s, %s -> %s) = %v, want %v", c.login, c.target, c.from, c.to, got, c.want)
		}
	}
}

// A response the guard made up is no word of the server: it must not read as a
// lost session.
func TestPageCauseIgnoresGuardAnswer(t *testing.T) {
	k := &keeper{login: &Login{Snapshot: &session.Snapshot{LoginURL: "http://app.test/login", Signs: session.Signs{Cookies: []string{"sid"}}}}, target: "http://app.test/"}
	real := detect.Doc{URL: "http://app.test/x", Status: 403}
	if k.pageCause(real) != "status" {
		t.Fatal("a real 403 must still count")
	}
	made := detect.Doc{URL: "http://app.test/x", Status: 403, Headers: map[string]string{"x-jsharvest-guard": "write"}}
	if c := k.pageCause(made); c != "" {
		t.Errorf("guard's 403 counted: %q", c)
	}
}

// A login kept in storage: a document opened as a page answers 401 (the
// token rides on the app's requests, never on navigations): no loss. With
// a sign cookie it still counts (P5.6).
func TestPageCauseStorageLoginAPIDoc(t *testing.T) {
	k := &keeper{login: &Login{Snapshot: &session.Snapshot{LoginURL: "http://app.test/login"}}, target: "http://app.test/"}
	api := detect.Doc{URL: "http://app.test/Auth/Keys", Status: 401, Headers: map[string]string{"content-type": "application/json"}}
	if c := k.pageCause(api); c != "" {
		t.Errorf("a JSON 401 of a storage login counted: %q", c)
	}
	bare := detect.Doc{URL: "http://app.test/Auth/Keys", Status: 401}
	if c := k.pageCause(bare); c != "" {
		t.Errorf("a 401 with no type of a storage login counted: %q", c)
	}
	k.login.Snapshot.Signs.Cookies = []string{"sid"}
	if k.pageCause(api) != "status" {
		t.Error("with a sign cookie a JSON 401 must still count")
	}
}
