package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Round 25I/25J: the User-Agent a role's bare requests go with: its
// login's, else its own crawls' browser's, else the target's; Chrome's
// own requests before the HTTP engine's, never a headless or a library's.
func TestPickUA(t *testing.T) {
	root := t.TempDir()
	write := func(role string, es ...traffic.Entry) {
		d := filepath.Join(root, role)
		os.MkdirAll(d, 0o700)
		var b strings.Builder
		for _, e := range es {
			j, _ := json.Marshal(e)
			b.Write(append(j, '\n'))
		}
		os.WriteFile(filepath.Join(d, "requests.jsonl"), []byte(b.String()), 0o600)
	}
	e := func(ua string, tags ...string) traffic.Entry {
		return traffic.Entry{Headers: map[string]string{"user-agent": ua}, Tags: tags}
	}
	const chrome, engine, user = "Mozilla/5.0 Chrome/156.0.0.0", "Mozilla/5.0 Chrome/141.0.0.0", "Mozilla/5.0 Chrome/155.0.0.0 user"
	write("anon", e(chrome), e(chrome), e(engine, "http"), e(engine, "http"), e(engine, "http"),
		e("Go-http-client/1.1"), e("Mozilla/5.0 HeadlessChrome/156"), e("Mozilla/5.0 (jsharvest archive check)"))
	write("user", e(user))
	glob := filepath.Join(root, "*")
	for _, c := range []struct {
		name string
		snap *session.Snapshot
		role string
		want string
	}{
		{"the login's", &session.Snapshot{UserAgent: "Mozilla/5.0 login"}, "user", "Mozilla/5.0 login"},
		{"the role's own", nil, "user", user},
		{"the target's, Chrome's before the engine's", nil, "admin", chrome},
		{"a headless login is not taken", &session.Snapshot{UserAgent: "Mozilla/5.0 HeadlessChrome/156"}, "anon", chrome},
	} {
		if got := pickUA(c.snap, filepath.Join(root, c.role), glob); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := observedUA(filepath.Join(root, "none*")); got != "" {
		t.Errorf("no traffic: %q", got)
	}
}
