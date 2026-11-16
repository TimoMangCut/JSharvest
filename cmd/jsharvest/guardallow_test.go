package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/session"
)

func TestLoginRefusesUnanchoredGuardAllow(t *testing.T) {
	for _, re := range []string{`/api/auth/refresh`, `^https://.*/refresh`, `^https://evil\.io/refresh`, `^https://app\.x\.com/a|.*`} {
		dir := t.TempDir()
		err := runLogin([]string{"-u", "https://app.x.com/login", "-profiles", dir, "-guard-allow", re})
		if err == nil {
			t.Fatalf("%q: login went on", re)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Fatalf("%q: something was written: %v", re, ents)
		}
	}
}

func TestSessionGuardAllowORsWithFlag(t *testing.T) {
	dir := t.TempDir()
	snap := &session.Snapshot{Target: "https://app.x.com/", GuardAllow: []string{
		`^https://app\.x\.com/api/auth/refresh(\?|$)`,
		`^https://.*/anything`, // edited into the file: ignored
	}}
	if err := snap.Save(dir); err != nil {
		t.Fatal(err)
	}
	back, err := session.Load(dir)
	if err != nil || len(back.GuardAllow) != 2 {
		t.Fatalf("round trip: %v %v", back, err)
	}
	extra := sessionGuardAllow(back, "rdn")
	if len(extra) != 1 {
		t.Fatalf("kept %v", extra)
	}
	rules, err := guardRules(`^https://app\.x\.com/bff/renew$`, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if rules, err = rules.WithAllow(extra...); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		url  string
		pass bool
	}{
		{"https://app.x.com/api/auth/refresh", true},
		{"https://app.x.com/bff/renew", true},
		{"https://app.x.com/api/auth/refresh2", false},
		{"https://evil.io/anything", false},
	} {
		d := rules.Classify(guard.Request{Method: "POST", URL: c.url})
		if (d.Action == guard.Pass) != c.pass {
			t.Errorf("%s: %+v", c.url, d)
		}
	}
	_ = filepath.Join
}
