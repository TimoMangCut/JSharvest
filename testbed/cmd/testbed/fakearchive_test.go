package main

import (
	"strings"
	"testing"
)

func TestFakeArchiveRehost(t *testing.T) {
	const app = "../../apps/archive-app"
	plain, err := loadFakeArchive(app)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Wayback) == 0 {
		t.Fatal("no captures")
	}
	for _, c := range plain.Wayback {
		if strings.Contains(c.URL, "pxy.jsh.test") {
			t.Fatalf("rehosted without being asked: %s", c.URL)
		}
	}
	t.Setenv("FAKE_ARCHIVE_REHOST", "pxy.jsh.test:8770")
	re, err := loadFakeArchive(app)
	if err != nil {
		t.Fatal(err)
	}
	if len(re.Wayback) != len(plain.Wayback) {
		t.Fatalf("%d captures, was %d", len(re.Wayback), len(plain.Wayback))
	}
	was, now := 0, 0
	for _, c := range plain.Wayback {
		if strings.Contains(c.URL, "127.0.0.1:8770") {
			was++
		}
	}
	for _, c := range re.Wayback {
		if strings.Contains(c.URL, "127.0.0.1:8770") {
			t.Errorf("not rehosted: %s", c.URL)
		}
		if strings.HasPrefix(c.URL, "http://pxy.jsh.test:8770/") {
			now++
		}
		if c.digest == "" {
			t.Errorf("no digest for %s", c.URL)
		}
	}
	moved := was
	if now != was {
		t.Fatalf("%d rehosted, %d were on 127.0.0.1:8770", now, was)
	}
	if moved == 0 {
		t.Fatal("nothing of the history was on 127.0.0.1:8770")
	}
}
