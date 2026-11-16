package archive

import (
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/htmlscan"
)

func TestPagePick(t *testing.T) {
	at := func(d int) time.Time { return time.Date(2023, 1, d, 0, 0, 0, 0, time.UTC) }
	caps := []Capture{
		{URL: "https://h/a/b/c", Time: at(9)},
		{URL: "https://h/login", Time: at(5)},
		{URL: "https://h/", Time: at(1)},
		{URL: "https://h/", Time: at(3)},
		{URL: "https://h/?utm=1", Time: at(8)},
		{URL: "https://h/about", Time: at(7)},
	}
	got := pagePick(caps, 4)
	want := []string{"https://h/", "https://h/?utm=1", "https://h/about", "https://h/login"}
	if len(got) != len(want) {
		t.Fatalf("got %d pages", len(got))
	}
	for i, c := range got {
		if c.URL != want[i] {
			t.Errorf("%d: %s, want %s", i, c.URL, want[i])
		}
	}
	if !got[0].Time.Equal(at(3)) {
		t.Errorf("the root's capture is not the newest: %v", got[0].Time)
	}
}

func TestChallengePage(t *testing.T) {
	for body, want := range map[string]bool{
		`<title>Just a moment...</title>`:                                                 true,
		`<script>window._cf_chl_opt={}</script>`:                                          true,
		`<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>`: true,
		`<title>Admin</title><script src="/static/js/main.js"></script>`:                  false,
	} {
		if got := challengePage(htmlscan.Scan([]byte(body), "https://h/")); got != want {
			t.Errorf("%s: %v, want %v", body, got, want)
		}
	}
}
