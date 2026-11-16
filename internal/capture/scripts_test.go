package capture

import (
	"fmt"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/marker"
)

// Two sessions parse the same script at once: the second sighting waits for
// the first read and is emitted after the content, with its hash.
func TestHashWaiters(t *testing.T) {
	var got []string
	c := &Capture{hashes: map[string]string{}, hashWaiters: map[string][]Script{}}
	c.sink = func(s Script) { got = append(got, fmt.Sprintf("%s/%s/%s", s.Target, s.SHA256, string(s.Body))) }

	if _, st := c.claimHash("h1", Script{Target: "page"}); st != hashNew {
		t.Fatalf("first claim = %v, want hashNew", st)
	}
	if _, st := c.claimHash("h1", Script{Target: "worker"}); st != hashPending {
		t.Fatalf("second claim = %v, want hashPending", st)
	}
	c.claimHash("h1", Script{Target: "iframe"})
	c.emit(Script{Target: "page", Body: []byte("src")})
	c.knownHash("h1", "abc")
	if want := "[page//src worker/abc/ iframe/abc/]"; fmt.Sprint(got) != want {
		t.Fatalf("emitted %v, want %s", got, want)
	}
	if sha, st := c.claimHash("h1", Script{Target: "page"}); st != hashKnown || sha != "abc" {
		t.Fatalf("later claim = %v %q, want hashKnown abc", st, sha)
	}

	// A failed read drops the waiters and frees the hash for a new claim.
	got = nil
	c.claimHash("h2", Script{Target: "page"})
	c.claimHash("h2", Script{Target: "worker"})
	c.releaseHash("h2")
	if _, st := c.claimHash("h2", Script{Target: "worker"}); st != hashNew || len(got) != 0 {
		t.Fatalf("after release: state %v, emitted %v", st, got)
	}
}

// jsharvest's own code is never stored as the target's: the tagger was,
// in every crawl that recorded actions, until 4.7 found it in a store.
func TestOwnScript(t *testing.T) {
	for src, want := range map[string]bool{
		"self": true,
		"(() => {})()\n//# sourceURL=jsharvest-tagger": true,
		"fetch(x)\n//# sourceURL=jsharvest-internal":   true,
		"(() => {})()\n//# sourceURL=" + marker.Tagger: true,
		"fetch(x)\n//# sourceURL=" + marker.Internal:   true,
		"console.log('JSHMARK:eval:main')":             false,
	} {
		if got := ownScript("", src); got != want {
			t.Errorf("%q: %v", src, got)
		}
	}
	if ownScript("http://app.test/self.js", "self") {
		t.Error("a page's script that reads self")
	}
}
