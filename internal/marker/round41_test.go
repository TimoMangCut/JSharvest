package marker_test

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/marker"
)

func TestRound41SeededMarkersRecognizeDefaultRuns(t *testing.T) {
	// Default (unseeded) build preserves exact historical marker values.
	if marker.Internal != "rt-4f9c2a.js" || marker.Tagger != "pf-8d1e7b.js" ||
		marker.TaggerKey != "pf.8d1e7b" || marker.TaskPrefix != "pf8d1e7b:" {
		t.Fatalf("unseeded defaults changed: internal=%q tagger=%q key=%q prefix=%q",
			marker.Internal, marker.Tagger, marker.TaggerKey, marker.TaskPrefix)
	}

	// Build-seeded test binary derives distinct markers AND still recognizes default + legacy run artifacts.
	cmd := exec.Command("go", "test", "-ldflags", "-X github.com/TimoMangCut/JSharvest/internal/marker.seed=round41-seed",
		"-run", "^TestRound41SeededBinaryHelper$", "github.com/TimoMangCut/JSharvest/internal/marker")
	cmd.Env = append(cmd.Environ(), "GOTOOLCHAIN=local", "JSHARVEST_TEST_SEEDED_MARKER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("seeded go test failed: %v\n%s", err, out)
	}
}

func TestRound41SeededBinaryHelper(t *testing.T) {
	if marker.Internal == "rt-4f9c2a.js" {
		// Running unseeded in normal suite; nothing else to assert here.
		return
	}
	if !strings.HasPrefix(marker.Internal, "rt-") || !strings.HasSuffix(marker.Internal, ".js") {
		t.Fatalf("bad seeded Internal: %q", marker.Internal)
	}
	if marker.Tagger == "pf-8d1e7b.js" || marker.TaggerKey == "pf.8d1e7b" || marker.TaskPrefix == "pf8d1e7b:" {
		t.Fatalf("seeded markers did not change: tagger=%q key=%q prefix=%q", marker.Tagger, marker.TaggerKey, marker.TaskPrefix)
	}

	// Must recognize dynamic, default ("rt-4f9c2a.js", "pf-8d1e7b.js"), and legacy ("jsharvest-*") markers.
	for _, u := range []string{marker.Internal, "rt-4f9c2a.js", "jsharvest-internal"} {
		if !marker.IsInternal(u) {
			t.Fatalf("IsInternal(%q) = false in seeded build", u)
		}
	}
	for _, u := range []string{marker.Tagger, "pf-8d1e7b.js", "jsharvest-tagger"} {
		if !marker.IsTagger(u) {
			t.Fatalf("IsTagger(%q) = false in seeded build", u)
		}
	}
	for _, src := range []string{
		"//# sourceURL=" + marker.Internal,
		"//# sourceURL=rt-4f9c2a.js",
		"//# sourceURL=pf-8d1e7b.js",
		"//# sourceURL=jsharvest-tagger",
	} {
		if !marker.InSource(src) {
			t.Fatalf("InSource(%q) = false in seeded build", src)
		}
	}

	// flow.Build in seeded build must trace causal tasks from seeded, default ("pf8d1e7b:"), and legacy ("jsh:") runs.
	t0 := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	for i, pfx := range []string{marker.TaskPrefix, "pf8d1e7b:", "jsh:"} {
		actTag := "D:1000:click"
		ev := flow.Event{
			Tag:     actTag,
			Type:    "click",
			Wall:    t0,
			Trusted: true,
			Top:     true,
			URL:     "https://app.example/",
			Element: &flow.Element{Tag: "button", ID: "save", Label: "save"},
		}
		reqs := []flow.Request{{
			ID:           i + 1,
			Time:         t0.Add(50 * time.Millisecond),
			End:          t0.Add(70 * time.Millisecond),
			Target:       "page",
			Page:         "https://app.example/",
			Method:       "POST",
			URL:          "https://app.example/api/save",
			ResourceType: "Fetch",
			Outcome:      "ok",
			Chain:        []string{pfx + actTag},
			Stack:        []flow.Frame{{URL: "https://app.example/app.js", Func: "save", Line: 1, Col: 1}},
		}}
		fs := flow.Build([]flow.Event{ev}, reqs, flow.Options{Run: "r1"})
		foundCausal := false
		for _, f := range fs {
			for _, ref := range f.Requests {
				if ref.ID == i+1 && ref.How == flow.Causal {
					foundCausal = true
				}
			}
		}
		if !foundCausal {
			t.Fatalf("seeded flow.Build did not trace prefix %q causally: %+v", pfx, fs)
		}
	}
}
