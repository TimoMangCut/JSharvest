package verify

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/replay"
)

// Round 25B (3.4): source_only endpoints are skipped by default in verify.Run
// and omitted from WriteDraftsFull, unless IncludeSourceOnly (-include-source-only)
// is enabled or verify already confirmed the route alive.
func TestRound25SourceOnlyVerifyAndWriteDrafts(t *testing.T) {
	var hitPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPaths = append(hitPaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/active" || r.URL.Path == "/api/treeshaken" {
			w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer srv.Close()

	in := Inputs{
		InScope: func(string) bool { return true },
		Catalog: []endpoints.Endpoint{
			{Method: "GET", Path: "/api/active", Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"},
			{Method: "GET", Path: "/api/treeshaken", Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch", SourceOnly: true},
		},
	}
	ds := Drafts(in)
	if len(ds) != 2 || ds[0].SourceOnly || !ds[1].SourceOnly {
		t.Fatalf("unexpected drafts SourceOnly flags: %+v", ds)
	}

	// 1. Default verify.Run skips SourceOnly without sending a probe for /api/treeshaken.
	s1, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 50})
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()

	rep1, err := Run(context.Background(), Options{
		Target:  "test",
		Role:    "anon",
		Drafts:  ds,
		Sender:  s1,
		InScope: in.InScope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep1.Results[0].Verdict != Alive {
		t.Errorf("active result = %+v, want Alive", rep1.Results[0])
	}
	if rep1.Results[1].Verdict != Skipped || !strings.Contains(rep1.Results[1].Reason, "source_only") {
		t.Errorf("source_only default result = %+v, want Skipped(source_only)", rep1.Results[1])
	}
	for _, p := range hitPaths {
		if p == "/api/treeshaken" {
			t.Errorf("default verify probed /api/treeshaken unexpectedly: %v", hitPaths)
		}
	}

	// 2. WriteDraftsFull with includeSourceOnly=false omits /api/treeshaken.
	dir1 := filepath.Join(t.TempDir(), "drafts-default")
	idx1, err := WriteDraftsFull(dir1, ds, false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if idx1.Files != 1 || idx1.Drafts[1].Omitted == "" {
		t.Errorf("WriteDraftsFull(default): files=%d omitted=%q, want 1 file and omitted reason", idx1.Files, idx1.Drafts[1].Omitted)
	}

	// 3. verify.Run with IncludeSourceOnly=true probes /api/treeshaken and confirms it Alive.
	s2, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 50})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	rep2, err := Run(context.Background(), Options{
		Target:            "test",
		Role:              "anon",
		Drafts:            ds,
		Sender:            s2,
		InScope:           in.InScope,
		IncludeSourceOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Results[1].Verdict != Alive {
		t.Errorf("IncludeSourceOnly result = %+v, want Alive", rep2.Results[1])
	}

	// 4. WriteDraftsFull with includeSourceOnly=true writes valid .http files for both.
	dir2 := filepath.Join(t.TempDir(), "drafts-included")
	idx2, err := WriteDraftsFull(dir2, ds, false, false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if idx2.Files != 2 {
		t.Fatalf("WriteDraftsFull(includeSourceOnly=true): files=%d, want 2", idx2.Files)
	}
	for _, entry := range idx2.Drafts {
		raw, err := os.ReadFile(filepath.Join(dir2, entry.File))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw))); err != nil {
			t.Errorf("invalid .http file %s: %v", entry.File, err)
		}
	}

	// 5. WriteDraftsFull with includeSourceOnly=false STILL writes /api/treeshaken if verify marked it alive.
	dir3 := filepath.Join(t.TempDir(), "drafts-alive")
	idx3, err := WriteDraftsFull(dir3, ds, false, false, false, map[string]string{
		"GET /api/treeshaken": srv.URL + "/api/treeshaken",
	})
	if err != nil || idx3.Files != 2 {
		t.Fatalf("WriteDraftsFull(alive source_only): err=%v files=%d, want 2", err, idx3.Files)
	}
}
