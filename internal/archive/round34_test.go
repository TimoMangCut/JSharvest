package archive

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/store"
)

func TestArchiveGzipCDXFamilyStrideAndNoHTMLJSONL(t *testing.T) {
	// Build 32 versions of a CMS/CI bundle /sites/default/files/js/js_<hash>.js:
	// - Versions 0..13 and 18..31 only change UI strings (identical empty APISig).
	// - Versions 14..17 introduce a temporary debug endpoint "/api/v1/temp-debug-34"
	//   that was later removed before version 31!
	type ver struct {
		ts     string
		url    string
		body   []byte
		digest string
	}
	var versions []ver
	bodyByKey := map[string][]byte{}
	for i := 0; i < 32; i++ {
		ts := fmt.Sprintf("202401%02d120000", (i%28)+1)
		if i >= 28 {
			ts = fmt.Sprintf("202402%02d120000", (i-28)+1)
		}
		tok := fmt.Sprintf("cmsBuildHash%02dAbCdEf123456", i)
		u := fmt.Sprintf("https://cms.example.test/sites/default/files/js/js_%s.js", tok)
		code := fmt.Sprintf("console.log('ui-theme-%d');", i)
		if i >= 14 && i <= 17 {
			code += `fetch("/api/v1/temp-debug-34");`
		}
		b := []byte(code)
		versions = append(versions, ver{ts: ts, url: u, body: b, digest: store.SHA1B32(b)})
		bodyByKey[ts+"|"+u] = b
	}

	var mementoFetches atomic.Int32
	var sawGzipCDX atomic.Bool
	var sawIdentityMemento atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cdx/search/cdx":
			if r.URL.Query().Get("showNumPages") == "true" {
				_, _ = w.Write([]byte("2\n"))
				return
			}
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				sawGzipCDX.Store(true)
			}
			page := r.URL.Query().Get("page")
			rows := [][]string{{"timestamp", "original", "mimetype", "statuscode", "digest"}}
			if page == "0" {
				rows = append(rows, []string{"20240210000000", "https://cms.example.test/", "text/html", "200", "HTMLDIGEST1"})
				for _, v := range versions[:16] {
					rows = append(rows, []string{v.ts, v.url, "application/javascript", "200", v.digest})
				}
			} else {
				for _, v := range versions[16:] {
					rows = append(rows, []string{v.ts, v.url, "application/javascript", "200", v.digest})
				}
			}
			rawJSON, _ := json.Marshal(rows)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			var gz bytes.Buffer
			zw := gzip.NewWriter(&gz)
			_, _ = zw.Write(rawJSON)
			_ = zw.Close()
			_, _ = w.Write(gz.Bytes())

		case strings.HasPrefix(r.URL.Path, "/web/"):
			if r.Header.Get("Accept-Encoding") == "identity" {
				sawIdentityMemento.Store(true)
			}
			rest := strings.TrimPrefix(r.URL.Path, "/web/")
			idx := strings.Index(rest, "id_/")
			if idx < 0 {
				http.NotFound(w, r)
				return
			}
			ts := rest[:idx]
			orig := rest[idx+4:]
			if orig == "https://cms.example.test/" {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<html><head><title>CMS</title></head><body><script>fetch("/api/v1/inline-cms")</script></body></html>`))
				return
			}
			mementoFetches.Add(1)
			b, ok := bodyByKey[ts+"|"+orig]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	root := t.TempDir()
	archDir := filepath.Join(root, "cms.example.test", "archive")
	client := NewClientSafe(nil, nil, []string{srv.URL})
	client.Wait = 0

	sum, err := Run(context.Background(), Options{
		Dir:     archDir,
		Root:    root,
		Host:    "cms.example.test",
		InScope: func(h string) bool { return h == "cms.example.test" },
		Sources: []string{"wayback"},
		MaxHTML: 5,
		MaxBody: 4 << 20,
		Workers: 8,
		Wayback: &Wayback{
			Base:     srv.URL,
			Client:   client,
			Index:    &Budget{},
			Files:    &Budget{},
			Collapse: "digest",
			Sharded:  true,
		},
		Log: func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("archive.Run: %v", err)
	}
	if !sawGzipCDX.Load() {
		t.Error("expected CDX index request to advertise Accept-Encoding: gzip")
	}
	if !sawIdentityMemento.Load() {
		t.Error("expected memento request to preserve Accept-Encoding: identity")
	}
	// html.jsonl must NOT be created in stateVersion 3.
	if _, err := os.Stat(filepath.Join(archDir, "html.jsonl")); !os.IsNotExist(err) {
		t.Errorf("expected html.jsonl to be eliminated, stat err=%v", err)
	}
	if sum.Pages != 1 || sum.Inline != 1 {
		t.Errorf("expected 1 archived HTML page read with 1 inline script, got pages=%d inline=%d", sum.Pages, sum.Inline)
	}
	// Family stride + binary zoom-in must skip a large share of the 32 redundant CMS builds...
	if int(mementoFetches.Load()) >= 24 || sum.Skipped["family unchanged"] < 8 {
		t.Errorf("expected family stride pruning: fetches=%d skipped=%v", mementoFetches.Load(), sum.Skipped)
	}
	// ...while STILL recovering the temporary mid-timeline endpoint /api/v1/temp-debug-34!
	histBytes, err := os.ReadFile(filepath.Join(archDir, "historical.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(histBytes, []byte("/api/v1/temp-debug-34")) {
		t.Fatalf("binary zoom-in missed temporary mid-timeline endpoint /api/v1/temp-debug-34:\n%s", string(histBytes))
	}
	if !bytes.Contains(histBytes, []byte("/api/v1/inline-cms")) {
		t.Fatalf("HTMLTop candidate pool missed inline endpoint /api/v1/inline-cms:\n%s", string(histBytes))
	}
}
