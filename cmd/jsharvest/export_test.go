package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/store"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// makeHTTPOnlyDir builds an -engine http style role directory: index.jsonl +
// js/<sha>.js + static/<sha>.json + endpoints.jsonl, plus a requests.jsonl
// containing only Document and Script fetches (0 live API flows).
func makeHTTPOnlyDir(t *testing.T, root, host string, withStaticCatalog bool) string {
	t.Helper()
	roleDir := filepath.Join(root, targetDir(host), "anon")
	if err := os.MkdirAll(filepath.Join(roleDir, "js"), 0o700); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 16, 4, 0, 0, 0, time.UTC)
	reqs := []traffic.Entry{
		{
			Run:          "R1",
			ID:           1,
			Time:         t0,
			Method:       "GET",
			URL:          "https://" + host + "/",
			ResourceType: "Document",
			Outcome:      "ok",
			Response:     &traffic.Response{Status: 200, Headers: map[string]string{"content-type": "text/html"}},
			Tags:         []string{"http"},
		},
		{
			Run:          "R1",
			ID:           2,
			Time:         t0.Add(time.Second),
			Method:       "GET",
			URL:          "https://" + host + "/assets/app.js",
			ResourceType: "Script",
			Outcome:      "ok",
			Response:     &traffic.Response{Status: 200, Headers: map[string]string{"content-type": "application/javascript"}},
			Tags:         []string{"http"},
		},
	}
	var reqBuf []byte
	for _, r := range reqs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		reqBuf = append(reqBuf, b...)
		reqBuf = append(reqBuf, '\n')
	}
	if err := os.WriteFile(filepath.Join(roleDir, "requests.jsonl"), reqBuf, 0o600); err != nil {
		t.Fatal(err)
	}

	if !withStaticCatalog {
		return roleDir
	}

	code := []byte(`
		const api = axios.create({ baseURL: "/api-gateway" });
		api.get("/v1/users", { params: { page: 1 } });
		api.post("/v1/orders", { sku: "A1", qty: 2 });
	`)
	sum := sha256.Sum256(code)
	sha := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(roleDir, "js", sha+".js"), code, 0o600); err != nil {
		t.Fatal(err)
	}
	idxEntry, err := json.Marshal(store.Entry{
		SHA256: sha,
		URLs:   []string{"https://" + host + "/assets/app.js"},
		Size:   len(code),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roleDir, "index.jsonl"), append(idxEntry, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := scope.New(hostOnly(host), "rdn")
	if err != nil {
		t.Fatal(err)
	}
	eps, _, err := endpoints.CatalogWithStats(roleDir, in, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoints.Write(roleDir, eps); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoints.SaveIntel(roleDir, in, nil); err != nil {
		t.Fatal(err)
	}
	return roleDir
}

func TestExportFormatAllWithoutLiveFlows(t *testing.T) {
	t.Run("static_catalog_with_zero_flows_format_all", func(t *testing.T) {
		root := t.TempDir()
		const host = "admin.example.com"
		makeHTTPOnlyDir(t, root, host, true)
		dest := filepath.Join(root, "out-all")

		if err := runExport([]string{"-o", root, "-target", host, "-format", "all", "-dest", dest}); err != nil {
			t.Fatalf("runExport(-format all) failed: %v", err)
		}
		oaBytes, err := os.ReadFile(filepath.Join(dest, "openapi.json"))
		if err != nil {
			t.Fatalf("openapi.json was not written: %v", err)
		}
		var doc struct {
			OpenAPI string                     `json:"openapi"`
			Paths   map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(oaBytes, &doc); err != nil {
			t.Fatalf("invalid openapi.json: %v", err)
		}
		if doc.OpenAPI != "3.1.0" || len(doc.Paths) == 0 {
			t.Fatalf("expected non-empty OpenAPI 3.1.0 paths, got openapi=%q paths=%v", doc.OpenAPI, doc.Paths)
		}
		if _, ok := doc.Paths["/api-gateway/v1/users"]; !ok {
			t.Errorf("expected /api-gateway/v1/users in openapi.json paths, got %v", doc.Paths)
		}
		if _, err := os.Stat(filepath.Join(dest, "drafts")); !os.IsNotExist(err) {
			t.Errorf("drafts/ should not be written without -drafts, stat err=%v", err)
		}
	})

	t.Run("static_catalog_with_zero_flows_format_all_drafts", func(t *testing.T) {
		root := t.TempDir()
		const host = "admin.example.com"
		makeHTTPOnlyDir(t, root, host, true)
		dest := filepath.Join(root, "out-all-drafts")

		if err := runExport([]string{"-o", root, "-target", host, "-format", "all", "-drafts", "-dest", dest}); err != nil {
			t.Fatalf("runExport(-format all -drafts) failed: %v", err)
		}
		oaBytes, err := os.ReadFile(filepath.Join(dest, "openapi.json"))
		if err != nil {
			t.Fatalf("openapi.json was not written alongside drafts: %v", err)
		}
		var doc struct {
			Paths map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(oaBytes, &doc); err != nil || len(doc.Paths) == 0 {
			t.Fatalf("expected non-empty openapi.json paths, err=%v paths=%v", err, doc.Paths)
		}
		if _, ok := doc.Paths["/api-gateway/v1/orders"]; !ok {
			t.Errorf("expected /api-gateway/v1/orders in openapi.json paths, got %v", doc.Paths)
		}
		idxBytes, err := os.ReadFile(filepath.Join(dest, "drafts", "index.json"))
		if err != nil {
			t.Fatalf("drafts/index.json was not written: %v", err)
		}
		var idx struct {
			Files int `json:"files"`
		}
		if err := json.Unmarshal(idxBytes, &idx); err != nil || idx.Files == 0 {
			t.Fatalf("expected written draft files in drafts/index.json, err=%v files=%d", err, idx.Files)
		}
	})

	t.Run("completely_empty_dir_returns_error", func(t *testing.T) {
		root := t.TempDir()
		const host = "empty.example.com"
		if err := os.MkdirAll(filepath.Join(root, targetDir(host), "anon"), 0o700); err != nil {
			t.Fatal(err)
		}
		dest1 := filepath.Join(root, "empty-all")
		if err := runExport([]string{"-o", root, "-target", host, "-format", "all", "-dest", dest1}); err == nil {
			t.Fatalf("expected error on completely empty dir with -format all, got nil")
		}
		if _, err := os.Stat(filepath.Join(dest1, "openapi.json")); !os.IsNotExist(err) {
			t.Errorf("openapi.json should not be created for empty dir")
		}

		dest2 := filepath.Join(root, "empty-all-drafts")
		if err := runExport([]string{"-o", root, "-target", host, "-format", "all", "-drafts", "-dest", dest2}); err == nil {
			t.Fatalf("expected error on completely empty dir with -format all -drafts, got nil")
		}

		// Also verify a dir with requests.jsonl (0 API flows) and 0 static endpoints returns error.
		makeHTTPOnlyDir(t, root, "noflows.example.com", false)
		dest3 := filepath.Join(root, "noflows-all")
		if err := runExport([]string{"-o", root, "-target", "noflows.example.com", "-format", "all", "-dest", dest3}); err == nil {
			t.Fatalf("expected error when both live flows and static catalog are empty, got nil")
		}
	})
}
