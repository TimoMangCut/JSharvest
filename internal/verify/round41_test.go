package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestRound41CloudProbeRespectsRateBudgetAndLogsSent(t *testing.T) {
	var mu sync.Mutex
	var reqTimes []time.Time
	cloudSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqTimes = append(reqTimes, time.Now())
		mu.Unlock()
		h, _, _ := strings.Cut(r.Host, ":")
		switch h {
		case "priv-bucket.s3.amazonaws.com":
			// 403 AccessDenied must still classify as bucket_exists_private (NOT WAF block!).
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>secret_key=cloud_leak_999</Message></Error>`))
		case "second-bucket.s3.amazonaws.com":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><ListBucketResult><Name>second-bucket</Name></ListBucketResult>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cloudSrv.Close()

	cu, err := url.Parse(cloudSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Map synthetic S3 hosts to our local TLS server's IP, and rewrite port via Proxy?
	// Wait: S3 URLs on custom port https://priv-bucket.s3.amazonaws.com:<port>/key parse cleanly in ParseCloudURL!
	port := cu.Port()
	rules, err := netsafe.ParseHostRules("MAP *.s3.amazonaws.com 127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	cloud := []endpoints.IntelURL{
		{URL: "https://priv-bucket.s3.amazonaws.com:" + port + "/doc.pdf?access_token=cloud_query_tok_123"},
		{URL: "https://second-bucket.s3.amazonaws.com:" + port + "/other.pdf"},
	}

	// Case 1: -max 2 allows target 1's GET root + HEAD object (2 requests), then halts before target 2!
	// Rate = 80ms means request 2 cannot even start until >= 80ms after request 1 starts.
	dir := t.TempDir()
	sentPath := filepath.Join(dir, "sent.jsonl")
	sender, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		HostRules:    rules,
		Insecure:     true,
		Rate:         80 * time.Millisecond,
		Max:          2,
		Log:          sentPath,
		Redactor:     traffic.NewRedactor(),
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rep, err := Run(context.Background(), Options{
		Target:  "app.example",
		Role:    "anon",
		Cloud:   cloud,
		Sender:  sender,
		InScope: func(string) bool { return true },
		Dir:     dir,
	})
	if err := sender.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	gotHits := append([]time.Time(nil), reqTimes...)
	mu.Unlock()
	if len(gotHits) != 2 {
		t.Fatalf("expected -max 2 to stop after 2 cloud requests, got %d hits", len(gotHits))
	}
	if elapsed := gotHits[1].Sub(start); elapsed < 75*time.Millisecond {
		t.Fatalf("expected 2nd cloud request paced by 80ms rate, arrived after %v", elapsed)
	}
	if rep.Sent != 2 {
		t.Fatalf("rep.Sent = %d, want 2", rep.Sent)
	}
	if !strings.Contains(rep.Stopped, "budget") {
		t.Fatalf("expected rep.Stopped to note budget exhaustion, got %q", rep.Stopped)
	}
	if len(rep.CloudChecks) != 1 || rep.CloudChecks[0].Status != endpoints.CloudBucketPrivate {
		t.Fatalf("expected 1st bucket classified as %q, got %+v", endpoints.CloudBucketPrivate, rep.CloudChecks)
	}

	// Verify sent.jsonl has 2 lines matching rep.Sent, Purpose == "cloud", and Redactor scrubbed query + body secrets.
	rawSent, err := os.ReadFile(sentPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(rawSent)), "\n")
	if len(lines) != rep.Sent {
		t.Fatalf("sent.jsonl has %d lines, want rep.Sent=%d:\n%s", len(lines), rep.Sent, string(rawSent))
	}
	for i, ln := range lines {
		var s replay.Sent
		if err := json.Unmarshal([]byte(ln), &s); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
		if s.Purpose != "cloud" {
			t.Fatalf("line %d Purpose = %q, want cloud", i, s.Purpose)
		}
	}
	if strings.Contains(string(rawSent), "cloud_query_tok_123") || strings.Contains(string(rawSent), "cloud_leak_999") {
		t.Fatalf("sent.jsonl leaked cloud query/body secret:\n%s", string(rawSent))
	}
}

func TestRound41VerifyScrubsReasonsAndRedirectLocations(t *testing.T) {
	const tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sigabcdef123456"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/secret-redir"):
			w.Header().Set("Location", "https://idp.example.test/cb?access_token="+tok)
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	sender, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		Max:          20,
		Log:          filepath.Join(dir, "sent.jsonl"),
		Redactor:     traffic.NewRedactor(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	rep, err := Run(context.Background(), Options{
		Target:  "app.example.test",
		Role:    "anon",
		Sender:  sender,
		InScope: func(string) bool { return true },
		Dir:     dir,
		Drafts: []Draft{{
			ID:         "d1",
			Source:     "static",
			Method:     "GET",
			Path:       "/api/secret-redir",
			Confidence: "call",
			Tier:       "tier1",
			URL:        srv.URL + "/api/secret-redir",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, rep); err != nil {
		t.Fatal(err)
	}
	for _, fname := range []string{"verify.json", "verify.md"} {
		raw, err := os.ReadFile(filepath.Join(dir, fname))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), tok) {
			t.Fatalf("%s leaked redirect access_token:\n%s", fname, string(raw))
		}
	}
}

func TestRound41DoExternalCancelWhileRateLimitedDoesNotCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	sentPath := filepath.Join(dir, "sent.jsonl")
	sender, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		Rate:         500 * time.Millisecond,
		Max:          2,
		Log:          sentPath,
		Redactor:     traffic.NewRedactor(),
	})
	if err != nil {
		t.Fatal(err)
	}

	req1, _ := http.NewRequest("GET", srv.URL+"/one", nil)
	resp1, err := sender.DoExternal(context.Background(), srv.Client(), req1, "cloud", "https://admin:p%40ss@example.test/one")
	if err != nil {
		t.Fatalf("req1 failed: %v", err)
	}
	_ = resp1.Body.Close()

	// Request 2 cancels while waiting on 500ms rate limit; must NOT increment s.n or write sent.jsonl.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	req2, _ := http.NewRequest("GET", srv.URL+"/two", nil)
	if resp2, err := sender.DoExternal(ctx2, srv.Client(), req2, "cloud", "https://example.test/two"); err == nil {
		_ = resp2.Body.Close()
		t.Fatal("expected req2 to fail on context deadline while rate limited")
	}

	// Request 3 must still succeed within Max=2!
	req3, _ := http.NewRequest("GET", srv.URL+"/three", nil)
	resp3, err := sender.DoExternal(context.Background(), srv.Client(), req3, "cloud", "https://example.test/three")
	if err != nil {
		t.Fatalf("req3 failed after canceled req2: %v", err)
	}
	_ = resp3.Body.Close()

	if sender.Count() != 2 {
		t.Fatalf("sender.Count() = %d, want 2", sender.Count())
	}
	if err := sender.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(sentPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("sent.jsonl has %d lines, want 2:\n%s", len(lines), string(raw))
	}
	for i, ln := range lines {
		var s replay.Sent
		if err := json.Unmarshal([]byte(ln), &s); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
		if s.N != i+1 {
			t.Fatalf("line %d N = %d, want %d", i, s.N, i+1)
		}
	}
	if strings.Contains(string(raw), "p%40ss") || strings.Contains(string(raw), "p@ss") {
		t.Fatalf("sent.jsonl leaked Sent.Item userinfo password:\n%s", string(raw))
	}
}
