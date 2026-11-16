package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestVerifyExtractsPreAuthSSOFlows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/portal/bootstrap":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sso_url":"https://sso.example.com/realms/portal/protocol/openid-connect/auth?client_id=portal-ui&response_type=code&redirect_uri=https%3A%2F%2Fadmin.example.com%2Fcb&scope=openid+profile"}`))
		case "/api/v1/portal/entry":
			w.Header().Set("Location", "https://acme.us.auth0.com/authorize?client_id=auth0-spa&response_type=code&redirect_uri=https://admin.example.com/cb")
			w.WriteHeader(http.StatusFound)
		case "/api/v1/auth/sso-url":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"url":"https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize?client_id=entra-spa&response_type=code&redirect_uri=https://admin.example.com/cb"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found"}`))
		}
	}))
	defer srv.Close()

	in := Inputs{
		InScope: func(string) bool { return true },
		Intel:   endpoints.Intel{Bases: []string{srv.URL}},
		Catalog: []endpoints.Endpoint{
			{Method: "GET", Path: "/api/v1/portal/bootstrap", Confidence: "code"},
			{Method: "GET", Path: "/api/v1/portal/entry", Confidence: "code"},
			{Method: "GET", Path: "/api/v1/auth/sso-url", Confidence: "code"},
		},
	}
	drafts := Drafts(in)
	dir := t.TempDir()
	sender, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		Max:          20,
		Log:          filepath.Join(dir, "sent.jsonl"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	rep, err := Run(context.Background(), Options{
		Target:  "127.0.0.1",
		Role:    "anon",
		Drafts:  drafts,
		Sender:  sender,
		Policy:  replay.Policy{AuthAllow: regexp.MustCompile("^" + regexp.QuoteMeta(srv.URL) + "/api/v1/auth/")},
		InScope: func(string) bool { return true },
		Dir:     dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(rep.Results))
	}
	r0 := rep.Results[0]
	if r0.Verdict != Alive || len(r0.AuthFlows) != 1 || r0.AuthFlows[0].Provider != "keycloak" || r0.AuthFlows[0].TenantID != "portal" || r0.AuthFlows[0].ClientID != "portal-ui" {
		t.Fatalf("result[0] = %+v", r0)
	}
	r1 := rep.Results[1]
	if r1.Verdict != Alive || len(r1.AuthFlows) != 1 || r1.AuthFlows[0].Provider != "auth0" || r1.AuthFlows[0].ClientID != "auth0-spa" {
		t.Fatalf("result[1] = %+v", r1)
	}
	r2 := rep.Results[2]
	if r2.Verdict != Alive || len(r2.AuthFlows) != 1 || r2.AuthFlows[0].Provider != "entra_id" || r2.AuthFlows[0].TenantID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("result[2] = %+v", r2)
	}
}

func TestVerifyCloudProbeDefaultAndOptOut(t *testing.T) {
	var mu sync.Mutex
	var cloudHits int
	var leakedCreds []string

	cloudSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cloudHits++
		for _, h := range []string{"Cookie", "Authorization", "X-Client-Secret"} {
			if v := r.Header.Get(h); v != "" {
				leakedCreds = append(leakedCreds, h+"="+v)
			}
		}
		mu.Unlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>portal-open</Name></ListBucketResult>`))
	}))
	defer cloudSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"err":"no_route"}`))
	}))
	defer apiSrv.Close()

	cloudURL, _ := url.Parse(cloudSrv.URL)
	rules, err := netsafe.ParseHostRules(fmt.Sprintf("MAP *.amazonaws.com %s", cloudURL.Host))
	if err != nil {
		t.Fatal(err)
	}

	roleDir := t.TempDir()
	verifyDir := filepath.Join(roleDir, "verify")
	intel := endpoints.Intel{
		Bases:   []string{apiSrv.URL},
		Headers: []endpoints.IntelHeader{{Name: "X-Client-Secret", Value: "static-app-secret"}},
		Cloud: []endpoints.IntelURL{
			{
				URL:     "http://portal-open.s3.ap-southeast-1.amazonaws.com/templates/data.xlsx",
				Sources: []endpoints.Source{{SHA256: "s1", Script: "https://admin.example.com/app.js", Kind: "string"}},
			},
		},
	}
	ib, _ := json.MarshalIndent(intel, "", "  ")
	if err := os.WriteFile(filepath.Join(roleDir, endpoints.IntelFile), ib, 0o600); err != nil {
		t.Fatal(err)
	}

	in := Inputs{
		InScope: func(string) bool { return true },
		Intel:   intel,
		Catalog: []endpoints.Endpoint{{Method: "GET", Path: "/api/v1/health", Confidence: "code"}},
	}
	drafts := Drafts(in)
	id := replay.NewIdentity("user", nil, []traffic.Entry{{
		URL:     apiSrv.URL + "/api/v1/health",
		Headers: map[string]string{"authorization": "Bearer secret-jwt-token", "cookie": "sid=secret-cookie"},
	}}, time.Now())

	// 1. With NoCloudProbe=true (-no-cloud-probe): 0 cloud hits.
	sOptOut, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		HostRules:    rules,
		Max:          20,
		Log:          filepath.Join(verifyDir, "optout.jsonl"),
	})
	if err != nil {
		t.Fatal(err)
	}
	repOptOut, err := Run(context.Background(), Options{
		Target:       "127.0.0.1",
		Role:         "anon",
		Drafts:       drafts,
		Cloud:        intel.Cloud,
		IntelDir:     roleDir,
		NoCloudProbe: true,
		Sender:       sOptOut,
		InScope:      func(string) bool { return true },
		Dir:          verifyDir,
	})
	sOptOut.Close()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if cloudHits != 0 || len(repOptOut.CloudChecks) != 0 {
		t.Fatalf("NoCloudProbe sent %d cloud requests, checks=%+v", cloudHits, repOptOut.CloudChecks)
	}
	mu.Unlock()

	// 2. With DryRun=true (-dry-run): 0 cloud hits.
	sDry, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		HostRules:    rules,
		DryRun:       true,
		Log:          filepath.Join(verifyDir, "dry.jsonl"),
	})
	if err != nil {
		t.Fatal(err)
	}
	repDry, err := Run(context.Background(), Options{
		Target:   "127.0.0.1",
		Role:     "anon",
		Drafts:   drafts,
		Cloud:    intel.Cloud,
		IntelDir: roleDir,
		Sender:   sDry,
		InScope:  func(string) bool { return true },
		Dir:      verifyDir,
	})
	sDry.Close()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if cloudHits != 0 || len(repDry.CloudChecks) != 0 {
		t.Fatalf("DryRun sent %d cloud requests, checks=%+v", cloudHits, repDry.CloudChecks)
	}
	mu.Unlock()

	// 3. Default verify run: probes cloud via Sender's HostRules, zero credential leak, records CloudChecks & updates intel.json!
	sLive, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		HostRules:    rules,
		Max:          20,
		Log:          filepath.Join(verifyDir, "live.jsonl"),
	})
	if err != nil {
		t.Fatal(err)
	}
	repLive, err := Run(context.Background(), Options{
		Target:   "127.0.0.1",
		Role:     "user",
		Identity: id,
		Drafts:   drafts,
		Cloud:    intel.Cloud,
		IntelDir: roleDir,
		Sender:   sLive,
		InScope:  func(string) bool { return true },
		Dir:      verifyDir,
	})
	sLive.Close()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(leakedCreds) > 0 {
		t.Fatalf("credentials leaked to cloud storage: %v", leakedCreds)
	}
	if cloudHits == 0 {
		t.Fatal("expected cloud probe requests on default verify run")
	}
	mu.Unlock()

	if len(repLive.CloudChecks) != 1 || repLive.CloudChecks[0].Status != "public_listable" {
		t.Fatalf("CloudChecks = %+v, want 1 public_listable", repLive.CloudChecks)
	}
	var updated endpoints.Intel
	ub, err := os.ReadFile(filepath.Join(roleDir, endpoints.IntelFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ub, &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Cloud) != 1 || updated.Cloud[0].Status != "public_listable" || updated.Cloud[0].Bucket != "portal-open" {
		t.Fatalf("updated intel.json cloud = %+v", updated.Cloud)
	}
}

