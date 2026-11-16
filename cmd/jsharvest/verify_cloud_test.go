package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/verify"
)

func TestRunVerifyCloudProbeFlag(t *testing.T) {
	var cloudHits atomic.Int32
	cloudSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cloudHits.Add(1)
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>cli-bucket</Name></ListBucketResult>`))
		}
	}))
	defer cloudSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/ping" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"pong":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"err":"404"}`))
	}))
	defer apiSrv.Close()

	cloudURL, _ := url.Parse(cloudSrv.URL)
	apiURL, _ := url.Parse(apiSrv.URL)
	rules := fmt.Sprintf("MAP *.amazonaws.com %s", cloudURL.Host)

	setupOut := func() (outRoot, roleDir string) {
		outRoot = t.TempDir()
		roleDir = filepath.Join(outRoot, targetDir(apiURL.Host), "anon")
		if err := os.MkdirAll(roleDir, 0o700); err != nil {
			t.Fatal(err)
		}
		epLine := fmt.Sprintf("{\"method\":\"GET\",\"host\":%q,\"path\":\"/api/v1/ping\",\"status\":\"static\",\"kind\":\"fetch\",\"confidence\":\"code\"}\n", apiURL.Host)
		if err := os.WriteFile(filepath.Join(roleDir, endpoints.File), []byte(epLine), 0o600); err != nil {
			t.Fatal(err)
		}
		intel := endpoints.Intel{
			Bases: []string{apiSrv.URL},
			Cloud: []endpoints.IntelURL{{URL: "http://cli-bucket.s3.us-east-1.amazonaws.com/sample.txt"}},
		}
		ib, _ := json.MarshalIndent(intel, "", "  ")
		if err := os.WriteFile(filepath.Join(roleDir, endpoints.IntelFile), ib, 0o600); err != nil {
			t.Fatal(err)
		}
		return outRoot, roleDir
	}

	// 1. -no-cloud-probe skips cloud probing completely.
	out1, _ := setupOut()
	if err := runVerify([]string{"-o", out1, "-target", apiURL.Host, "-scope", "fqdn", "-rate", "50", "-proxy", "none", "-host-resolver-rules", rules, "-no-cloud-probe"}); err != nil {
		t.Fatalf("runVerify -no-cloud-probe: %v", err)
	}
	if n := cloudHits.Load(); n != 0 {
		t.Fatalf("expected 0 cloud hits with -no-cloud-probe, got %d", n)
	}

	// 2. Default verify probes cloud, populates verify.json cloud_checks, and updates intel.json.
	out2, roleDir2 := setupOut()
	if err := runVerify([]string{"-o", out2, "-target", apiURL.Host, "-scope", "fqdn", "-rate", "50", "-proxy", "none", "-host-resolver-rules", rules}); err != nil {
		t.Fatalf("runVerify default: %v", err)
	}
	if cloudHits.Load() == 0 {
		t.Fatal("expected cloud hits on default runVerify")
	}
	vb, err := os.ReadFile(filepath.Join(roleDir2, "verify", "verify.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep verify.Report
	if err := json.Unmarshal(vb, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.CloudChecks) != 1 || rep.CloudChecks[0].Status != "public_listable" {
		t.Fatalf("verify.json cloud_checks = %+v", rep.CloudChecks)
	}
	ib, err := os.ReadFile(filepath.Join(roleDir2, endpoints.IntelFile))
	if err != nil {
		t.Fatal(err)
	}
	var updated endpoints.Intel
	if err := json.Unmarshal(ib, &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Cloud) != 1 || updated.Cloud[0].Status != "public_listable" {
		t.Fatalf("intel.json cloud = %+v", updated.Cloud)
	}
}
