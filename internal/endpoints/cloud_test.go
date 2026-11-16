package endpoints

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

func TestParseCloudURLAllProviders(t *testing.T) {
	cases := []struct {
		raw       string
		provider  string
		bucket    string
		region    string
		objectKey string
		rootURL   string
	}{
		{
			raw:       "https://portal-assets.s3.ap-southeast-1.amazonaws.com/templates/import.xlsx",
			provider:  "aws_s3",
			bucket:    "portal-assets",
			region:    "ap-southeast-1",
			objectKey: "templates/import.xlsx",
			rootURL:   "https://portal-assets.s3.ap-southeast-1.amazonaws.com",
		},
		{
			raw:       "https://portal-assets.s3.amazonaws.com/logo.png",
			provider:  "aws_s3",
			bucket:    "portal-assets",
			region:    "",
			objectKey: "logo.png",
			rootURL:   "https://portal-assets.s3.amazonaws.com",
		},
		{
			raw:       "https://my.dotted.bucket.s3-us-west-2.amazonaws.com/a/b/c.json",
			provider:  "aws_s3",
			bucket:    "my.dotted.bucket",
			region:    "us-west-2",
			objectKey: "a/b/c.json",
			rootURL:   "https://my.dotted.bucket.s3-us-west-2.amazonaws.com",
		},
		{
			raw:       "https://s3.ap-southeast-1.amazonaws.com/portal-assets/dir/file.csv",
			provider:  "aws_s3",
			bucket:    "portal-assets",
			region:    "ap-southeast-1",
			objectKey: "dir/file.csv",
			rootURL:   "https://s3.ap-southeast-1.amazonaws.com/portal-assets",
		},
		{
			raw:       "https://s3.amazonaws.com/portal-assets/",
			provider:  "aws_s3",
			bucket:    "portal-assets",
			region:    "",
			objectKey: "",
			rootURL:   "https://s3.amazonaws.com/portal-assets",
		},
		{
			raw:       "//portal-assets.s3.eu-central-1.amazonaws.com/static/app.png",
			provider:  "aws_s3",
			bucket:    "portal-assets",
			region:    "eu-central-1",
			objectKey: "static/app.png",
			rootURL:   "https://portal-assets.s3.eu-central-1.amazonaws.com",
		},
		{
			raw:       "https://storage.googleapis.com/media-bucket/images/hero.webp",
			provider:  "gcs",
			bucket:    "media-bucket",
			region:    "",
			objectKey: "images/hero.webp",
			rootURL:   "https://storage.googleapis.com/media-bucket",
		},
		{
			raw:       "https://media-bucket.storage.googleapis.com/images/hero.webp",
			provider:  "gcs",
			bucket:    "media-bucket",
			region:    "",
			objectKey: "images/hero.webp",
			rootURL:   "https://media-bucket.storage.googleapis.com",
		},
		{
			raw:       "https://firebasestorage.googleapis.com/v0/b/app-prod.appspot.com/o/avatars%2Fuser1.png?alt=media",
			provider:  "firebase",
			bucket:    "app-prod.appspot.com",
			region:    "",
			objectKey: "avatars/user1.png",
			rootURL:   "https://firebasestorage.googleapis.com/v0/b/app-prod.appspot.com/o",
		},
		{
			raw:       "https://corpstore.blob.core.windows.net/exports/2026/report.pdf",
			provider:  "azure_blob",
			bucket:    "exports",
			region:    "",
			objectKey: "2026/report.pdf",
			rootURL:   "https://corpstore.blob.core.windows.net/exports",
		},
		{
			raw:       "https://cdn-files.sgp1.digitaloceanspaces.com/releases/v1.zip",
			provider:  "digitalocean_spaces",
			bucket:    "cdn-files",
			region:    "sgp1",
			objectKey: "releases/v1.zip",
			rootURL:   "https://cdn-files.sgp1.digitaloceanspaces.com",
		},
		{
			raw:       "https://acct123456.r2.cloudflarestorage.com/builds/latest.tar.gz",
			provider:  "cloudflare_r2",
			bucket:    "builds",
			region:    "",
			objectKey: "latest.tar.gz",
			rootURL:   "https://acct123456.r2.cloudflarestorage.com/builds",
		},
		{
			raw:       "https://pub-998877665544.r2.dev/docs/manual.pdf",
			provider:  "cloudflare_r2",
			bucket:    "pub-998877665544",
			region:    "",
			objectKey: "docs/manual.pdf",
			rootURL:   "https://pub-998877665544.r2.dev",
		},
		{
			raw:       "https://corp-static.oss-ap-southeast-1.aliyuncs.com/bundles/vendor.js",
			provider:  "alibaba_oss",
			bucket:    "corp-static",
			region:    "ap-southeast-1",
			objectKey: "bundles/vendor.js",
			rootURL:   "https://corp-static.oss-ap-southeast-1.aliyuncs.com",
		},
		{
			raw:       "https://backups-prod.s3.us-west-004.backblazeb2.com/db/schema.sql",
			provider:  "backblaze_b2",
			bucket:    "backups-prod",
			region:    "us-west-004",
			objectKey: "db/schema.sql",
			rootURL:   "https://backups-prod.s3.us-west-004.backblazeb2.com",
		},
		{
			raw:       "https://archive-data.s3.eu-central-1.wasabisys.com/logs/2026.gz",
			provider:  "wasabi",
			bucket:    "archive-data",
			region:    "eu-central-1",
			objectKey: "logs/2026.gz",
			rootURL:   "https://archive-data.s3.eu-central-1.wasabisys.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			p, b, r, k, root, ok := ParseCloudURL(tc.raw)
			if !ok {
				t.Fatalf("ParseCloudURL(%q) = ok=false, want true", tc.raw)
			}
			if p != tc.provider || b != tc.bucket || r != tc.region || k != tc.objectKey || root != tc.rootURL {
				t.Fatalf("got (%q, %q, %q, %q, %q), want (%q, %q, %q, %q, %q)",
					p, b, r, k, root, tc.provider, tc.bucket, tc.region, tc.objectKey, tc.rootURL)
			}
		})
	}

	for _, bad := range []string{
		"https://admin.example.com/api/v1/users",
		"https://s3.amazonaws.com/",
		"https://storage.googleapis.com/",
		"not-a-url",
	} {
		if _, _, _, _, _, ok := ParseCloudURL(bad); ok {
			t.Fatalf("ParseCloudURL(%q) expected false", bad)
		}
	}
}

func TestBuildIntelPopulatesCloudMetadata(t *testing.T) {
	scripts := []Script{
		{
			SHA256: "abc123",
			URLs:   []string{"https://cdn.example.net/assets/app.js"},
			Result: jsapi.Result{
				Cloud: []string{"https://s3.ap-southeast-1.amazonaws.com/portal-docs/guide.pdf"},
			},
		},
	}
	in := BuildIntel(scripts, func(h string) bool { return h == "admin.example.com" })
	if len(in.Cloud) != 1 {
		t.Fatalf("got %d cloud entries, want 1", len(in.Cloud))
	}
	c := in.Cloud[0]
	if c.Provider != "aws_s3" || c.Bucket != "portal-docs" || c.Region != "ap-southeast-1" ||
		c.ObjectKey != "guide.pdf" || c.BucketRootURL != "https://s3.ap-southeast-1.amazonaws.com/portal-docs" || c.Status != "" {
		t.Fatalf("unexpected cloud entry: %+v", c)
	}
}

func TestProbeCloudClassificationsAndSafety(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	var encHeaders []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method+" "+r.Host+r.URL.Path)
		encHeaders = append(encHeaders, r.Header.Get("Accept-Encoding"))
		mu.Unlock()
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected credential header on cloud request: %v", r.Header)
		}

		switch r.Host {
		case "listable.s3.us-east-1.amazonaws.com":
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>listable</Name></ListBucketResult>` + strings.Repeat("X", 16384)))
		case "pubobj.s3.us-east-1.amazonaws.com":
			if r.Method == http.MethodHead && r.URL.Path == "/public.png" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
		case "priv.s3.us-east-1.amazonaws.com":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
		case "notfound.s3.us-east-1.amazonaws.com":
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
		case "missing.s3.us-east-1.amazonaws.com":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`))
		case "corp.blob.core.windows.net":
			if r.URL.Path == "/open-container" && r.URL.Query().Get("comp") == "list" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<EnumerationResults ContainerName="open-container"></EnumerationResults>`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>ContainerNotFound</Code></Error>`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()

	srvURL, _ := url.Parse(srv.URL)
	rules, err := netsafe.ParseHostRules(fmt.Sprintf("MAP *.amazonaws.com %s, MAP *.windows.net %s", srvURL.Host, srvURL.Host))
	if err != nil {
		t.Fatal(err)
	}

	inputs := []IntelURL{
		{URL: "http://listable.s3.us-east-1.amazonaws.com/doc.pdf"},
		{URL: "http://pubobj.s3.us-east-1.amazonaws.com/public.png"},
		{URL: "http://priv.s3.us-east-1.amazonaws.com/"},
		{URL: "http://notfound.s3.us-east-1.amazonaws.com/gone.png"},
		{URL: "http://missing.s3.us-east-1.amazonaws.com/any.png"},
		{URL: "http://corp.blob.core.windows.net/open-container"},
	}

	got, checks := ProbeCloud(context.Background(), inputs, CloudProbeOptions{
		HostRules:    rules,
		AllowPrivate: false,
	})
	if len(got) != len(inputs) || len(checks) != len(inputs) {
		t.Fatalf("got=%d checks=%d, want %d", len(got), len(checks), len(inputs))
	}

	wantStatus := []string{
		"public_listable",
		"public_object",
		"bucket_exists_private",
		"object_not_found",
		"bucket_missing",
		"public_listable",
	}
	for i, w := range wantStatus {
		if got[i].Status != w || checks[i].Status != w {
			t.Fatalf("item %d (%s): got status=%q check=%q, want %q", i, inputs[i].URL, got[i].Status, checks[i].Status, w)
		}
	}

	mu.Lock()
	for _, enc := range encHeaders {
		if enc != "identity" {
			t.Fatalf("Accept-Encoding = %q, want identity", enc)
		}
	}
	// Verify priv.s3.us-east-1.amazonaws.com/ (ObjectKey == "") did NOT get a HEAD request.
	for _, m := range methods {
		if strings.HasPrefix(m, "HEAD priv.s3.") {
			t.Fatalf("unexpected HEAD when ObjectKey is empty: %s", m)
		}
	}
	mu.Unlock()
}

func TestProbeCloudSSRFGuardProxyAndCap(t *testing.T) {
	// 1. Without HostRules and AllowPrivate=false, DNS resolving to 127.0.0.1 is refused by netsafe.
	hit := false
	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer localSrv.Close()

	rebindResolver := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	_, checks := ProbeCloud(context.Background(), []IntelURL{
		{URL: "http://rebind-bucket.s3.amazonaws.com/key.txt"},
	}, CloudProbeOptions{
		AllowPrivate: false,
		Resolver:     rebindResolver,
	})
	if hit {
		t.Fatal("SSRF guard failed: private/loopback address was dialed on public run")
	}
	if len(checks) != 1 || checks[0].Status != "" || checks[0].Error == "" {
		t.Fatalf("expected refused check with error, got %+v", checks)
	}

	// 2. Through an HTTP proxy, all requests traverse the proxy and cap at MaxCloudTargets (10).
	var proxyHits int
	var pmu sync.Mutex
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pmu.Lock()
		proxyHits++
		pmu.Unlock()
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
	}))
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)

	var twelve []IntelURL
	for i := range 12 {
		twelve = append(twelve, IntelURL{URL: fmt.Sprintf("http://b%02d.s3.us-east-1.amazonaws.com/", i)})
	}
	probed, pchecks := ProbeCloud(context.Background(), twelve, CloudProbeOptions{
		Proxy:        proxyURL,
		AllowPrivate: false,
	})
	if len(pchecks) != MaxCloudTargets {
		t.Fatalf("checks = %d, want MaxCloudTargets (%d)", len(pchecks), MaxCloudTargets)
	}
	for i := range 12 {
		if i < MaxCloudTargets && probed[i].Status != "bucket_exists_private" {
			t.Fatalf("probed[%d].Status = %q, want bucket_exists_private", i, probed[i].Status)
		}
		if i >= MaxCloudTargets && probed[i].Status != "" {
			t.Fatalf("probed[%d].Status = %q, want empty past cap", i, probed[i].Status)
		}
	}
	pmu.Lock()
	if proxyHits != MaxCloudTargets {
		t.Fatalf("proxyHits = %d, want %d", proxyHits, MaxCloudTargets)
	}
	pmu.Unlock()
}
