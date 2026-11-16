package endpoints

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

func TestIsTrackerHost(t *testing.T) {
	trackers := []string{
		"www.google-analytics.com",
		"googletagmanager.com",
		"www.googletagmanager.com:443",
		"analytics.google.com",
		"stats.g.doubleclick.net",
		"connect.facebook.net",
		"www.facebook.com",
		"static.hotjar.com",
		"www.clarity.ms",
		"widget.intercom.io",
		"cdn.segment.com",
		"api.segment.io",
		"api-js.mixpanel.com",
		"cdn.amplitude.com",
		"edge.fullstory.com",
		"www.datadoghq-browser-agent.com",
		"js-agent.newrelic.com",
		"bam.nr-data.net",
		"analytics.tiktok.com",
		"tr.snapchat.com",
		"px.ads.linkedin.com",
		"bat.bing.com",
		"mc.yandex.ru",
		"hm.baidu.com",
	}
	for _, h := range trackers {
		if !IsTrackerHost(h) {
			t.Errorf("IsTrackerHost(%q) = false, want true", h)
		}
	}

	nonTrackers := []string{
		"admin.example.com",
		"d111111abcdef8.cloudfront.net",
		"static.corp-assets.net",
		"corp-bucket.s3.ap-southeast-1.amazonaws.com",
		"storage.googleapis.com",
		"notgoogle-analytics.com",
	}
	for _, h := range nonTrackers {
		if IsTrackerHost(h) {
			t.Errorf("IsTrackerHost(%q) = true, want false", h)
		}
	}
}

func TestAppReferencedCDNScopeAndIntelRoutes(t *testing.T) {
	const gmapsKey = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
	const trackerKey = "AIzaSyZ9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J"

	// Inline bootstrap on the target HTML origin (no bases of its own).
	inlineBoot := Script{
		SHA256: "boot",
		URLs:   []string{"https://admin.example.com/"},
		Result: jsapi.Extract([]byte(`window.__APP_READY__ = true;`)),
	}

	// App's own chunks hosted on a separate CloudFront asset domain (tagged third-party by RDN scope).
	cdnSharedSrc := `
export function epFor(seg) { return ` + "`/records/${seg}`" + `; }
const sharedApi = axios.create({ baseURL: "/api-gateway" });
export function fetchUsers(params) {
	return sharedApi.get("/users", { params });
}
`
	cdnAppSrc := `
import { epFor, fetchUsers } from "./shared.js";
const client = axios.create({
	baseURL: "/api-gateway",
	headers: { "X-Client-Id": "PORTAL_WEB" },
});
const loader = new Loader({ key: "` + gmapsKey + `" });
const tpl = "https://portal-templates.s3.ap-southeast-1.amazonaws.com/import.xlsx";
fetchUsers({ page: 1 });
client.delete(` + "`${epFor(\"devices\")}/${id}`" + `);
const router = createRouter({
	routes: [
		{
			path: "/ota",
			component: OtaShell,
			redirect: "/ota/release-package",
			children: [
				{ path: "release-package", component: ReleasePkg, meta: { authRequired: true, roles: ["ADMIN"], permission: "ota:read" } },
				{ path: "public-notes", component: Notes, meta: { public: true } },
			],
		},
	],
});
`
	cdnShared := Script{
		SHA256:     "cdn1",
		URLs:       []string{"https://d111111abcdef8.cloudfront.net/assets/shared.js"},
		ThirdParty: true,
		Load:       func() []byte { return []byte(cdnSharedSrc) },
		Result:     jsapi.Extract([]byte(cdnSharedSrc)),
	}
	cdnApp := Script{
		SHA256:     "cdn2",
		URLs:       []string{"https://d111111abcdef8.cloudfront.net/assets/app.js"},
		ThirdParty: true,
		Load:       func() []byte { return []byte(cdnAppSrc) },
		Result:     jsapi.Extract([]byte(cdnAppSrc)),
	}

	// Genuine third-party tracker script on googletagmanager.com: MUST still be excluded!
	gtmScript := Script{
		SHA256:     "gtm",
		URLs:       []string{"https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"},
		ThirdParty: true,
		Result: jsapi.Extract([]byte(`
			axios.create({ baseURL: "https://www.google-analytics.com/g", headers: { "X-Tracker-Header": "GA1" } });
			const k = { key: "` + trackerKey + `" };
			const fakeRoutes = [{ path: "/gtm-internal-route", component: X }];
		`)),
	}

	inScope := func(h string) bool {
		return h == "example.com" || strings.HasSuffix(h, ".example.com")
	}

	scripts := []Script{inlineBoot, cdnShared, cdnApp, gtmScript}
	intel := BuildIntel(scripts, inScope)

	// 1. App CDN script's bases, headers, keys, cloud, and routes are kept; GTM tracker's are excluded.
	if !slices.Contains(intel.Bases, "/api-gateway") {
		t.Errorf("expected /api-gateway in Intel.Bases, got %v", intel.Bases)
	}
	if len(intel.Headers) != 1 || intel.Headers[0].Name != "X-Client-Id" || intel.Headers[0].Value != "PORTAL_WEB" {
		t.Errorf("Intel.Headers = %+v, want only X-Client-Id=PORTAL_WEB (no tracker header)", intel.Headers)
	}
	if len(intel.Keys) != 1 || intel.Keys[0].Value != gmapsKey {
		t.Errorf("Intel.Keys = %+v, want only %s (no tracker key)", intel.Keys, gmapsKey)
	}
	if len(intel.Cloud) != 1 || !strings.Contains(intel.Cloud[0].URL, "portal-templates.s3.ap-southeast-1.amazonaws.com") {
		t.Errorf("Intel.Cloud = %+v, want portal-templates S3 URL", intel.Cloud)
	}

	routesByPath := map[string]IntelRoute{}
	for _, r := range intel.Routes {
		routesByPath[r.Path] = r
	}
	if _, bad := routesByPath["/gtm-internal-route"]; bad {
		t.Errorf("tracker script route leaked into Intel.Routes: %+v", intel.Routes)
	}
	if ota, ok := routesByPath["/ota"]; !ok || ota.Redirect != "/ota/release-package" {
		t.Errorf("missing or incomplete /ota in Intel.Routes: %+v", intel.Routes)
	}
	if rp, ok := routesByPath["/ota/release-package"]; !ok || rp.AuthRequired == nil || !*rp.AuthRequired ||
		!slices.Equal(rp.Roles, []string{"ADMIN"}) || !slices.Equal(rp.Permissions, []string{"ota:read"}) || len(rp.Sources) == 0 {
		t.Errorf("/ota/release-package in Intel.Routes = %+v", rp)
	}
	if pub, ok := routesByPath["/ota/public-notes"]; !ok || pub.AuthRequired == nil || *pub.AuthRequired != false {
		t.Errorf("/ota/public-notes in Intel.Routes = %+v, want AuthRequired=false", pub)
	}

	// 2. Cross-chunk module linking (both ESM import wrapper `fetchUsers` AND `linkDeferred` `epFor`) works across CDN chunks!
	eps := Build(scripts, nil, inScope)
	epMap := byPath(eps)
	if u, ok := epMap["GET /api-gateway/users"]; !ok || u.ThirdParty || !slices.Equal(u.Query, []string{"page"}) {
		t.Errorf("CDN cross-chunk import GET /api-gateway/users = %+v (all: %+v)", u, epMap)
	}
	if d, ok := epMap["DELETE /api-gateway/records/devices/{}"]; !ok || d.ThirdParty {
		t.Errorf("CDN cross-chunk deferred builder DELETE /api-gateway/records/devices/{} = %+v (all: %+v)", d, epMap)
	}

	// 3. SaveIntel writes intel.json even when Routes is the ONLY populated section, and enrichIntelBases resolves /api-gateway against https://admin.example.com.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "js"), 0o700); err != nil {
		t.Fatal(err)
	}
	routesOnlyCode := []byte(`const router = createRouter({ routes: [{ path: "/only-route", component: R }] });`)
	sum := sha256.Sum256(routesOnlyCode)
	sha := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, "js", sha+".js"), routesOnlyCode, 0o600); err != nil {
		t.Fatal(err)
	}
	ent, _ := json.Marshal(store.Entry{SHA256: sha, URLs: []string{"https://admin.example.com/app.js"}})
	if err := os.WriteFile(filepath.Join(dir, "index.jsonl"), append(ent, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Analyze(dir, 1); err != nil {
		t.Fatal(err)
	}
	saved, err := SaveIntel(dir, inScope, nil)
	if err != nil {
		t.Fatalf("SaveIntel failed: %v", err)
	}
	if len(saved.Routes) != 1 || saved.Routes[0].Path != "/only-route" {
		t.Fatalf("SaveIntel routes = %+v, want [/only-route]", saved.Routes)
	}
	if _, err := os.Stat(filepath.Join(dir, IntelFile)); err != nil {
		t.Fatalf("intel.json was not written when only Routes was non-empty: %v", err)
	}

	enriched := enrichIntelBases(t.TempDir(), scripts, intel.Bases, inScope)
	if !slices.Contains(enriched, "https://admin.example.com/api-gateway") {
		t.Errorf("enrichIntelBases = %v, want https://admin.example.com/api-gateway", enriched)
	}
}
