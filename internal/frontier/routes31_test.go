package frontier

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func TestFromScriptDiscoversNestedStaticRoutesOnly(t *testing.T) {
	src := `
const router = createRouter({
	routes: [
		{
			path: "/ota",
			component: OtaLayout,
			children: [
				{ path: "release-package", component: ReleasePkg },
				{ path: "ecu/:id/edit", component: EcuEdit },
				{ path: "*", redirect: "/ota/release-package" },
			],
		},
	],
});
`
	res := jsapi.Extract([]byte(src))
	base, _ := url.Parse("https://admin.example.com/")
	found := keys(FromScript(res, base, false))

	if !slices.Contains(found, "route visit https://admin.example.com/ota") {
		t.Errorf("missing /ota in frontier FromScript: %v", found)
	}
	if !slices.Contains(found, "route visit https://admin.example.com/ota/release-package") {
		t.Errorf("missing nested /ota/release-package in frontier FromScript: %v", found)
	}
	for _, f := range found {
		if f == "route visit https://admin.example.com/ota/ecu/:id/edit" || f == "route visit https://admin.example.com/ota/*" {
			t.Errorf("template/wildcard route leaked into frontier visit list: %s", f)
		}
	}
}

func TestSpecCollectorFiltersUIPropBasesAndSPARoutes(t *testing.T) {
	src := `
const router = createRouter({
	routes: [
		{ path: "/api-error-log/home", component: ErrView },
		{ path: "/audit-log/home", component: AuditView },
		{ path: "/banner-management/home", component: BannerView },
		{ path: "/dashboard", component: DashView },
	],
});
const navMenu = [
	{ title: "Errors", url: "/api-error-log/home" },
	{ title: "Audit", url: "/audit-log/home" },
	{ title: "Banners", url: "/banner-management/home" },
	{ title: "Dash", href: "/dashboard" },
	{ p: "/editor-assets" },
	{ CSV_TEMPLATE_URL: "https://files.example.com/templates/sample.csv" },
	{ CHART: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart" },
	{ AUTH_DOC: "https://schemas.microsoft.com/office/2014/relationships/chartEx" },
	{ docLink: "https://help.partner.example.com/guide" },
	{ baseServer: "/audit-log/home" },
	{ fallbackServer: "/gw-fallback" },
];
const client = axios.create({ baseURL: "/api-gateway" });
function load() {
	client.get("orders/v1/a");
	client.get("orders/v1/b");
	client.get("orders/v1/c");
	client.get("orders/v1/d");
	client.get("orders/v1/e");
	client.get("orders/v1/f");
	client.get("billing/v1/a");
	client.get("billing/v1/b");
	client.get("billing/v1/c");
	client.get("billing/v1/d");
	client.get("billing/v1/e");
	client.get("inventory/v1/a");
	client.get("inventory/v1/b");
	client.get("inventory/v1/c");
	client.get("inventory/v1/d");
	client.get("reports/v1/a");
	client.get("reports/v1/b");
	client.get("reports/v1/c");
	client.get("users/v1/a");
	client.get("users/v1/b");
	client.get("alerts/v1/feed");
}
`
	res := jsapi.Extract([]byte(src))
	if res.Error != "" {
		t.Fatalf("Extract error: %s", res.Error)
	}

	var sc SpecCollector
	sc.AddScript(res, "https://admin.example.com/", "https://admin.example.com/app.js")
	plan := sc.Plan("https://admin.example.com", func(h string) bool {
		return h == "admin.example.com" || strings.HasSuffix(h, ".example.com")
	})

	for _, b := range plan.Bases {
		if strings.Contains(b, "/home") || strings.Contains(b, "/dashboard") || strings.Contains(b, "/editor-assets") {
			t.Fatalf("UI/SPA route leaked into SpecCollector Bases: %v", plan.Bases)
		}
	}
	wantBases := []string{
		"https://admin.example.com/api-gateway",
		"https://admin.example.com/gw-fallback",
	}
	if !slices.Equal(plan.Bases, wantBases) {
		t.Fatalf("SpecCollector Bases = %v, want %v", plan.Bases, wantBases)
	}

	var prefixes []string
	for _, svc := range plan.Services {
		prefixes = append(prefixes, svc.PrefixURL)
	}
	wantPrefixes := []string{
		"https://admin.example.com/api-gateway/orders",
		"https://admin.example.com/api-gateway/billing",
		"https://admin.example.com/api-gateway/inventory",
		"https://admin.example.com/api-gateway/reports",
		"https://admin.example.com/api-gateway/users",
	}
	if !slices.Equal(prefixes, wantPrefixes) {
		t.Fatalf("SpecCollector Services = %v, want %v", prefixes, wantPrefixes)
	}

	// APIOrigins must also ignore XML schema namespaces and non-API PropBases (`url`, `docLink`).
	apiRes := jsapi.Result{
		PropBases: []jsapi.Header{
			{Name: "CHART", Value: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart"},
			{Name: "href", Value: "https://portal-static.partner.test/guide"},
			{Name: "docLink", Value: "https://docs.partner.test/manual"},
			{Name: "authServer", Value: "https://auth.partner.test/oauth2"},
		},
	}
	origins := APIOrigins(apiRes, func(string) bool { return false })
	wantOrigins := []string{"https://auth.partner.test"}
	if !slices.Equal(origins, wantOrigins) {
		t.Fatalf("APIOrigins = %v, want %v", origins, wantOrigins)
	}
}
