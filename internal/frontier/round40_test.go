package frontier

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

func TestRound40SpecProbeBlocksThirdPartySDKAndOutOfScopePlan(t *testing.T) {
	r := jsapi.Result{
		Bases: []string{
			"https://login.microsoftonline.com/common/oauth2/v2.0",
			"https://login.microsoftonline.us/organizations",
			"https://login.chinacloudapi.cn/common",
			"https://graph.microsoft.com/v1.0",
			"https://nominatim.openstreetmap.org/search",
			"https://reactrouter.com/docs",
			"https://ns.adobe.com/xdp",
			"https://www.xfa.org/schema",
			// Unlisted external partner host: proves scope rule is the primary defense.
			"https://api-partner.example.net/gw",
			// In-scope subdomain gateway.
			"https://api.example.test/gw",
		},
		Endpoints: []jsapi.Endpoint{
			{Method: "GET", URL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", Kind: "fetch"},
			{Method: "GET", URL: "https://api-partner.example.net/gw/billing/v1/invoices", Kind: "fetch"},
			{Method: "GET", URL: "https://api-partner.example.net/orders/v1/list", Kind: "fetch"},
			{Method: "GET", URL: "https://api.example.test/gw/auth/v1/me", Kind: "fetch"},
		},
	}

	rdnScope, err := scope.New("www.example.test", "rdn")
	if err != nil {
		t.Fatal(err)
	}

	origins := APIOrigins(r, rdnScope)
	for _, blocked := range []string{
		"https://login.microsoftonline.com",
		"https://login.microsoftonline.us",
		"https://login.chinacloudapi.cn",
		"https://graph.microsoft.com",
		"https://nominatim.openstreetmap.org",
		"https://reactrouter.com",
		"https://ns.adobe.com",
		"https://www.xfa.org",
	} {
		if slices.Contains(origins, blocked) {
			t.Fatalf("third-party SDK/IdP/map/schema origin %s leaked into APIOrigins: %v", blocked, origins)
		}
	}
	// D2 preserved: clean unlisted partner API origin still appears in APIOrigins for root SpecPaths.
	if !slices.Contains(origins, "https://api-partner.example.net") {
		t.Fatalf("clean partner origin missing from APIOrigins (D2): %v", origins)
	}
	if !slices.Contains(origins, "https://api.example.test") {
		t.Fatalf("in-scope origin missing from APIOrigins: %v", origins)
	}

	var sc SpecCollector
	sc.AddScript(r, "https://www.example.test/", "https://www.example.test/app.js")
	plan := sc.Plan("https://www.example.test", rdnScope)

	if !slices.Equal(plan.Bases, []string{"https://api.example.test/gw"}) {
		t.Fatalf("rdn plan.Bases = %v, want [https://api.example.test/gw]", plan.Bases)
	}
	for _, svc := range plan.Services {
		if strings.Contains(svc.PrefixURL, "api-partner.example.net") || strings.Contains(svc.PrefixURL, "microsoftonline") {
			t.Fatalf("out-of-scope service leaked into plan.Services: %+v", plan.Services)
		}
	}
	var svcURLs []string
	for _, svc := range plan.Services {
		svcURLs = append(svcURLs, svc.PrefixURL)
	}
	if !slices.Contains(svcURLs, "https://api.example.test/gw/auth") {
		t.Fatalf("expected in-scope service https://api.example.test/gw/auth in %v", svcURLs)
	}

	// -scope fqdn on www.example.test: sibling api.example.test is out of scope for sub-path/service multiplication.
	fqdnScope, err := scope.New("www.example.test", "fqdn")
	if err != nil {
		t.Fatal(err)
	}
	fqdnPlan := sc.Plan("https://www.example.test", fqdnScope)
	if len(fqdnPlan.Bases) != 0 || len(fqdnPlan.Services) != 0 {
		t.Fatalf("fqdn plan should not multiply sibling gateway bases/services, got bases=%v services=%+v", fqdnPlan.Bases, fqdnPlan.Services)
	}
}
