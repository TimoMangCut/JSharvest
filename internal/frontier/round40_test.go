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

	// The partner's own named base is asked of (D2 at the base the code
	// names, round 40 B1), but nothing is derived under it.
	if !slices.Equal(plan.Bases, []string{"https://api.example.test/gw", "https://api-partner.example.net/gw"}) {
		t.Fatalf("rdn plan.Bases = %v, want [https://api.example.test/gw https://api-partner.example.net/gw]", plan.Bases)
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
	if !slices.Equal(fqdnPlan.Bases, []string{"https://api-partner.example.net/gw", "https://api.example.test/gw"}) || len(fqdnPlan.Services) != 0 {
		t.Fatalf("fqdn plan: want only the named bases, no services; got bases=%v services=%+v", fqdnPlan.Bases, fqdnPlan.Services)
	}
}

// R40-B1: a host outside -scope gets at most MaxOutOfScopeSpecBasesPerOrigin
// of the bases the code names, and none it derives (a gateway prefix seen
// only in endpoint paths).
func TestRound40OutOfScopeBasesCappedAndExplicitOnly(t *testing.T) {
	r := jsapi.Result{
		Bases: []string{
			"https://edge.partner.example.net/a",
			"https://edge.partner.example.net/b",
			"https://edge.partner.example.net/c",
		},
		Endpoints: []jsapi.Endpoint{
			// Implicit gateway /api-gateway/<svc>/v1 on another out-of-scope host.
			{Method: "GET", URL: "https://gw.other.example.org/api-gateway/users/v1/me", Kind: "fetch"},
			{Method: "GET", URL: "https://gw.other.example.org/api-gateway/orders/v1/list", Kind: "fetch"},
		},
	}
	inScope := func(h string) bool { return h == "www.example.test" }
	var sc SpecCollector
	sc.AddScript(r, "https://www.example.test/", "https://www.example.test/app.js")
	plan := sc.Plan("https://www.example.test", inScope)
	n := 0
	for _, b := range plan.Bases {
		if strings.Contains(b, "edge.partner.example.net") {
			n++
		}
		if strings.Contains(b, "gw.other.example.org") {
			t.Fatalf("derived out-of-scope gateway in plan.Bases: %v", plan.Bases)
		}
	}
	if n != MaxOutOfScopeSpecBasesPerOrigin {
		t.Fatalf("out-of-scope named bases kept %d, want %d: %v", n, MaxOutOfScopeSpecBasesPerOrigin, plan.Bases)
	}
	if len(plan.Services) != 0 {
		t.Fatalf("out-of-scope services: %+v", plan.Services)
	}
}
