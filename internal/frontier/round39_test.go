package frontier

import (
	"slices"
	"testing"
)

func TestRound39CookieConsentCDNFilteredFromAPIOrigins(t *testing.T) {
	for _, h := range []string{
		"privacyportal-eu-cdn.onetrust.com",
		"cdn.cookielaw.org",
		"consent.cookiebot.com",
		"consent.trustarc.com",
		"app.usercentrics.eu",
	} {
		if !isStaticOrNonAPIHost(h) {
			t.Errorf("expected %q to be classified as non-API infra host", h)
		}
	}
}

func TestRound39WellKnownAppLinksAndWebManifest(t *testing.T) {
	wm := []byte(`{
		"name": "Backoffice PWA",
		"start_url": "/pwa/dashboard",
		"scope": "/",
		"shortcuts": [{"url": "/pwa/orders"}],
		"share_target": {"action": "/pwa/share", "method": "POST"}
	}`)
	gotWM := keys(FromWebManifest(wm, "https://portal.example.test/site.webmanifest"))
	wantWM := []string{
		"route name https://portal.example.test/pwa/share",
		"route visit https://portal.example.test/pwa/dashboard",
		"route visit https://portal.example.test/pwa/orders",
	}
	if !slices.Equal(gotWM, wantWM) {
		t.Fatalf("FromWebManifest = %v, want %v", gotWM, wantWM)
	}

	aasa := []byte(`{
		"applinks": {
			"details": [{
				"appID": "TEAMID.com.example.app",
				"paths": ["/mobile/orders/*", "NOT /internal/*", "*"],
				"components": [
					{"/": "/mobile/checkout/*", "exclude": false},
					{"/": "/mobile/blocked/*", "exclude": true}
				]
			}]
		}
	}`)
	gotAASA := keys(FromAppleAppSiteAssociation(aasa, "https://portal.example.test"))
	wantAASA := []string{
		"route visit https://portal.example.test/mobile/checkout",
		"route visit https://portal.example.test/mobile/orders",
	}
	if !slices.Equal(gotAASA, wantAASA) {
		t.Fatalf("FromAppleAppSiteAssociation = %v, want %v", gotAASA, wantAASA)
	}

	al := []byte(`[
		{"relation": ["delegate_permission/common.handle_all_urls"], "target": {"namespace": "android_app", "package_name": "com.example.app"}},
		{"relation": ["delegate_permission/common.get_login_creds"], "target": {"namespace": "web", "site": "https://companion.example.test"}}
	]`)
	gotAL := keys(FromAssetLinks(al))
	wantAL := []string{"link visit https://companion.example.test"}
	if !slices.Equal(gotAL, wantAL) {
		t.Fatalf("FromAssetLinks = %v, want %v", gotAL, wantAL)
	}
}
