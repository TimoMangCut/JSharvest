package frontier

import "testing"

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
