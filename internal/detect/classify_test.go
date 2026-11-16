package detect

import "testing"

// Round 25J: the kinds every caller reads, from what each has: the
// Sender's head of the body, a tab's title alone (the frontier).
func TestClassifyKinds(t *testing.T) {
	cf := map[string]string{"server": "cloudflare", "cf-ray": "1-SIN", "content-type": "text/html"}
	for _, c := range []struct {
		name string
		d    Doc
		want BlockKind // "" for no block
	}{
		{"title only: a WAF rule's page", Doc{Status: 403, Headers: cf, Title: "Attention Required! | Cloudflare"}, BlockRequest},
		{"title only: a challenge", Doc{Status: 403, Headers: cf, Title: "Just a moment..."}, BlockChallenge},
		{"title only: access denied (a rule or a ban: unknown)", Doc{Status: 403, Headers: cf, Title: "Access denied | x.test used Cloudflare to restrict access"}, BlockRequest},
		{"body: 1006", Doc{Status: 403, Headers: cf, Title: "Access denied | x.test used Cloudflare to restrict access", Body: `<div id="cf-error-details">Error 1006</div>`}, BlockClient},
		{"plain text 1006", Doc{Status: 403, Headers: map[string]string{"server": "cloudflare"}, Body: "error code: 1006"}, BlockClient},
		{"sorry you have been blocked, with the JSD script", Doc{Status: 403, Headers: cf, Title: "Attention Required! | Cloudflare",
			Body: `<h1>Sorry, you have been blocked</h1><script src="/cdn-cgi/challenge-platform/h/g/scripts/jsd/x/main.js"></script>`}, BlockRequest},
		{"cf-mitigated", Doc{Status: 403, Headers: map[string]string{"cf-mitigated": "challenge"}}, BlockChallenge},
		{"429", Doc{Status: 429, Headers: map[string]string{"retry-after": "3"}}, BlockRate},
		{"the app's own 403", Doc{Status: 403, Headers: cf, Title: "Access Denied", Body: "<h1>403</h1>"}, ""},
	} {
		b := Classify(c.d)
		got := BlockKind("")
		if b != nil {
			got = b.Kind
		}
		if got != c.want {
			t.Errorf("%s: %q (%v), want %q", c.name, got, b, c.want)
		}
	}
	if !BlockChallenge.BrowserMayPass() || !BlockSignature.BrowserMayPass() || BlockRequest.BrowserMayPass() || BlockClient.BrowserMayPass() || BlockRate.BrowserMayPass() {
		t.Error("BrowserMayPass")
	}
}
