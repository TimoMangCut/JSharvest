package detect

import "testing"

func TestCheck(t *testing.T) {
	cases := []struct {
		name    string
		doc     Doc
		blocked bool
		vendor  string
	}{
		// Cloudflare.
		{"cf-mitigated header", Doc{Status: 403, Headers: map[string]string{"cf-mitigated": "challenge"}}, true, Cloudflare},
		{"cf-mitigated on a 200", Doc{Status: 200, Headers: map[string]string{"cf-mitigated": "Challenge"}}, true, Cloudflare},
		{"503 from cloudflare with challenge title", Doc{Status: 503, Headers: map[string]string{"server": "cloudflare"}, Title: "Just a moment..."}, true, Cloudflare},
		{"403 attention required", Doc{Status: 403, Headers: map[string]string{"server": "cloudflare"}, Title: "Attention Required! | Cloudflare"}, true, Cloudflare},
		{"403 cloudflare 1006 access denied title", Doc{Status: 403, Headers: map[string]string{"server": "cloudflare", "cf-ray": "99abc"}, Title: "Access denied | admin.example.vn used Cloudflare to restrict access | admin.example.vn | Cloudflare"}, true, Cloudflare},
		{"403 cloudflare 1006 via cf-ray only", Doc{Status: 403, Headers: map[string]string{"cf-ray": "99abc"}, Title: "Access denied | example.com used Cloudflare to restrict access | example.com | Cloudflare"}, true, Cloudflare},
		{"429 cloudflare 1015 rate limited title", Doc{Status: 429, Headers: map[string]string{"server": "cloudflare"}, Title: "Access denied | example.com | Cloudflare | Error 1015"}, true, Cloudflare},
		{"403 cloudflare 1006 body without title", Doc{Status: 403, Headers: map[string]string{"server": "cloudflare"}, Body: `<div id="cf-error-details"><h1>Access denied</h1><a href="https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1006/">Cloudflare</a></div>`}, true, Cloudflare},
		// Akamai.
		{"akamai access denied", Doc{Status: 403, Headers: map[string]string{"server": "AkamaiGHost"}, Title: "Access Denied"}, true, Akamai},
		{"akamai reference in body", Doc{Status: 403, Headers: map[string]string{"server": "AkamaiGHost"}, Body: "You don't have permission. Reference #18.abcd"}, true, Akamai},
		// DataDome.
		{"datadome 403", Doc{Status: 403, Headers: map[string]string{"x-datadome": "protected", "x-dd-b": "1"}}, true, DataDome},
		{"datadome interstitial body", Doc{Status: 200, Body: "<iframe src='https://geo.captcha-delivery.com/captcha/'>"}, true, DataDome},
		// PerimeterX / HUMAN.
		{"perimeterx 403 header", Doc{Status: 403, Headers: map[string]string{"x-px-block": "1"}}, true, PerimeterX},
		{"perimeterx body", Doc{Status: 200, Body: "Please verify you are a human by clicking px-captcha"}, true, PerimeterX},
		// Imperva / Incapsula.
		{"imperva incident", Doc{Status: 403, Headers: map[string]string{"x-iinfo": "1-2-3"}, Body: "Request unsuccessful. Incapsula incident ID: 123"}, true, Imperva},

		// Negatives: healthy pages behind a WAF, and errors that are not
		// challenges. A fronting vendor alone is never a block.
		{"healthy page behind cloudflare", Doc{Status: 200, Headers: map[string]string{"server": "cloudflare"}, Title: "Welcome"}, false, ""},
		{"plain 503", Doc{Status: 503, Headers: map[string]string{"server": "nginx"}, Title: "Service Unavailable"}, false, ""},
		{"cloudflare 503 without challenge title", Doc{Status: 503, Headers: map[string]string{"server": "cloudflare"}, Title: "Maintenance"}, false, ""},
		{"origin app 403 access denied behind cloudflare", Doc{Status: 403, Headers: map[string]string{"server": "cloudflare", "cf-ray": "99abc"}, Title: "Access Denied", Body: `{"error":"access denied"}`}, false, ""},
		{"origin app 403 forbidden behind cloudflare", Doc{Status: 403, Headers: map[string]string{"server": "cloudflare", "cf-ray": "99abc"}, Title: "403 Forbidden", Body: "<h1>403 Forbidden</h1>"}, false, ""},
		{"403 cloudflare 1006 plain text (API client)", Doc{Status: 403, Headers: map[string]string{"server": "cloudflare", "cf-ray": "a5-HKG", "content-type": "text/plain; charset=UTF-8"}, Body: "error code: 1006\n"}, true, Cloudflare},
		{"403 app plain text 'error code: 1006' without cloudflare", Doc{Status: 403, Headers: map[string]string{"content-type": "text/plain"}, Body: "error code: 1006"}, false, ""},
		{"200 cloudflare body 'error code: 1006' (not a blocking status)", Doc{Status: 200, Headers: map[string]string{"server": "cloudflare"}, Body: "error code: 1006"}, false, ""},
		{"200 docs page mentioning cloudflare-1xxx-errors", Doc{Status: 200, Headers: map[string]string{"server": "cloudflare"}, Title: "Troubleshooting | Cloudflare", Body: "cloudflare-1xxx-errors/error-1006"}, false, ""},
		{"challenge title on a 200", Doc{Status: 200, Headers: map[string]string{"server": "cloudflare"}, Title: "Just a moment..."}, false, ""},
		{"healthy akamai 200", Doc{Status: 200, Headers: map[string]string{"server": "AkamaiGHost"}, Title: "Home"}, false, ""},
		{"akamai 403 but ordinary", Doc{Status: 403, Headers: map[string]string{"server": "AkamaiGHost"}, Title: "Forbidden"}, false, ""},
		{"healthy datadome 200", Doc{Status: 200, Headers: map[string]string{"x-datadome": "protected", "set-cookie": "datadome=abc"}, Title: "Home"}, false, ""},
		{"healthy imperva 200", Doc{Status: 200, Headers: map[string]string{"x-iinfo": "1-2-3", "set-cookie": "incap_ses_1=x"}, Title: "Home"}, false, ""},
		{"imperva 403 without incident page", Doc{Status: 403, Headers: map[string]string{"x-iinfo": "1-2-3"}, Title: "Forbidden"}, false, ""},
		{"an app's own 403 behind datadome", Doc{Status: 403, Headers: map[string]string{"x-datadome": "protected"}, Title: "Forbidden"}, false, ""},
		{"an app's own 401 behind perimeterx", Doc{Status: 401, Headers: map[string]string{"x-px": "1"}, Title: "Login"}, false, ""},
		{"perimeterx cookie but 200", Doc{Status: 200, Headers: map[string]string{"set-cookie": "_pxhd=abc"}, Title: "Home"}, false, ""},
	}
	for _, c := range cases {
		got := Check(c.doc)
		if got.Blocked != c.blocked {
			t.Errorf("%s: blocked = %v, want %v (%+v)", c.name, got.Blocked, c.blocked, got)
			continue
		}
		if c.blocked && got.Vendor != c.vendor {
			t.Errorf("%s: vendor = %q, want %q", c.name, got.Vendor, c.vendor)
		}
		if c.blocked && len(got.Evidence) == 0 {
			t.Errorf("%s: blocked with no evidence", c.name)
		}
	}
}

func TestVendor(t *testing.T) {
	for _, c := range []struct {
		name   string
		doc    Doc
		vendor string
	}{
		{"cloudflare by server", Doc{Headers: map[string]string{"server": "cloudflare"}}, Cloudflare},
		{"cloudflare by cf-ray", Doc{Headers: map[string]string{"cf-ray": "abc"}}, Cloudflare},
		{"akamai", Doc{Headers: map[string]string{"server": "AkamaiGHost"}}, Akamai},
		{"datadome cookie", Doc{Headers: map[string]string{"set-cookie": "datadome=abc; path=/"}}, DataDome},
		{"perimeterx cookie", Doc{Headers: map[string]string{"set-cookie": "_px3=abc"}}, PerimeterX},
		{"imperva cookie", Doc{Headers: map[string]string{"set-cookie": "visid_incap_1=x"}}, Imperva},
		{"none", Doc{Headers: map[string]string{"server": "nginx"}}, ""},
	} {
		if v, ev := Vendor(c.doc); v != c.vendor {
			t.Errorf("%s: vendor = %q, want %q (%v)", c.name, v, c.vendor, ev)
		} else if v != "" && len(ev) == 0 {
			t.Errorf("%s: vendor %q with no evidence", c.name, v)
		}
	}
}

func TestAllChallenge(t *testing.T) {
	for _, c := range []struct {
		total, challenge int
		want             bool
	}{
		{0, 0, false},
		{3, 3, true},
		{3, 2, false},
		{1, 0, false},
	} {
		if got := AllChallenge(c.total, c.challenge); got != c.want {
			t.Errorf("AllChallenge(%d, %d) = %v, want %v", c.total, c.challenge, got, c.want)
		}
	}
}

func TestScriptTags(t *testing.T) {
	for url, want := range map[string]bool{
		"https://site/cdn-cgi/challenge-platform/scripts/jsd/main.js":      true,
		"https://challenges.cloudflare.com/turnstile/v0/api.js":            true,
		"https://geo.captcha-delivery.com/captcha/main.js":                 true,
		"https://client.px-cloud.net/abc/main.min.js":                      true,
		"https://site/_Incapsula_Resource?SWJIYLWA=x":                      true,
		"https://site/static/js/main.js":                                   false,
		"https://site/cdn-cgi/scripts/5c5dd728/cloudflare-static/email.js": true, // cdn-infra
	} {
		if got := len(ScriptTags(url)) > 0; got != want {
			t.Errorf("ScriptTags(%s) = %v, want %v", url, got, want)
		}
	}
}

func TestIsChallengeScript(t *testing.T) {
	const site = "https://admin.example.test/"
	const plat = "https://admin.example.test/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=1"
	big := make([]byte, maxChallengeBody+1)
	copy(big, "window._cf_chl_opt={}")
	for _, c := range []struct {
		name               string
		url, init, kind    string
		body               string
		bodyBytes          []byte
		blocked, challenge bool
	}{
		{"challenge platform file", plat, "", "file", "x", nil, false, true},
		{"turnstile", "https://challenges.cloudflare.com/turnstile/v0/b/1/api.js", plat, "file", "x", nil, false, true},
		// Cloudflare's VM: eval blocks with no URL, evaluated by the platform.
		{"eval from the platform", "", plat, "eval", "var a=1", nil, false, true},
		// The inline loader on the challenge page: the page's URL is the site's.
		{"inline loader", site, "", "inline", `(function(){window._cf_chl_opt={cvId:'3'}})()`, nil, false, true},
		{"inline jsd snippet on a healthy page", site, "", "inline", `a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'`, nil, false, true},
		{"inline cloudflare 1006 sparrow feedback", site, "", "inline", `b.open("POST","https://sparrow.cloudflare.com/api/v1/event")`, nil, false, true},
		{"inline cloudflare 1006 ip reveal", site, "", "inline", `var c=a.getElementById("cf-footer-ip-reveal")`, nil, false, true},
		{"inline cloudflare 1006 translation", site, "", "inline", `window._cf_translation = {};`, nil, false, true},
		{"any script of a blocked page", site + "static/app.js", "", "file", "x", nil, true, true},
		{"datadome tag", "https://js.datadome.co/tags.js", "", "file", "x", nil, false, true},
		{"recaptcha", "https://www.google.com/recaptcha/api.js", "", "file", "x", nil, false, true},

		{"site bundle", site + "static/js/main.js", site, "file", "fetch('/api')", nil, false, false},
		// A file of the site may name the challenge (to handle it): kept.
		{"site file that names the platform", site + "static/js/main.js", "", "file", "if(u.includes('/cdn-cgi/challenge-platform/'))", nil, false, false},
		{"large inline that names it", site, "", "inline", "", big, false, false},
		{"site eval", "", site + "static/js/main.js", "eval", "x=1", nil, false, false},
	} {
		body := c.bodyBytes
		if body == nil {
			body = []byte(c.body)
		}
		if got := IsChallengeScript(c.url, c.init, c.kind, body, c.blocked); got != c.challenge {
			t.Errorf("%s: IsChallengeScript = %v, want %v", c.name, got, c.challenge)
		}
	}
}

func TestInfra(t *testing.T) {
	for _, c := range []struct {
		url  string
		tags []string
	}{
		{"https://site/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js", []string{TagCDNInfra}},
		{"https://site/cdn-cgi/zaraz/s.js", []string{TagCDNInfra}},
		{"https://static.cloudflareinsights.com/beacon.min.js", []string{TagCDNInfra}},
		{"https://performance.radar.cloudflare.com/beacon.js", []string{TagCDNInfra}},
		{"https://site/cdn-cgi/challenge-platform/scripts/jsd/main.js", []string{TagChallenge}},
		{"https://site/static/js/main.js", nil},
	} {
		got := ScriptTags(c.url)
		if len(got) != len(c.tags) || (len(got) > 0 && got[0] != c.tags[0]) {
			t.Errorf("ScriptTags(%s) = %v, want %v", c.url, got, c.tags)
		}
	}
	for p, want := range map[string]bool{"/cdn-cgi/challenge-platform/h/b/flow/ov1/x": true, "/cdn-cgi/rum": true, "/api/cdn-cgi": false, "/": false} {
		if InfraPath(p) != want {
			t.Errorf("InfraPath(%s) = %v", p, !want)
		}
	}
	if !Quarantined(nil, nil, []string{"https://s/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"}) {
		t.Error("an eval of the platform is not quarantined")
	}
	if Quarantined(nil, []string{"https://s/app.js"}, []string{"https://s/"}) {
		t.Error("a site script is quarantined")
	}
}
