// Package detect identifies bot/WAF challenges and labels vendor challenge
// scripts so they are isolated from the target's collected assets.
package detect

import (
	"fmt"
	"regexp"
	"strings"
)

// Doc is the main-frame document the tab ended up on.
type Doc struct {
	URL     string
	Status  int64
	Headers map[string]string // lowercase keys; set-cookie holds all cookies joined
	Title   string
	// Body is the main document's text, when a caller has it. It is optional:
	// header, status and title alone catch most challenges, and some vendors
	// (PerimeterX, Imperva, Akamai) only become certain with the body. An
	// empty Body simply skips the body rules.
	Body string
}

type Result struct {
	Blocked  bool     `json:"blocked"`
	Vendor   string   `json:"vendor,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// cfPlainCodeRe is the whole body of Cloudflare's plain-text block answer.
var cfPlainCodeRe = regexp.MustCompile(`^error code: (1\d{3})$`)

// vendor names, stable strings that callers and run.json record.
const (
	Cloudflare = "cloudflare"
	Akamai     = "akamai"
	DataDome   = "datadome"
	PerimeterX = "perimeterx"
	Imperva    = "imperva"
)

// rule is one WAF/bot vendor. identify finds the signs that the vendor sits
// in front of this response at all, present on healthy pages too (a server
// header, a cookie); it is never on its own a reason to call a run blocked.
// block finds the signs specific to a challenge or deny page.
type rule struct {
	vendor   string
	identify func(d Doc, h func(string) string, title, body string) []string
	block    func(d Doc, h func(string) string, title, body string) []string
}

var rules = []rule{
	{
		vendor: Cloudflare,
		identify: func(d Doc, h func(string) string, title, body string) []string {
			var e []string
			if strings.Contains(h("server"), "cloudflare") {
				e = append(e, "server: cloudflare")
			}
			if h("cf-ray") != "" {
				e = append(e, "cf-ray header")
			}
			return e
		},
		block: func(d Doc, h func(string) string, title, body string) []string {
			// cf-mitigated: challenge is the one header Cloudflare sets only
			// on a challenge, so it stands on any status.
			if h("cf-mitigated") == "challenge" {
				return []string{"cf-mitigated: challenge"}
			}
			isCF := strings.Contains(h("server"), "cloudflare") || h("cf-ray") != ""
			if !blockingStatus(d.Status) || !isCF {
				return nil
			}
			cfHeader := "server: cloudflare"
			if !strings.Contains(h("server"), "cloudflare") {
				cfHeader = "cf-ray header"
			}
			// Challenge interstitials ("Just a moment...", "Attention Required!")
			// and Cloudflare 1xxx IP/WAF/rate-limit deny pages ("Access denied |
			// <host> used Cloudflare to restrict access", "Error 1015 ... |
			// Cloudflare"). Requiring "cloudflare" alongside "access denied |"
			// keeps an origin app's own "<title>Access Denied</title>" 403
			// unblocked.
			if strings.Contains(title, "just a moment") ||
				strings.Contains(title, "attention required") ||
				(strings.Contains(title, "cloudflare") &&
					(strings.Contains(title, "access denied |") ||
						strings.Contains(title, "used cloudflare to restrict access") ||
						strings.Contains(title, "you are being rate limited") ||
						strings.Contains(title, "error 10") ||
						strings.Contains(title, "error 11") ||
						strings.Contains(title, "error 12"))) {
				return []string{fmt.Sprintf("status %d", d.Status), cfHeader, "title: " + d.Title}
			}
			if body != "" &&
				(strings.Contains(body, "cloudflare-1xxx-errors") ||
					(strings.Contains(body, `id="cf-error-details"`) &&
						(strings.Contains(body, "access denied") ||
							strings.Contains(body, "you are being rate limited") ||
							strings.Contains(body, "has banned your ip")))) {
				return []string{fmt.Sprintf("status %d", d.Status), cfHeader, "cloudflare 1xxx block page"}
			}
			// The same block to a client that does not ask for HTML (an API
			// call, Accept: application/json): text/plain "error code: 1006"
			// (round 25I; seen on api.example.biz and api2.example.com,
			// 2026-11-12).
			if m := cfPlainCodeRe.FindStringSubmatch(strings.TrimSpace(body)); m != nil {
				return []string{fmt.Sprintf("status %d", d.Status), cfHeader, "error code: " + m[1]}
			}
			return nil
		},
	},
	{
		vendor: Akamai,
		identify: func(d Doc, h func(string) string, title, body string) []string {
			var e []string
			if strings.Contains(h("server"), "akamaighost") {
				e = append(e, "server: AkamaiGHost")
			}
			if h("x-akamai-transformed") != "" {
				e = append(e, "x-akamai-transformed header")
			}
			return e
		},
		block: func(d Doc, h func(string) string, title, body string) []string {
			// Akamai's deny page is "Access Denied" from AkamaiGHost with a
			// "Reference #..." line; the reference line is what tells it from
			// an ordinary 403.
			if blockingStatus(d.Status) && strings.Contains(h("server"), "akamaighost") &&
				(strings.Contains(title, "access denied") || strings.Contains(body, "reference #")) {
				return []string{fmt.Sprintf("status %d", d.Status), "server: AkamaiGHost", "access denied page"}
			}
			return nil
		},
	},
	{
		vendor: DataDome,
		identify: func(d Doc, h func(string) string, title, body string) []string {
			var e []string
			if h("x-datadome") != "" {
				e = append(e, "x-datadome header")
			}
			if strings.Contains(h("set-cookie"), "datadome=") {
				e = append(e, "datadome cookie")
			}
			return e
		},
		block: func(d Doc, h func(string) string, title, body string) []string {
			// x-datadome rides every response DataDome fronts, the app's own
			// 403 included: a block needs its own sign, the x-dd-b header
			// of a blocked answer, or the interstitial that loads
			// captcha-delivery.com.
			if blockingStatus(d.Status) && h("x-datadome") != "" && h("x-dd-b") != "" {
				return []string{fmt.Sprintf("status %d", d.Status), "x-datadome header", "x-dd-b header"}
			}
			if strings.Contains(body, "captcha-delivery.com") {
				return []string{"captcha-delivery.com in body"}
			}
			return nil
		},
	},
	{
		vendor: PerimeterX,
		identify: func(d Doc, h func(string) string, title, body string) []string {
			var e []string
			if pxHeader(h) {
				e = append(e, "x-px header")
			}
			c := h("set-cookie")
			if strings.Contains(c, "_pxhd=") || strings.Contains(c, "_px3=") || strings.Contains(c, "_px=") {
				e = append(e, "_px cookie")
			}
			return e
		},
		block: func(d Doc, h func(string) string, title, body string) []string {
			// HUMAN/PerimeterX block page: 403 with a "verify you are a
			// human" interstitial served from px-cdn / px-cloud.
			// x-px may ride every response; x-px-block is the block's.
			if blockingStatus(d.Status) && h("x-px-block") != "" {
				return []string{fmt.Sprintf("status %d", d.Status), "x-px-block header"}
			}
			if strings.Contains(body, "px-captcha") || strings.Contains(body, "perimeterx") ||
				strings.Contains(body, "please verify you are a human") {
				return []string{"perimeterx interstitial in body"}
			}
			return nil
		},
	},
	{
		vendor: Imperva,
		identify: func(d Doc, h func(string) string, title, body string) []string {
			var e []string
			if h("x-iinfo") != "" {
				e = append(e, "x-iinfo header")
			}
			if strings.Contains(h("x-cdn"), "incapsula") {
				e = append(e, "x-cdn: Incapsula")
			}
			c := h("set-cookie")
			if strings.Contains(c, "incap_ses_") || strings.Contains(c, "visid_incap_") {
				e = append(e, "incapsula cookie")
			}
			return e
		},
		block: func(d Doc, h func(string) string, title, body string) []string {
			// Imperva/Incapsula's block page says "Request unsuccessful" with
			// an "Incapsula incident ID"; x-iinfo rides every response, so it
			// is not a block on its own.
			if strings.Contains(body, "incapsula incident id") {
				return []string{"incapsula incident id in body"}
			}
			if blockingStatus(d.Status) && h("x-iinfo") != "" &&
				(strings.Contains(title, "request unsuccessful") || strings.Contains(body, "request unsuccessful")) {
				return []string{fmt.Sprintf("status %d", d.Status), "x-iinfo header", "request unsuccessful page"}
			}
			return nil
		},
	},
}

// Check looks at the last main-frame document. A challenge solves itself
// and reloads, so the first document can be a challenge on a healthy run;
// only the last one counts. Scripts are not evidence here: Cloudflare injects
// challenge-platform scripts into ordinary pages, and Turnstile sits on
// ordinary login forms (see AllChallenge for the whole-run signal).
func Check(d Doc) Result {
	h := func(k string) string { return strings.ToLower(d.Headers[k]) }
	title := strings.ToLower(d.Title)
	body := strings.ToLower(d.Body)
	for _, r := range rules {
		if ev := r.block(d, h, title, body); ev != nil {
			return Result{Blocked: true, Vendor: r.vendor, Evidence: ev}
		}
	}
	return Result{}
}

// Vendor names the bot/WAF vendor sitting in front of a response, blocked or
// not, with the signs that say so, or "" if none is recognized. It lets a run
// report "fronted by Cloudflare" on a healthy page and, with the status, tell
// an authorized operator which product to whitelist.
func Vendor(d Doc) (string, []string) {
	h := func(k string) string { return strings.ToLower(d.Headers[k]) }
	title := strings.ToLower(d.Title)
	body := strings.ToLower(d.Body)
	for _, r := range rules {
		if ev := r.identify(d, h, title, body); ev != nil {
			return r.vendor, ev
		}
	}
	return "", nil
}

func pxHeader(h func(string) string) bool {
	// PerimeterX stamps responses with x-px, x-px-... headers.
	return h("x-px") != "" || h("x-px-block") != "" || h("x-px-compromised-credentials") != ""
}

// Warning returns a note for a main document that failed without the signs
// of a challenge, or "".
func Warning(d Doc) string {
	if d.Status >= 400 {
		return fmt.Sprintf("main document %s returned %d", d.URL, d.Status)
	}
	return ""
}

// blockingStatus: the statuses vendors answer a block with. Not 401: an
// app's own login-required answer.
// Suspect reports a main document that may be a block page whose title
// tells (Cloudflare's "Attention Required!" carries no cf-mitigated): a
// 403, 429 or 503 from behind a recognized bot vendor that Check does not
// call blocked on its status and headers alone.
func Suspect(d Doc) bool {
	if !blockingStatus(d.Status) || Check(d).Blocked {
		return false
	}
	v, _ := Vendor(d)
	return v != ""
}

func blockingStatus(s int64) bool {
	return s == 403 || s == 429 || s == 503
}

// AllChallenge reports that every script a run saw is a bot-vendor
// challenge script (which capture drops) and there is at least one. It is a
// separate signal from Check: a site can answer with a 200 page whose only
// scripts are the challenge's, so the main document looks healthy while the
// run in truth saw nothing but the challenge.
func AllChallenge(totalScripts, challengeScripts int) bool {
	return totalScripts > 0 && totalScripts == challengeScripts
}

// Script tags. A "challenge" script is a bot vendor's challenge or
// interstitial code: never the target's, so capture drops it before it
// reaches the store, the resolver or the endpoint catalog. A "cdn-infra"
// script is the CDN's own helper (email obfuscation, analytics beacon,
// Zaraz): kept, but not read for the target's endpoints.
const (
	TagChallenge = "challenge"
	TagCDNInfra  = "cdn-infra"
)

// ChallengeURL reports whether a URL belongs to a bot vendor's challenge:
// the script itself, or the code it loads and evaluates.
func ChallengeURL(u string) bool {
	l := strings.ToLower(u)
	for _, p := range challengeURLs {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

var challengeURLs = []string{
	"/cdn-cgi/challenge-platform/", "/cdn-cgi/images/trace/", // Cloudflare
	"challenges.cloudflare.com/",     // Cloudflare Turnstile
	"captcha-delivery.com/",          // DataDome
	"js.datadome.co/",                // DataDome tags
	".px-cdn.net/", ".px-cloud.net/", // PerimeterX / HUMAN
	"/px/captcha/", "captcha.px-cdn.net", // PerimeterX
	"/_incapsula_resource", // Imperva
	"hcaptcha.com/",        // hCaptcha
	"/recaptcha/api", "/recaptcha/enterprise", "recaptcha.net/recaptcha/",
	"arkoselabs.com/", "funcaptcha.com/", // Arkose
}

// InfraURL reports whether a URL is a CDN's own helper script rather than
// the site's: Cloudflare's /cdn-cgi/ scripts (the challenge platform is
// ChallengeURL's), its analytics and Radar beacons.
func InfraURL(u string) bool {
	l := strings.ToLower(u)
	return (strings.Contains(l, "/cdn-cgi/") && !ChallengeURL(l)) ||
		strings.Contains(l, "static.cloudflareinsights.com/") ||
		strings.Contains(l, "performance.radar.cloudflare.com/")
}

// InfraPath reports whether a request path is a CDN's own: Cloudflare
// answers /cdn-cgi/ on every site it fronts, challenge, beacon and trace
// alike. It is never the target's endpoint.
func InfraPath(path string) bool {
	return strings.HasPrefix(strings.ToLower(path), "/cdn-cgi/")
}

// challengeBody are strings only a challenge's or vendor block page's own
// inline code carries.
var challengeBody = []string{
	"window._cf_chl_opt", "_cf_chl_opt=", "__cf_chl_tk", "cf_chl_prog", "/cdn-cgi/challenge-platform/",
	"sparrow.cloudflare.com/api/v1/event", "cf-footer-ip-reveal", "window._cf_translation",
	"captcha-delivery.com", "_pxappid", "window._pxuuid", "_incapsula_resource",
}

// maxChallengeBody bounds the inline or eval code whose text is read for
// the signs of a challenge. A challenge's inline loader is a few KB; a
// large script with one of those strings is the site's own code that
// handles a challenge, and is kept.
const maxChallengeBody = 64 << 10

// IsChallengeScript reports whether a script belongs to a bot challenge
// rather than to the site:
//   - its URL, or the URL of the script that loaded or evaluated it, is a
//     vendor challenge's (the eval blocks of Cloudflare's VM have no URL;
//     their initiator is the challenge platform);
//   - the page it ran on is a challenge or deny page (pageBlocked): every
//     script of that page is the challenge's;
//   - it is inline or eval code (kind != "file") of at most 64 KB whose text
//     carries a challenge's own markers (window._cf_chl_opt...).
func IsChallengeScript(url, initiatorURL, kind string, body []byte, pageBlocked bool) bool {
	if pageBlocked || ChallengeURL(url) || (initiatorURL != "" && ChallengeURL(initiatorURL)) {
		return true
	}
	if kind == "file" || len(body) == 0 || len(body) > maxChallengeBody {
		return false
	}
	return ChallengeBody(string(body))
}

// ChallengeBody reports whether code carries a challenge's markers. Only
// small inline or eval code should be asked (see IsChallengeScript).
func ChallengeBody(body string) bool {
	l := strings.ToLower(body)
	for _, m := range challengeBody {
		if strings.Contains(l, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// ScriptTags labels a script by its URL alone: "challenge" for a vendor
// challenge's, "cdn-infra" for a CDN helper's. IsChallengeScript also
// knows the initiator, the body and the page.
func ScriptTags(url string) []string {
	switch {
	case ChallengeURL(url):
		return []string{TagChallenge}
	case InfraURL(url):
		return []string{TagCDNInfra}
	}
	return nil
}

// Quarantined reports whether a stored script must stay out of endpoint
// analysis: tagged a challenge or CDN helper, or loaded from such a URL, or
// evaluated by one (an output written before capture dropped them).
func Quarantined(tags, urls, initiators []string) bool {
	for _, t := range tags {
		if t == TagChallenge || t == TagCDNInfra {
			return true
		}
	}
	for _, u := range urls {
		if ChallengeURL(u) || InfraURL(u) {
			return true
		}
	}
	for _, u := range initiators {
		if ChallengeURL(u) {
			return true
		}
	}
	return false
}
