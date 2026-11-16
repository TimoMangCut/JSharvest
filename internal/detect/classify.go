package detect

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// BlockKind is what a vendor's answer says of a request (rounds 25H/25J,
// docs/gd6-waf-design.md sections 27-29). A block is the CDN's or WAF's
// answer, not the application's: it tells nothing of the route. Every
// caller reads the same kinds: the replay Sender, the HTTP engine, the
// browser frontier.
type BlockKind string

const (
	// BlockRequest: a rule matched this request (Cloudflare 1020, a WAF's
	// "Sorry, you have been blocked" or deny page for one URL or payload).
	// Other requests may still pass; a browser would be refused alike.
	BlockRequest BlockKind = "request"
	// BlockClient: the vendor says the client is refused (Cloudflare
	// 1005-1009 and 1012: "your IP address has been banned"). Seen to
	// depend on the client all the same: on 2026-11-12 Chrome passed where
	// a Go client got 1006 from the same IP within seconds (round 25I), so
	// it is never taken as an IP ban on its own word.
	BlockClient BlockKind = "client"
	// BlockSignature: the client's signature is refused (Cloudflare 1010);
	// a browser may still pass.
	BlockSignature BlockKind = "signature"
	// BlockChallenge: an interstitial a browser must solve (cf-mitigated,
	// "Just a moment", a captcha).
	BlockChallenge BlockKind = "challenge"
	// BlockRate: slow down (429, Cloudflare 1015, 503 with Retry-After).
	BlockRate BlockKind = "rate"
)

// BrowserMayPass reports whether a browser could get past a block of this
// kind where the client that met it could not: a challenge to solve, a
// signature refused. A rule or a rate limit refuse a browser alike:
// escalating to Chrome for them is a wasted launch (portal.example.biz,
// "Sorry, you have been blocked", escalated twice in vain).
//
// A client ban (1006) is the edge: on 2026-11-12 it depended on the client
// (the Sender's Go-http-client was refused where Chrome passed), but that
// client said what it was; the HTTP engine has always sent a browser's
// User-Agent, and since round 25K the browser's own version and client
// hints, so a 1006 it meets is taken as one Chrome would meet too.
func (k BlockKind) BrowserMayPass() bool { return k == BlockChallenge || k == BlockSignature }

// Block is a vendor's answer in place of the application's.
type Block struct {
	Kind     BlockKind `json:"kind"`
	Vendor   string    `json:"vendor,omitempty"`
	Code     string    `json:"code,omitempty"` // Cloudflare's 1xxx
	Evidence []string  `json:"evidence,omitempty"`
	// RetryAfter is what a rate answer asks to wait (0: not said).
	RetryAfter time.Duration `json:"retry_after,omitempty"`
}

func (b *Block) String() string {
	if b == nil {
		return ""
	}
	s := string(b.Kind) + " block"
	if b.Vendor != "" {
		s = b.Vendor + " " + s
	}
	if b.Code != "" {
		s += " (error " + b.Code + ")"
	} else if len(b.Evidence) > 0 {
		s += " (" + strings.Join(b.Evidence, ", ") + ")"
	}
	return s
}

// cfCodeRe finds Cloudflare's error code on its 1xxx pages: "Error 1006",
// "Error code 1020", <span class="cf-error-code">1015</span>, the
// documentation link's /error-1010/, or the plain-text "error code: 1006".
var cfCodeRe = regexp.MustCompile(`(?i)(?:error(?:\s+code)?[\s:#]*|cf-error-code"?>\s*|/error-)(1\d{3})\b`)

// wafBlockRe is a WAF's "you have been blocked" page: Cloudflare's
// "Attention Required! | Cloudflare" with "Sorry, you have been blocked"
// is a rule that blocked, not a challenge a browser can pass.
var wafBlockRe = regexp.MustCompile(`(?i)sorry, you have been blocked|you are unable to access`)

// challengeRe are the signs of an interstitial a browser must solve.
var challengeRe = regexp.MustCompile(`(?i)just a moment|captcha-delivery\.com|px-captcha|please verify you are a human|_cf_chl_opt|/cdn-cgi/challenge-platform/h/[a-z]/(?:orchestrate|turnstile)`)

// wafRe is a WAF's page on a 403 that no vendor rule names.
var wafRe = regexp.MustCompile(`(?i)attention required|cloudflare ray id|access denied.{0,80}(incapsula|akamai|imperva)|request (was )?blocked|sucuri website firewall|web application firewall|_incapsula_resource|errors\.edgesuite\.net`)

// Classify says whether a response is a vendor's block, and what kind; nil
// when it is the application's own (its 403 included). d.Headers are
// lower-case; d.Title is the caller's to read from HTML (this package
// parses none); d.Body is the head of the body (64 KB is plenty).
func Classify(d Doc) *Block {
	hdr := func(k string) string { return d.Headers[k] }
	body := []byte(d.Body)
	switch {
	case d.Status == http.StatusTooManyRequests:
		b := &Block{Kind: BlockRate, Evidence: []string{"429"}, RetryAfter: RetryAfter(hdr("retry-after"))}
		if m := cfCodeRe.FindSubmatch(body); m != nil {
			b.Vendor, b.Code = Cloudflare, string(m[1])
		}
		return b
	case d.Status == http.StatusServiceUnavailable && hdr("retry-after") != "":
		return &Block{Kind: BlockRate, Evidence: []string{"503 with Retry-After"}, RetryAfter: RetryAfter(hdr("retry-after"))}
	case hdr("cf-mitigated") != "":
		return &Block{Kind: BlockChallenge, Vendor: Cloudflare, Evidence: []string{"cf-mitigated: " + hdr("cf-mitigated")}}
	}
	if blk := Check(d); blk.Blocked {
		b := &Block{Kind: BlockRequest, Vendor: blk.Vendor, Evidence: blk.Evidence}
		if m := cfCodeRe.FindSubmatch(body); m != nil && (blk.Vendor == Cloudflare || blk.Vendor == "") {
			b.Code = string(m[1])
			switch b.Code {
			case "1005", "1006", "1007", "1008", "1009", "1012":
				b.Kind = BlockClient
			case "1010":
				b.Kind = BlockSignature
			case "1015":
				b.Kind = BlockRate
				b.RetryAfter = RetryAfter(hdr("retry-after"))
			}
		}
		if b.Kind == BlockRequest && b.Code == "" && !wafBlockRe.Match(body) &&
			(challengeRe.Match(body) || challengeRe.MatchString(d.Title)) {
			b.Kind = BlockChallenge
		}
		return b
	}
	if d.Status == http.StatusForbidden && (wafRe.Match(body[:min(len(body), 4096)]) || wafRe.MatchString(d.Title)) {
		return &Block{Kind: BlockRequest, Evidence: []string{"403 with a WAF's page"}}
	}
	return nil
}

// RetryAfter reads a Retry-After value: seconds, or an HTTP date.
func RetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
