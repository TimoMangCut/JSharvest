// Package secretsig recognizes high-precision vendor API key and token
// signatures by fixed prefix, strict character set, exact/bounded length,
// and token boundaries. No blind entropy scanning is performed.
package secretsig

import (
	"regexp"
	"sort"
	"strings"
)

// Match is one vendor secret found in a string.
type Match struct {
	Kind  string
	Value string
	Start int
	End   int
}

type rule struct {
	kind       string
	hints      []string
	re         *regexp.Regexp
	flankLeft  func(byte) bool
	flankRight func(byte) bool
	body       func(string) string
}

func isWordByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_'
}

func isURLSafeTokenByte(b byte) bool {
	return isWordByte(b) || b == '-'
}

func isDotTokenByte(b byte) bool {
	return isURLSafeTokenByte(b) || b == '.'
}

var rules = []rule{
	{
		kind:       "google_api_key",
		hints:      []string{"AIza"},
		re:         regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		flankLeft:  isURLSafeTokenByte,
		flankRight: isURLSafeTokenByte,
		body:       func(s string) string { return s[4:] },
	},
	{
		kind:       "aws_access_key_id",
		hints:      []string{"AKIA", "ASIA"},
		re:         regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
		flankLeft:  isWordByte,
		flankRight: isWordByte,
		body:       func(s string) string { return s[4:] },
	},
	{
		kind:       "stripe_key",
		hints:      []string{"_live_", "_test_"},
		re:         regexp.MustCompile(`(?:pk|sk|rk)_(?:live|test)_[0-9A-Za-z]{16,99}`),
		flankLeft:  isWordByte,
		flankRight: isWordByte,
		body:       func(s string) string { return s[8:] },
	},
	{
		kind:       "github_token",
		hints:      []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		re:         regexp.MustCompile(`(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})`),
		flankLeft:  isWordByte,
		flankRight: isWordByte,
		body: func(s string) string {
			if strings.HasPrefix(s, "github_pat_") {
				return s[11:]
			}
			return s[4:]
		},
	},
	{
		kind:       "slack_token",
		hints:      []string{"xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"},
		re:         regexp.MustCompile(`xox[abprs]-[0-9]{10,13}-[0-9A-Za-z-]{10,128}`),
		flankLeft:  isURLSafeTokenByte,
		flankRight: isURLSafeTokenByte,
		body:       func(s string) string { return s[5:] },
	},
	{
		kind:       "sendgrid_key",
		hints:      []string{"SG."},
		re:         regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
		flankLeft:  isDotTokenByte,
		flankRight: isDotTokenByte,
		body:       func(s string) string { return s[3:] },
	},
	{
		kind:       "mapbox_token",
		hints:      []string{"pk.eyJ", "sk.eyJ"},
		re:         regexp.MustCompile(`(?:pk|sk)\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`),
		flankLeft:  isDotTokenByte,
		flankRight: isDotTokenByte,
		body:       func(s string) string { return s[6:] },
	},
	{
		kind:       "sentry_dsn",
		hints:      []string{".sentry.io/"},
		re:         regexp.MustCompile(`https://[0-9a-f]{32}@(?:[a-z0-9-]+\.)*ingest(?:\.[a-z]{2})?\.sentry\.io/\d+`),
		flankLeft:  isWordByte,
		flankRight: isWordByte,
		body:       func(s string) string { return s[8:40] },
	},
}

var allHints = func() []string {
	var out []string
	for _, r := range rules {
		out = append(out, r.hints...)
	}
	return out
}()

// HasHint reports whether s contains any vendor secret prefix or domain hint.
func HasHint(s string) bool {
	if len(s) < 20 {
		return false
	}
	for _, h := range allHints {
		if strings.Contains(s, h) {
			return true
		}
	}
	return false
}

func hasAnyHint(s string, hints []string) bool {
	for _, h := range hints {
		if strings.Contains(s, h) {
			return true
		}
	}
	return false
}

var placeholderWords = []string{
	"example",
	"dummy",
	"placeholder",
	"your_api_key",
	"your-api-key",
	"replace_me",
	"changeme",
}

func isPlaceholder(body string) bool {
	low := strings.ToLower(body)
	for _, w := range placeholderWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	// Reject runs of >= 8 identical characters after the prefix (00000000,
	// 11111111, xxxxxxxx, AAAAAAAA).
	run := 1
	for i := 1; i < len(body); i++ {
		if body[i] == body[i-1] {
			run++
			if run >= 8 {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

func scan(s string, keepPlaceholders bool) []Match {
	if !HasHint(s) {
		return nil
	}
	var cands []Match
	for _, r := range rules {
		if !hasAnyHint(s, r.hints) {
			continue
		}
		locs := r.re.FindAllStringIndex(s, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			if start > 0 && r.flankLeft != nil && r.flankLeft(s[start-1]) {
				continue
			}
			if end < len(s) && r.flankRight != nil && r.flankRight(s[end]) {
				continue
			}
			val := s[start:end]
			if !keepPlaceholders && isPlaceholder(r.body(val)) {
				continue
			}
			cands = append(cands, Match{Kind: r.kind, Value: val, Start: start, End: end})
		}
	}
	if len(cands) <= 1 {
		return cands
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Start != cands[j].Start {
			return cands[i].Start < cands[j].Start
		}
		return cands[i].End > cands[j].End
	})
	out := cands[:0]
	prevEnd := -1
	for _, m := range cands {
		if m.Start < prevEnd {
			continue
		}
		out = append(out, m)
		prevEnd = m.End
	}
	return out
}

// FindAll returns all non-placeholder vendor secrets found in s, in order.
func FindAll(s string) []Match {
	return scan(s, false)
}

// ReplaceAllFunc replaces every wire-format vendor secret in s (including
// documentation placeholders) with repl(match).
func ReplaceAllFunc(s string, repl func(string) string) string {
	ms := scan(s, true)
	if len(ms) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	for _, m := range ms {
		b.WriteString(s[pos:m.Start])
		b.WriteString(repl(m.Value))
		pos = m.End
	}
	b.WriteString(s[pos:])
	return b.String()
}
