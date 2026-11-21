// Package marker names the code jsharvest puts into a page (round 25I,
// docs/research-2026-11-13-bot-transport.md N0). A page sees those names
// (a sourceURL in its stack traces, a Symbol.for key): they are neutral,
// never the tool's name. The capture and the flow builder still know the
// names of default and older runs (Legacy), whose outputs are read again.
package marker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// seed may be set at build time via:
// -ldflags "-X github.com/TimoMangCut/JSharvest/internal/marker.seed=..."
var seed = ""

const (
	defaultInternal   = "rt-4f9c2a.js"
	defaultTagger     = "pf-8d1e7b.js"
	defaultTaggerKey  = "pf.8d1e7b"
	defaultTaskPrefix = "pf8d1e7b:"

	LegacyTaskPrefix = "jsh:"

	legacyInternal = "jsharvest-internal"
	legacyTagger   = "jsharvest-tagger"
)

var (
	// Internal is the sourceURL of the code jsharvest evaluates: the
	// resolver's fetch, explore's helpers, the guard's socket stub, the
	// session's storage restore, the action reporter.
	Internal string
	// Tagger is the sourceURL of the action tagger's wrappers, which run
	// under the page's own handlers (capture/actions.go).
	Tagger string
	// TaggerKey is the Symbol.for key the tagger sets once installed.
	TaggerKey string
	// TaskPrefix starts the console.createTask names the tagger gives an
	// action's handlers and timers (flow reads them back from async
	// stacks). LegacyTaskPrefix is the older runs'.
	TaskPrefix string
)

func init() {
	Internal, Tagger, TaggerKey, TaskPrefix = derive(seed)
}

func derive(s string) (internal, tagger, taggerKey, taskPrefix string) {
	if s == "" {
		return defaultInternal, defaultTagger, defaultTaggerKey, defaultTaskPrefix
	}
	sum := sha256.Sum256([]byte("jsharvest-marker:" + s))
	h := hex.EncodeToString(sum[:])
	a, b := h[0:6], h[6:12]
	if a == b {
		b = h[12:18]
	}
	return "rt-" + a + ".js", "pf-" + b + ".js", "pf." + b, "pf" + b + ":"
}

// IsInternal reports whether a script or stack frame URL is jsharvest's own
// evaluated code, of this build, the default build, or an older version.
func IsInternal(url string) bool {
	return url == Internal || url == defaultInternal || url == legacyInternal
}

// IsTagger reports whether a URL is the action tagger's.
func IsTagger(url string) bool {
	return url == Tagger || url == defaultTagger || url == legacyTagger
}

// InSource reports whether a script's source carries one of the markers.
func InSource(src string) bool {
	for _, n := range []string{Internal, Tagger, defaultInternal, defaultTagger, legacyInternal, legacyTagger} {
		if strings.Contains(src, "sourceURL="+n) {
			return true
		}
	}
	return false
}

// CutTaskPrefix strips any recognized tagger task prefix (current build,
// default unseeded build, or legacy "jsh:") from d.
func CutTaskPrefix(d string) (string, bool) {
	for _, p := range []string{TaskPrefix, defaultTaskPrefix, LegacyTaskPrefix} {
		if rest, ok := strings.CutPrefix(d, p); ok {
			return rest, true
		}
	}
	return d, false
}

// Slug is a random path segment of lowercase letters and digits, for a
// path that cannot exist (the SPA check, verify's canaries): what any
// route parameter looks like, never the tool's name.
func Slug() string {
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b [12]byte
	rand.Read(b[:])
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = abc[int(c)%len(abc)]
	}
	// A letter first: a path segment of digits reads as an id to some
	// routers, which then answer as for a missing item, not a missing route.
	out[0] = abc[int(b[0])%26]
	return string(out)
}

// FallbackUA is the User-Agent of a stable desktop Chrome, sent when no
// browser of the run said its own: never a library's default
// (Go-http-client), never the tool's name.
const FallbackUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

// SampleEmail is the address a draft or a form gets for an email field.
const SampleEmail = "test.user@example.com"
