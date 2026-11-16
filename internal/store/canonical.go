package store

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// A short content hash before the extension, as Rollup/Vite (base64url,
	// which may itself contain "-" or "_") and esbuild/Angular (uppercase
	// base32) emit it: index-tkF5t2Ua.js, index-D-eBaYxL.js, chunk-LADWWXNY.js.
	shortHashRe = regexp.MustCompile(`^(.+)-([A-Za-z0-9_-]{8})(\.[mc]?js)$`)
	// A hex hash between separators, as webpack and Next.js emit it:
	// main.7b54536e.js, 16.a8b9b39f.chunk.js, page-e3e3e3122d5a64cf.js.
	hexHashRe = regexp.MustCompile(`([.-])([0-9a-f]{6,64})([.-])`)
	// A whole path segment that is an id, such as the Next.js build id.
	idSegmentRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	base32Re    = regexp.MustCompile(`^[A-Z2-7]{8}$`)
	// A CamelCase word, such as a component name: HomePage, CheckBox.
	camelRe = regexp.MustCompile(`^(?:[A-Z][a-z]+)+$`)
)

// CanonicalKey returns host+path with build hashes replaced by "[h]" and the
// query and fragment dropped, so that the versions of one file across builds
// share a key. It returns "" for a value that is not an absolute URL.
func CanonicalKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	segs := strings.Split(u.Path, "/")
	for i, seg := range segs {
		if i == len(segs)-1 {
			segs[i] = canonicalName(seg)
		} else if idSegmentRe.MatchString(seg) && hasDigit(seg) && hasLetter(seg) {
			segs[i] = "[h]"
		}
	}
	return strings.ToLower(u.Host) + strings.Join(segs, "/")
}

func canonicalName(name string) string {
	if m := shortHashRe.FindStringSubmatch(name); m != nil && isShortHash(m[2]) {
		return m[1] + "-[h]" + m[3]
	}
	// Replace in a loop: adjacent hashes share a separator, which a single
	// ReplaceAll pass would consume.
	for {
		out := hexHashRe.ReplaceAllStringFunc(name, func(s string) string {
			tok := s[1 : len(s)-1]
			if !hasDigit(tok) || !hasLetter(tok) {
				return s
			}
			return s[:1] + "[h]" + s[len(s)-1:]
		})
		if out == name {
			return out
		}
		name = out
	}
}

// isShortHash tells an 8-character hash from an 8-letter word: a hash has a
// digit, mixes cases, or is uppercase base32. A digit is not required: about
// a quarter of Rollup's 8-character hashes ((54/64)^8) have none. "settings" and CamelCase
// words such as "HomePage" stay; so would a hash that happens to read as
// either: about 1% of random 8-character hashes read as CamelCase (measured
// over 10^6 samples) and stay unnormalised, which only breaks the version
// chain of that file.
func isShortHash(tok string) bool {
	if camelRe.MatchString(tok) {
		return false
	}
	return hasDigit(tok) || (strings.ToLower(tok) != tok && strings.ToUpper(tok) != tok) || base32Re.MatchString(tok)
}

func hasDigit(s string) bool {
	return strings.ContainsAny(s, "0123456789")
}

func hasLetter(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') })
}
