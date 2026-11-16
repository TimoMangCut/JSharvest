package archive

import (
	"regexp"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
)

// sameEndpoint reports whether two catalog endpoints are one: a method
// (or none named), a host (or the page's own), and paths whose segments
// agree, a placeholder agreeing with anything. A path relative to an
// unknown base ({}/x) agrees with the end of the other.
func sameEndpoint(a, b endpoints.Endpoint) bool {
	if a.Method != "" && b.Method != "" && !strings.EqualFold(a.Method, b.Method) {
		return false
	}
	if a.Host != "" && b.Host != "" && !strings.EqualFold(a.Host, b.Host) {
		return false
	}
	for _, pa := range paths(a) {
		for _, pb := range paths(b) {
			if samePath(pa, pb) {
				return true
			}
		}
	}
	return false
}

// paths are an endpoint's full paths: with its base, each candidate base,
// and as it is.
func paths(e endpoints.Endpoint) []string {
	out := []string{e.Path}
	if e.Base != "" {
		out = append(out, e.Base+e.Path)
	}
	for _, b := range e.Bases {
		out = append(out, b+e.Path)
	}
	return out
}

// samePath reports whether two path templates are one path: segment by
// segment, a placeholder agreeing with any, and at least one segment
// named alike in both (two templates of placeholders say nothing). A
// path after a base the code computes ({}/x) is compared with the end of
// the other; there its named segments must be named in the other too:
// {}/customer-profiles/webpush-reset is no /apps/{}/scopes/{}/{}.
func samePath(a, b string) bool {
	sa, sb := split(a), split(b)
	tail := false
	if len(sa) > 0 && isPlace(sa[0]) && len(sa) < len(sb) {
		sb = sb[len(sb)-len(sa)+1:]
		sa = sa[1:]
		tail = true
	} else if len(sb) > 0 && isPlace(sb[0]) && len(sb) < len(sa) {
		sa, sb = sb[1:], sa[len(sa)-len(sb)+1:]
		tail = true
	}
	if len(sa) != len(sb) {
		return false
	}
	named := false
	for i := range sa {
		pa, pb := isPlace(sa[i]), isPlace(sb[i])
		switch {
		case !pa && !pb && sa[i] != sb[i]:
			return false
		case tail && !pa && pb:
			return false // the tail's named segment against a placeholder
		case !pa && !pb && !versionSeg.MatchString(sa[i]):
			named = true
		}
	}
	return named
}

// versionSeg is an API's version segment: v1, v2.0. Shared by most paths,
// it tells no two apart.
var versionSeg = regexp.MustCompile(`^v\d+(\.\d+)*$`)

func split(p string) []string {
	p, _, _ = strings.Cut(p, "?")
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func isPlace(seg string) bool { return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") }

// generic reports whether a template says too little to tell (fewer than
// two fixed segments: /api/{} of a wrapper), as the role diff has it.
func generic(e endpoints.Endpoint) bool {
	full := e.Base + e.Path
	if e.Base == "" && len(e.Bases) > 0 {
		full = e.Bases[0] + e.Path
	}
	fixed := 0
	for _, s := range split(full) {
		if !strings.Contains(s, "{") {
			fixed++
		}
	}
	return fixed < 2
}

// SameEndpoint reports whether two catalog endpoints are one, by template:
// a placeholder agrees with any segment, an empty method or host with any.
func SameEndpoint(a, b endpoints.Endpoint) bool { return sameEndpoint(a, b) }

// Generic reports whether a template says too little to match by (fewer
// than two fixed segments).
func Generic(e endpoints.Endpoint) bool { return generic(e) }
