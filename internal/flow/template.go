// Package flow groups a run's requests by the action that caused them, and
// describes each group for fuzzing: endpoint templates, and which request
// carries a value from which earlier response. It is pure: the capture and
// the engine feed it, and it does no I/O.
package flow

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var (
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	ulidRe   = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	b64Re    = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
	jwtRe    = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	emailRe  = regexp.MustCompile(`^[^@/\s]+@[^@/\s]+\.[A-Za-z]{2,}$`)
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(T[\d:.]+Z?)?$`)
	numberRe = regexp.MustCompile(`^\d+$`)
)

// Segment returns the placeholder for a path segment that is a value, not a
// name, or "" when it reads as a name.
func Segment(s string) string {
	switch {
	case s == "":
		return ""
	case numberRe.MatchString(s):
		return "{id}"
	case uuidRe.MatchString(s), ulidRe.MatchString(s):
		return "{uuid}"
	case jwtRe.MatchString(s):
		return "{token}"
	case emailRe.MatchString(s):
		return "{email}"
	case dateRe.MatchString(s):
		return "{date}"
	case hexRe.MatchString(s) && strings.ContainsAny(s, "0123456789"):
		return "{hash}"
	case b64Re.MatchString(s) && mixed(s):
		return "{hash}"
	}
	return ""
}

// mixed reports whether s has upper case, lower case and digits, as an
// encoded value does and a slug does not.
func mixed(s string) bool {
	var up, low, digit bool
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= 'a' && r <= 'z':
			low = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	return up && low && digit
}

// Path is a URL path split into segments; the first is empty for the root.
func segments(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

// ByShape is the template of a path by the segment rules alone.
func ByShape(p string) string {
	segs := segments(p)
	for i, s := range segs {
		if ph := Segment(s); ph != "" {
			segs[i] = ph
		}
	}
	return "/" + strings.Join(segs, "/")
}

// Call is what the template inference needs of one request.
type Call struct {
	Method string
	URL    string
	Frame  string // the first application frame, or ""
}

// Templates returns the endpoint template of each call. It applies the
// segment rules, then one rule of its own: calls made from the same frame
// of the application, with the same method, host and number of segments,
// that differ in exactly one segment, differ in a parameter there, whatever
// its shape (/api/projects/my-first/settings, /api/projects/demo/settings).
func Templates(calls []Call) []string {
	type key struct {
		method, host, frame string
		n                   int
	}
	shapes := make([][]string, len(calls))
	groups := map[key][]int{}
	for i, c := range calls {
		u, err := url.Parse(c.URL)
		if err != nil {
			continue
		}
		segs := segments(ByShape(u.EscapedPath()))
		shapes[i] = segs
		if c.Frame != "" {
			k := key{c.Method, u.Host, c.Frame, len(segs)}
			groups[k] = append(groups[k], i)
		}
	}
	for _, idx := range groups {
		if pos, ok := oneVarying(shapes, idx); ok {
			for _, i := range idx {
				shapes[i][pos] = "{param}"
			}
		}
	}
	out := make([]string, len(calls))
	for i, s := range shapes {
		if s != nil {
			out[i] = "/" + strings.Join(s, "/")
		}
	}
	return out
}

// oneVarying reports the one position where the shapes of idx differ, when
// there is exactly one, it takes at least minValues values (two samples
// could be two endpoints a generic loader serves), and some other position
// is a fixed name.
func oneVarying(shapes [][]string, idx []int) (int, bool) {
	const minValues = 3
	if len(idx) < minValues {
		return 0, false
	}
	first := shapes[idx[0]]
	pos, fixedName := -1, false
	for k := range first {
		varies := slices.ContainsFunc(idx[1:], func(i int) bool { return shapes[i][k] != first[k] })
		switch {
		case varies && pos >= 0:
			return 0, false
		case varies:
			pos = k
		case !strings.HasPrefix(first[k], "{"):
			fixedName = true
		}
	}
	if pos < 0 || !fixedName {
		return 0, false
	}
	values := map[string]bool{}
	for _, i := range idx {
		values[shapes[i][pos]] = true
	}
	return pos, len(values) >= minValues
}
