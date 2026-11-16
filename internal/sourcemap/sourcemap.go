// Package sourcemap finds a script's source map and reads the original
// sources out of it (CF-05). A production build that ships its maps hands
// over the app as written: file names (src/api/userService.ts), constants,
// comments, whole modules the bundle inlined beyond recognition.
package sourcemap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// sourceMappingURLRe is the comment a bundler writes last: //# (or the
// old //@) sourceMappingURL=..., or /*# ... */ in CSS-like form.
var sourceMappingURLRe = regexp.MustCompile(`(?m)(?://|/\*)[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)\s*(?:\*/)?\s*$`)

// Ref is where a script says its map is: a URL, or the map itself inline.
type Ref struct {
	URL    string // absolute; empty for an inline map
	Inline []byte // a data: URI's map
	// Guess: no header or comment names it; <script>.map is a guess.
	Guess bool
}

// Find returns where a script's map is: the SourceMap (or X-SourceMap)
// header, else the last sourceMappingURL comment; with guess, the script's
// URL plus .map when neither says. headers have lowercase keys.
func Find(scriptURL string, headers map[string]string, body []byte, guess bool) (Ref, bool) {
	base, err := url.Parse(scriptURL)
	if err != nil {
		return Ref{}, false
	}
	resolve := func(ref string) (Ref, bool) {
		ref = strings.TrimSpace(ref)
		if strings.HasPrefix(ref, "data:") {
			if b, ok := dataURI(ref); ok {
				return Ref{Inline: b}, true
			}
			return Ref{}, false
		}
		u, err := base.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return Ref{}, false
		}
		u.Fragment = ""
		return Ref{URL: u.String()}, true
	}
	for _, k := range []string{"sourcemap", "x-sourcemap"} {
		if v := headers[k]; v != "" {
			return resolve(v)
		}
	}
	// Only the tail: the comment is the last line, and a bundle is large.
	tail := body
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}
	if m := sourceMappingURLRe.FindAllSubmatch(tail, -1); len(m) > 0 {
		return resolve(string(m[len(m)-1][1]))
	}
	if guess && strings.HasSuffix(strings.ToLower(base.Path), ".js") {
		u := *base
		u.Path += ".map"
		u.RawPath, u.RawQuery, u.Fragment = "", "", ""
		return Ref{URL: u.String(), Guess: true}, true
	}
	return Ref{}, false
}

func dataURI(s string) ([]byte, bool) {
	meta, data, ok := strings.Cut(strings.TrimPrefix(s, "data:"), ",")
	if !ok {
		return nil, false
	}
	if strings.HasSuffix(meta, ";base64") {
		b, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			if b, err = base64.RawStdEncoding.DecodeString(data); err != nil {
				return nil, false
			}
		}
		return b, true
	}
	d, err := url.PathUnescape(data)
	return []byte(d), err == nil
}

// Map is the part of a source map v3 read here.
type Map struct {
	Version        int       `json:"version"`
	File           string    `json:"file"`
	SourceRoot     string    `json:"sourceRoot"`
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
	Sections       []struct {
		Map *Map `json:"map"`
	} `json:"sections"`
}

// ErrNotMap: the answer is not a source map (an SPA's index.html, a 404
// page with a 200).
var ErrNotMap = errors.New("not a source map")

// Parse reads a source map, past an XSSI prefix ()]}'), and flattens an
// indexed map's sections.
func Parse(b []byte) (*Map, error) {
	b = bytes.TrimSpace(b)
	if bytes.HasPrefix(b, []byte(")]}")) {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	if len(b) == 0 || b[0] != '{' {
		return nil, ErrNotMap
	}
	var m Map
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Version != 3 {
		return nil, ErrNotMap
	}
	for _, s := range m.Sections {
		if s.Map == nil {
			continue
		}
		m.Sources = append(m.Sources, s.Map.Sources...)
		content := s.Map.SourcesContent
		for len(content) < len(s.Map.Sources) {
			content = append(content, nil)
		}
		for len(m.SourcesContent) < len(m.Sources)-len(s.Map.Sources) {
			m.SourcesContent = append(m.SourcesContent, nil)
		}
		m.SourcesContent = append(m.SourcesContent, content...)
	}
	if len(m.Sources) == 0 {
		return nil, ErrNotMap
	}
	return &m, nil
}

// File is one original source a map carries.
type File struct {
	Path    string // as the map names it, cleaned (webpack:///./src/a.ts -> src/a.ts)
	Content string
	Vendor  bool // a dependency's (node_modules, webpack's own runtime)
}

// Files returns the sources whose content the map carries, the app's own
// first.
func (m *Map) Files() []File {
	var own, vendor []File
	for i, s := range m.Sources {
		if i >= len(m.SourcesContent) || m.SourcesContent[i] == nil || *m.SourcesContent[i] == "" {
			continue
		}
		f := File{Path: Clean(m.SourceRoot, s), Content: *m.SourcesContent[i]}
		f.Vendor = vendorPath(f.Path)
		if f.Vendor {
			vendor = append(vendor, f)
		} else {
			own = append(own, f)
		}
	}
	return append(own, vendor...)
}

var schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:/*`)

// Clean makes a source's name a plain relative path: no webpack:// or
// file:// scheme, no ./ or ../ in front, no query (webpack's ?xxxx).
func Clean(root, s string) string {
	if root != "" && !schemeRe.MatchString(s) && !strings.HasPrefix(s, "/") {
		s = strings.TrimSuffix(root, "/") + "/" + s
	}
	s = schemeRe.ReplaceAllString(s, "")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = path.Clean("/" + s)
	s = strings.TrimPrefix(s, "/")
	for strings.HasPrefix(s, "../") {
		s = s[3:]
	}
	// webpack:///webpack/bootstrap, webpack:///(webpack)/buildin/...
	return s
}

func vendorPath(p string) bool {
	l := strings.ToLower(p)
	return strings.Contains(l, "node_modules/") || strings.HasPrefix(l, "webpack/") || strings.HasPrefix(l, "(webpack)") ||
		strings.Contains(l, "/~/") || strings.HasPrefix(l, "~/") || strings.HasPrefix(l, "vite/") || strings.Contains(l, "\x00")
}
