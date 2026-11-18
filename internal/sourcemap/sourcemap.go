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

const (
	maxInlineMapDataLen  = 44 << 20 // ~33 MiB decoded
	maxSingleSourceBytes = 16 << 20
	maxTotalSourcesBytes = 64 << 20
)

func dataURI(s string) ([]byte, bool) {
	meta, data, ok := strings.Cut(strings.TrimPrefix(s, "data:"), ",")
	if !ok || len(data) > maxInlineMapDataLen {
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
	return m.FilesFor("")
}

// FilesFor is Files, also using scriptURL (when given) to identify
// standalone self-hosted third-party library maps (e.g. ckeditor5.js.map,
// bootstrap.bundle.min.js.map, livewire.js.map, /vendor/.../*.map) whose
// internal module paths do not carry a node_modules/ prefix.
func (m *Map) FilesFor(scriptURL string) []File {
	libScript, libStem := standaloneLibraryInfo(scriptURL)
	var raw []File
	var rawBytes int64
	monorepoHits := 0
	for i, s := range m.Sources {
		if i >= len(m.SourcesContent) || m.SourcesContent[i] == nil || *m.SourcesContent[i] == "" {
			continue
		}
		content := *m.SourcesContent[i]
		if len(content) > maxSingleSourceBytes {
			continue
		}
		if rawBytes+int64(len(content)) > 2*maxTotalSourcesBytes {
			break
		}
		rawBytes += int64(len(content))
		f := File{Path: Clean(m.SourceRoot, s), Content: content}
		f.Vendor = vendorPath(f.Path)
		if !f.Vendor && libStem != "" && hasMonorepoStem(f.Path, libStem) {
			monorepoHits++
		}
		raw = append(raw, f)
	}
	allLibMonorepo := libStem != "" && len(raw) > 0 && monorepoHits*10 >= len(raw)*9
	var own, vendor []File
	for _, f := range raw {
		if !f.Vendor && (libScript || allLibMonorepo || (libStem != "" && hasMonorepoStem(f.Path, libStem))) && !explicitAppSourcePath(f.Path) {
			f.Vendor = true
		}
		if f.Vendor {
			vendor = append(vendor, f)
		} else {
			own = append(own, f)
		}
	}
	out := make([]File, 0, len(own)+len(vendor))
	var keptBytes int64
	for _, f := range own {
		if keptBytes+int64(len(f.Content)) > maxTotalSourcesBytes && len(out) > 0 {
			break
		}
		keptBytes += int64(len(f.Content))
		out = append(out, f)
	}
	for _, f := range vendor {
		if keptBytes+int64(len(f.Content)) > maxTotalSourcesBytes {
			break
		}
		keptBytes += int64(len(f.Content))
		out = append(out, f)
	}
	return out
}

var (
	schemeRe               = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:/*`)
	standaloneVendorDirRe  = regexp.MustCompile(`(?i)/(?:vendors?|bower_components|node_modules|wp-includes/js|javax\.faces\.resource)/`)
	standaloneVendorFileRe = regexp.MustCompile(`(?i)^(?:jquery|bootstrap|ckeditor\d*|tinymce|datatables|jszip|select2|flatpickr|moment(?:-with-locales)?|owl\.carousel|swiper|lodash|underscore|backbone|handlebars|mustache|tabbable|popper|livewire|alpine(?:\.min)?|filepond|chart(?:\.umd)?|d3|three|pdf(?:\.worker)?|prism|highlight)(?:[._-][\w.~-]*)?\.m?js$`)
	genericAppStem         = map[string]bool{
		"main": true, "index": true, "app": true, "bundle": true, "chunk": true,
		"client": true, "page": true, "pages": true, "entry": true, "script": true,
		"scripts": true, "common": true, "shared": true, "core": true, "custom": true,
	}
)

func standaloneLibraryInfo(scriptURL string) (isLib bool, stem string) {
	if scriptURL == "" {
		return false, ""
	}
	p := scriptURL
	if u, err := url.Parse(scriptURL); err == nil && u.Path != "" {
		p = u.Path
	} else if q := strings.IndexAny(p, "?#"); q >= 0 {
		p = p[:q]
	}
	base := path.Base(p)
	if standaloneVendorDirRe.MatchString(p) || standaloneVendorFileRe.MatchString(base) {
		isLib = true
	}
	s := strings.ToLower(base)
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".mjs"), ".js")
	for _, suf := range []string{".min", ".umd", ".esm", ".cjs", ".bundle", ".prod", ".production"} {
		s = strings.TrimSuffix(s, suf)
	}
	if idx := strings.IndexAny(s, "._-"); idx >= 4 {
		s = s[:idx]
	}
	if len(s) >= 4 && !genericAppStem[s] {
		stem = s
	}
	return isLib, stem
}

func hasMonorepoStem(cleanPath, stem string) bool {
	l := strings.ToLower(cleanPath)
	if strings.HasPrefix(l, "packages/"+stem) {
		rest := l[len("packages/"+stem):]
		return rest == "" || rest[0] == '/' || rest[0] == '-' || rest[0] == '_'
	}
	if strings.HasPrefix(l, "packages/@") {
		if _, after, ok := strings.Cut(l[len("packages/@"):], "/"); ok && strings.HasPrefix(after, stem) {
			rest := after[len(stem):]
			return rest == "" || rest[0] == '/' || rest[0] == '-' || rest[0] == '_'
		}
	}
	return false
}

// explicitAppSourcePath keeps an app's own files if a hybrid bundle happens
// to be served from a shared directory.
func explicitAppSourcePath(cleanPath string) bool {
	l := strings.ToLower(cleanPath)
	return strings.HasPrefix(l, "resources/js/") || strings.HasPrefix(l, "resources/ts/") ||
		strings.HasPrefix(l, "client/src/") || strings.HasPrefix(l, "frontend/src/")
}

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
	return strings.Contains(l, "node_modules/") || strings.Contains(l, "bower_components/") ||
		strings.HasPrefix(l, "webpack/") || strings.HasPrefix(l, "(webpack)") ||
		strings.HasPrefix(l, "vendor/") || strings.HasPrefix(l, "vendors/") ||
		strings.Contains(l, "/~/") || strings.HasPrefix(l, "~/") || strings.HasPrefix(l, "vite/") || strings.Contains(l, "\x00")
}
