package export

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/flow"
)

// Param is a place in a raw request where a fuzzer puts its input. Start
// and End are the bytes of its value in the raw request as written: the
// value as encoded there (a%20b, a JSON string's escapes), so that putting
// a keyword in its place changes nothing else.
type Param struct {
	In    string // path, query, header, cookie, json, form, multipart
	Name  string // path: "seg<N>"; json: a path as flow writes it ($.a[0].b)
	Index int    // path: the segment, from 1 after trimming the slashes (as flow's path:N)
	Value string // decoded
	Start int
	End   int
}

// At is where flow's values say the param is (Link.At), "" when they have
// no such place.
func (p Param) At() string {
	switch p.In {
	case "path":
		return "path:" + strconv.Itoa(p.Index)
	case "query", "form":
		return p.In + ":" + p.Name
	case "header":
		return "header:" + strings.ToLower(p.Name)
	case "json":
		return "body:" + p.Name
	}
	return ""
}

const maxParams = 200

// Params reads the params of a raw request as RawRequest writes it.
func Params(raw []byte) []Param {
	var out []Param
	add := func(p Param) {
		if len(out) < maxParams {
			out = append(out, p)
		}
	}
	lineEnd := bytes.Index(raw, []byte("\r\n"))
	if lineEnd < 0 {
		return nil
	}
	sp := bytes.IndexByte(raw[:lineEnd], ' ')
	last := bytes.LastIndexByte(raw[:lineEnd], ' ')
	if sp < 0 || last <= sp {
		return nil
	}
	tStart, target := sp+1, string(raw[sp+1:last])
	pathPart, query, hasQuery := strings.Cut(target, "?")

	// Path segments, numbered as flow numbers them: after trimming the
	// slashes at both ends.
	trimmed := strings.TrimLeft(pathPart, "/")
	off := tStart + len(pathPart) - len(trimmed)
	trimmed = strings.TrimRight(trimmed, "/")
	if trimmed != "" {
		for i, seg := range strings.Split(trimmed, "/") {
			v, err := url.PathUnescape(seg)
			if err != nil {
				v = seg
			}
			add(Param{In: "path", Name: "seg" + strconv.Itoa(i+1), Index: i + 1, Value: v, Start: off, End: off + len(seg)})
			off += len(seg) + 1
		}
	}
	if hasQuery {
		pairs(query, tStart+len(pathPart)+1, "query", add)
	}

	// Headers, up to the blank line.
	head := bytes.Index(raw, []byte("\r\n\r\n"))
	if head < 0 {
		return out
	}
	contentType := ""
	for pos := lineEnd + 2; pos < head; {
		end := pos + bytes.Index(raw[pos:], []byte("\r\n"))
		line := string(raw[pos:end])
		name, value, ok := strings.Cut(line, ": ")
		vStart := pos + len(name) + 2
		pos = end + 2
		if !ok {
			continue
		}
		lower := strings.ToLower(name)
		switch {
		case lower == "content-type":
			contentType = value
		case lower == "cookie":
			// Split at each ";", spaces or none after it: a file written
			// by hand may say a=1;b=2.
			o := vStart
			for _, c := range strings.Split(value, ";") {
				lead := len(c) - len(strings.TrimLeft(c, " "))
				if n, v, ok := strings.Cut(c[lead:], "="); ok {
					start := o + lead + len(n) + 1
					add(Param{In: "cookie", Name: n, Value: strings.TrimRight(v, " "), Start: start, End: start + len(strings.TrimRight(v, " "))})
				}
				o += len(c) + 1
			}
		case lower == "host" || lower == "content-length" || flow.PlainHeader(lower):
		default:
			add(Param{In: "header", Name: lower, Value: value, Start: vStart, End: vStart + len(value)})
		}
	}

	body, bStart := raw[head+4:], head+4
	if len(body) == 0 {
		return out
	}
	mt, mp, _ := mime.ParseMediaType(contentType)
	trim := bytes.TrimSpace(body)
	switch {
	case strings.Contains(mt, "json") || bytes.HasPrefix(trim, []byte("{")) || bytes.HasPrefix(trim, []byte("[")):
		s := &jscan{b: body, base: bStart, add: add}
		s.ws()
		s.value("$", 0)
	case strings.HasPrefix(mt, "multipart/") && mp["boundary"] != "":
		multipart(body, bStart, mp["boundary"], add)
	case mt == "application/x-www-form-urlencoded" || ((mt == "" || mt == "text/plain") && formRe.Match(body)):
		pairs(string(body), bStart, "form", add)
	}
	return out
}

var formRe = regexp.MustCompile(`^[\w.\[\]%-]+=[^\s]*$`)

// pairs reads a=1&b=2 that starts at off.
func pairs(s string, off int, in string, add func(Param)) {
	for _, kv := range strings.Split(s, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if k != "" {
			name, err := url.QueryUnescape(k)
			if err != nil {
				name = k
			}
			dv, err := url.QueryUnescape(v)
			if err != nil {
				dv = v
			}
			start := off + len(k)
			if strings.Contains(kv, "=") {
				start++
			}
			add(Param{In: in, Name: name, Value: dv, Start: start, End: off + len(kv)})
			if in == "query" {
				scanQueryJSON(v, start, name, add)
			}
		}
		off += len(kv) + 1
	}
}

func scanQueryJSON(rawVal string, valStart int, name string, add func(Param)) {
	dec, offs, ok := unescapeQueryWithOffsets(rawVal)
	if !ok || len(dec) < 2 {
		return
	}
	if !((dec[0] == '{' && dec[len(dec)-1] == '}') || (dec[0] == '[' && dec[len(dec)-1] == ']')) {
		return
	}
	if !json.Valid([]byte(dec)) {
		return
	}
	s := &jscan{
		b:    []byte(dec),
		base: 0,
		add: func(jp Param) {
			if jp.In != "json" || jp.Start < 0 || jp.End > len(dec) {
				return
			}
			add(Param{
				In:    "query",
				Name:  name + jp.Name,
				Value: jp.Value,
				Start: valStart + offs[jp.Start],
				End:   valStart + offs[jp.End],
			})
		},
	}
	s.ws()
	s.value("$", 0)
}

func unescapeQueryWithOffsets(s string) (string, []int, bool) {
	var b strings.Builder
	offs := make([]int, 0, len(s)+1)
	for i := 0; i < len(s); {
		offs = append(offs, i)
		switch s[i] {
		case '%':
			if i+2 >= len(s) {
				return "", nil, false
			}
			hi, ok1 := fromHex(s[i+1])
			lo, ok2 := fromHex(s[i+2])
			if !ok1 || !ok2 {
				return "", nil, false
			}
			b.WriteByte(hi<<4 | lo)
			i += 3
		case '+':
			b.WriteByte(' ')
			i++
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	offs = append(offs, len(s))
	return b.String(), offs, true
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

var (
	partNameRe = regexp.MustCompile(`(?i)\bname="([^"]*)"`)
	fileNameRe = regexp.MustCompile(`(?i)\bfilename="([^"]*)"`)
)

// multipart reads the fields of a multipart body; of a file, its name.
func multipart(body []byte, off int, boundary string, add func(Param)) {
	delim := []byte("--" + boundary)
	pos := bytes.Index(body, delim)
	for pos >= 0 {
		start := pos + len(delim)
		next := bytes.Index(body[start:], delim)
		if next < 0 {
			return
		}
		part := body[start : start+next]
		if h := bytes.Index(part, []byte("\r\n\r\n")); h >= 0 {
			header := string(part[:h])
			value := bytes.TrimSuffix(part[h+4:], []byte("\r\n"))
			vStart := off + start + h + 4
			if m := partNameRe.FindStringSubmatchIndex(header); m != nil {
				name := header[m[2]:m[3]]
				if f := fileNameRe.FindStringSubmatchIndex(header); f != nil {
					hs := off + start
					add(Param{In: "multipart", Name: name + ".filename", Value: header[f[2]:f[3]], Start: hs + f[2], End: hs + f[3]})
				} else {
					add(Param{In: "multipart", Name: name, Value: string(value), Start: vStart, End: vStart + len(value)})
				}
			}
		}
		pos = start + next
	}
}

// jscan reads JSON for the spans of its values; it stops quietly at what
// is not JSON (a body the recorder cut).
type jscan struct {
	b    []byte
	i    int
	base int
	add  func(Param)
	bad  bool
}

func (s *jscan) ws() {
	for s.i < len(s.b) && strings.IndexByte(" \t\r\n", s.b[s.i]) >= 0 {
		s.i++
	}
}

func (s *jscan) value(path string, depth int) {
	if s.bad || s.i >= len(s.b) || depth > 20 {
		s.bad = true
		return
	}
	switch c := s.b[s.i]; {
	case c == '{':
		s.i++
		s.ws()
		if s.i < len(s.b) && s.b[s.i] == '}' {
			s.i++
			return
		}
		for !s.bad {
			s.ws()
			start, end, ok := s.str()
			if !ok {
				s.bad = true
				return
			}
			var key string
			if json.Unmarshal(s.b[start-1:end+1], &key) != nil {
				s.bad = true
				return
			}
			s.ws()
			if s.i >= len(s.b) || s.b[s.i] != ':' {
				s.bad = true
				return
			}
			s.i++
			s.ws()
			s.value(path+"."+key, depth+1)
			s.ws()
			if s.i < len(s.b) && s.b[s.i] == ',' {
				s.i++
				continue
			}
			if s.i < len(s.b) && s.b[s.i] == '}' {
				s.i++
				return
			}
			s.bad = true
		}
	case c == '[':
		s.i++
		s.ws()
		if s.i < len(s.b) && s.b[s.i] == ']' {
			s.i++
			return
		}
		for n := 0; !s.bad; n++ {
			s.ws()
			s.value(path+"["+strconv.Itoa(n)+"]", depth+1)
			s.ws()
			if s.i < len(s.b) && s.b[s.i] == ',' {
				s.i++
				continue
			}
			if s.i < len(s.b) && s.b[s.i] == ']' {
				s.i++
				return
			}
			s.bad = true
		}
	case c == '"':
		start, end, ok := s.str()
		if !ok {
			s.bad = true
			return
		}
		var v string
		if json.Unmarshal(s.b[start-1:end+1], &v) != nil {
			s.bad = true
			return
		}
		s.add(Param{In: "json", Name: path, Value: v, Start: s.base + start, End: s.base + end})
	default:
		start := s.i
		for s.i < len(s.b) && strings.IndexByte(",]} \t\r\n", s.b[s.i]) < 0 {
			s.i++
		}
		tok := string(s.b[start:s.i])
		if tok == "" || (tok != "true" && tok != "false" && tok != "null" && !numRe.MatchString(tok)) {
			s.bad = true
			return
		}
		s.add(Param{In: "json", Name: path, Value: tok, Start: s.base + start, End: s.base + s.i})
	}
}

var numRe = regexp.MustCompile(`^-?\d+(\.\d+)?([eE][-+]?\d+)?$`)

// str reads a JSON string at s.i: the bytes between its quotes.
func (s *jscan) str() (start, end int, ok bool) {
	if s.i >= len(s.b) || s.b[s.i] != '"' {
		return 0, 0, false
	}
	start = s.i + 1
	for j := start; j < len(s.b); j++ {
		switch s.b[j] {
		case '\\':
			j++
		case '"':
			s.i = j + 1
			return start, j, true
		}
	}
	return 0, 0, false
}
