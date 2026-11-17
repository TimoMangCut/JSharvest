// Package replay sends recorded requests again: a flow in order, with
// the values earlier responses gave taken fresh, and a higher role's
// requests under a lower role's identity, to tell an authorization the
// server enforces from one only the client does. It sends only to the
// target's scope, holds writes back unless allowed, never ends a session.
// See docs/gd5-replay-design.md.
package replay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/export"
)

// Patch puts a value at a place of a raw request (a Link's At: path:N,
// query:k, form:k, header:h, body:$.a), encoded as that place wants it,
// and writes Content-Length again. It fails when the request has no such
// place, or the value cannot go there.
func Patch(raw []byte, at, value string) ([]byte, error) {
	if strings.HasPrefix(at, "body:") && export.IsBinaryProtoMediaType(rawContentType(raw)) {
		return nil, fmt.Errorf("cannot patch binary protobuf body at %s", at)
	}
	for _, p := range export.Params(raw) {
		if p.At() != at {
			continue
		}
		// A JSON number, boolean or null has no quotes: another value
		// goes in as one only when it is one, else as a string.
		bare := p.In == "json" && (p.Start == 0 || raw[p.Start-1] != '"')
		queryJSON := p.In == "query" && strings.Contains(p.Name, "$")
		if queryJSON {
			quoted := (p.Start > 0 && raw[p.Start-1] == '"') ||
				(p.Start >= 3 && raw[p.Start-3] == '%' && raw[p.Start-2] == '2' && raw[p.Start-1] == '2')
			var enc string
			switch {
			case quoted:
				jb, _ := json.Marshal(value)
				enc = url.QueryEscape(string(jb[1 : len(jb)-1]))
			case jsonScalarRe.MatchString(value):
				enc = url.QueryEscape(value)
			default:
				jb, _ := json.Marshal(value)
				enc = url.QueryEscape(string(jb))
			}
			out := make([]byte, 0, len(raw)+len(enc))
			out = append(out, raw[:p.Start]...)
			out = append(out, enc...)
			out = append(out, raw[p.End:]...)
			return SetLength(out), nil
		}
		enc, err := encode(p, value)
		if bare && !jsonScalarRe.MatchString(value) {
			b, _ := json.Marshal(value)
			enc = string(b)
		}
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, len(raw)+len(enc))
		out = append(out, raw[:p.Start]...)
		out = append(out, enc...)
		out = append(out, raw[p.End:]...)
		return SetLength(out), nil
	}
	return nil, fmt.Errorf("no %s in the request", at)
}

var jsonScalarRe = regexp.MustCompile(`^(-?\d+(\.\d+)?([eE][-+]?\d+)?|true|false|null)$`)

// encode writes a value as the bytes of its place: a path segment, a
// query or form value, a JSON string's inside, or a header value. A JSON
// number or boolean stays one when the value is one.
func encode(p export.Param, v string) (string, error) {
	switch p.In {
	case "path":
		return url.PathEscape(v), nil
	case "query", "form":
		return url.QueryEscape(v), nil
	case "json":
		b, _ := json.Marshal(v)
		return string(b[1 : len(b)-1]), nil
	case "header", "cookie":
		if strings.ContainsAny(v, "\r\n") {
			return "", fmt.Errorf("a line break in a value for %s", p.At())
		}
		return v, nil
	}
	return "", fmt.Errorf("cannot write %s", p.In)
}

// SetLength writes a raw request's Content-Length again, for its body as
// it is now; a request with no body and no length is left as it is.
func SetLength(raw []byte) []byte {
	head := bytes.Index(raw, []byte("\r\n\r\n"))
	if head < 0 {
		return raw
	}
	body := raw[head+4:]
	lines := bytes.Split(raw[:head], []byte("\r\n"))
	had := false
	for i, l := range lines {
		if name, _, ok := bytes.Cut(l, []byte(":")); ok && i > 0 && strings.EqualFold(string(name), "content-length") {
			lines[i] = []byte("Content-Length: " + strconv.Itoa(len(body)))
			had = true
		}
	}
	if !had && len(body) > 0 {
		lines = append(lines, []byte("Content-Length: "+strconv.Itoa(len(body))))
	}
	out := bytes.Join(lines, []byte("\r\n"))
	out = append(out, "\r\n\r\n"...)
	return append(out, body...)
}

func rawContentType(raw []byte) string {
	head := bytes.Index(raw, []byte("\r\n\r\n"))
	if head < 0 {
		return ""
	}
	for _, l := range bytes.Split(raw[:head], []byte("\r\n"))[1:] {
		if k, v, ok := bytes.Cut(l, []byte(":")); ok && strings.EqualFold(strings.TrimSpace(string(k)), "content-type") {
			return strings.TrimSpace(string(v))
		}
	}
	return ""
}
