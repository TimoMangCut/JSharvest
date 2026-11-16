package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Sig is what an answer is, its values aside: status, type, and the
// skeleton of a JSON body (its key paths and their types, a stable error
// code) or the shell of a page (title and scripts) and its word count.
type Sig struct {
	Status       int    `json:"status"`
	Type         string `json:"type"`
	Skeleton     string `json:"skeleton,omitempty"`
	Code         string `json:"code,omitempty"` // a stable error code (ROUTE_NOT_FOUND)
	Shell        string `json:"shell,omitempty"`
	Words        int    `json:"words,omitempty"`
	Allow        string `json:"allow,omitempty"`
	MethodScoped bool   `json:"method_scoped,omitempty"` // 405, or router 404 naming GET/HEAD (Express/NestJS/Fastify)
}

// stableCodeRe is an error code that names a kind of error, not one
// request: upper or snake case, short.
var (
	stableCodeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[_.-][A-Za-z0-9]+)*$`)
	method404Re  = regexp.MustCompile(`(?i)\b(?:cannot\s+(?:get|head)\s+/|route\s+(?:get|head)[:\s]\s*/|method\s+(?:get|head)\s+not\s+allowed\b)`)
)

// SigOf reads an answer.
func SigOf(status int, header map[string]string, body []byte) Sig {
	s := Sig{Status: status, Type: mediaType(header["content-type"]), Allow: header["allow"]}
	text := string(body)
	if !scriptRe.MatchString(text) && (status == 405 || (status == 404 && method404Re.MatchString(text))) {
		s.MethodScoped = true
	}
	var v any
	if json.Unmarshal(body, &v) == nil && (strings.Contains(s.Type, "json") || len(body) > 0 && (body[0] == '{' || body[0] == '[')) {
		var paths []string
		skeleton(v, "", &paths, 0)
		sort.Strings(paths)
		h := sha256.Sum256([]byte(strings.Join(paths, "\n")))
		s.Skeleton = hex.EncodeToString(h[:8])
		if m, ok := v.(map[string]any); ok {
			s.Code = stableCode(m)
		}
		return s
	}
	if strings.Contains(s.Type, "html") || strings.Contains(strings.ToLower(text[:min(len(text), 512)]), "<html") {
		s.Shell = shell(text)
	}
	s.Words = len(strings.Fields(text))
	return s
}

// numericCodeKeys are the keys a number code lives under (a code that
// tells a route from a canary: nothing is concluded from its value).
var numericCodeKeys = []string{"code", "status", "statusCode", "errcode", "errorCode", "error_code"}

// stableCode reads a body's error code: a string that names a kind of
// error, or an integer under numericCodeKeys.
func stableCode(m map[string]any) string {
	str := func(v any) string {
		if c, ok := v.(string); ok && len(c) <= 48 && stableCodeRe.MatchString(c) {
			return c
		}
		return ""
	}
	for _, k := range []string{"code", "error_code", "errorCode", "error"} {
		if c := str(m[k]); c != "" {
			return c
		}
		if e, ok := m[k].(map[string]any); ok {
			if c := str(e["code"]); c != "" {
				return c
			}
		}
	}
	for _, k := range numericCodeKeys {
		if f, ok := m[k].(float64); ok && f == math.Trunc(f) && math.Abs(f) < 1e12 {
			return strconv.FormatInt(int64(f), 10)
		}
	}
	return ""
}

func mediaType(ct string) string {
	t, _, _ := strings.Cut(strings.ToLower(ct), ";")
	return strings.TrimSpace(t)
}

// skeleton lists a JSON value's key paths with their types; a list's
// items are one item.
func skeleton(v any, path string, out *[]string, depth int) {
	if depth > 8 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		*out = append(*out, path+":object")
		for k, c := range x {
			skeleton(c, path+"."+k, out, depth+1)
		}
	case []any:
		*out = append(*out, path+":array")
		if len(x) > 0 {
			skeleton(x[0], path+"[]", out, depth+1)
		}
	case string:
		*out = append(*out, path+":string")
	case float64:
		*out = append(*out, path+":number")
	case bool:
		*out = append(*out, path+":boolean")
	case nil:
		*out = append(*out, path+":null")
	}
}

var (
	titleRe  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	scriptRe = regexp.MustCompile(`(?is)<script[^>]*\bsrc=["']([^"']+)["']`)
)

// shell is a page's title and scripts: an SPA's fallback is the same page
// whatever the path.
func shell(html string) string {
	var parts []string
	if m := titleRe.FindStringSubmatch(html); m != nil {
		parts = append(parts, strings.TrimSpace(m[1]))
	}
	for _, m := range scriptRe.FindAllStringSubmatch(html, 50) {
		parts = append(parts, m[1])
	}
	if len(parts) == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:8])
}

// Same reports two answers of one kind: what a router says of any path
// (the canary's) and what it says of this one cannot be told apart.
func Same(a, b Sig) bool {
	if a.Status != b.Status || a.Type != b.Type {
		return false
	}
	switch {
	case a.Skeleton != "" || b.Skeleton != "":
		return a.Skeleton == b.Skeleton && a.Code == b.Code
	case a.Shell != "" && a.Shell == b.Shell:
		return true
	}
	lo, hi := min(a.Words, b.Words), max(a.Words, b.Words)
	return hi == 0 || float64(hi-lo) <= 0.15*float64(hi)
}

// missingRe reads a validation message's field: "warehouse_id should not
// be empty", "warehouse_id is required", "missing field `x`".
var missingRe = regexp.MustCompile("^`?([A-Za-z_][\\w.\\[\\]]*)`?\\s+(?:should|must|is required|is missing|are required|field required|may not)|(?i:missing (?:field|parameter|property))\\s+[`'\"]?([A-Za-z_][\\w.]*)")

// MissingParams are the fields a 400/415/422 says are missing or wrong.
func MissingParams(body []byte) []string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && len(s) <= 64 && !seen[s] && !strings.Contains(s, " ") {
			seen[s] = true
			out = append(out, s)
		}
	}
	var walk func(v any, key string, depth int)
	walk = func(v any, key string, depth int) {
		if depth > 6 {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			for _, f := range []string{"field", "property", "param", "parameter", "path", "name"} {
				if s, ok := x[f].(string); ok && (key == "errors" || key == "details" || key == "detail" || key == "violations") {
					add(s)
				}
			}
			// FastAPI: {"loc": ["body", "x"], "msg": "field required"}
			if loc, ok := x["loc"].([]any); ok && len(loc) > 0 {
				if s, ok := loc[len(loc)-1].(string); ok {
					add(s)
				}
			}
			for k, c := range x {
				walk(c, strings.ToLower(k), depth+1)
			}
		case []any:
			for _, c := range x {
				walk(c, key, depth+1)
			}
		case string:
			switch key {
			case "missing", "required", "missing_fields", "missingfields", "fields":
				add(x)
			case "message", "messages", "msg", "error", "errors":
				if m := missingRe.FindStringSubmatch(x); m != nil {
					add(m[1] + m[2])
				}
			}
		}
	}
	walk(v, "", 0)
	sort.Strings(out)
	return out
}

func (s Sig) String() string {
	return fmt.Sprintf("%d %s %s%s", s.Status, s.Type, s.Code, s.Skeleton)
}
