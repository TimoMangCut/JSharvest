package flow

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

const (
	maxValues = 200    // values kept of one response, or of one request
	maxIndex  = 100000 // values remembered across a run
)

// plainHeaders say nothing a later request would echo.
var plainHeaders = map[string]bool{
	"cookie": true, "host": true, "user-agent": true, "accept": true, "accept-encoding": true, "accept-language": true,
	"content-type": true, "content-length": true, "content-encoding": true, "content-language": true, "origin": true,
	"referer": true, "connection": true, "cache-control": true, "pragma": true, "priority": true, "dnt": true,
	"upgrade-insecure-requests": true, "date": true, "server": true, "vary": true, "expires": true, "last-modified": true,
	"keep-alive": true, "transfer-encoding": true, "set-cookie": true, "location": true, "x-content-type-options": true,
	"strict-transport-security": true, "content-security-policy": true, "x-frame-options": true, "referrer-policy": true,
	"permissions-policy": true, "report-to": true, "nel": true, "alt-svc": true, "via": true, "age": true,
	"next-action": true, "next-router-state-tree": true, "next-router-prefetch": true, "next-url": true, "rsc": true,
	strings.ToLower(traffic.GuardHeader): true,
}

// PlainHeader reports whether a header is one every request has (or a
// browser's own), not one the application sets.
func PlainHeader(name string) bool { return plainHeader(name) }

func plainHeader(name string) bool {
	n := strings.ToLower(name)
	return plainHeaders[n] || strings.HasPrefix(n, "sec-") || strings.HasPrefix(n, ":") || strings.HasPrefix(n, "access-control-")
}

// worth reports whether a value is specific enough that seeing it again
// means it was carried over: not a word, a flag, a small number or a year.
func worth(v string) bool {
	if len(v) < 5 || len(v) > 4096 || strings.ContainsAny(v, " \t\n") {
		return false
	}
	if isDigits(v) {
		return len(v) >= 5
	}
	if len(v) < 6 {
		return false
	}
	lowerWord := true
	for _, r := range v {
		if r < 'a' || r > 'z' {
			lowerWord = false
			break
		}
	}
	return !lowerWord
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

type collector struct {
	out  []Value
	seen map[string]bool
}

func (c *collector) add(v, at string) {
	// A copy: a substring would keep the whole body it came from alive for
	// as long as the run (a watch can be long).
	v = strings.Clone(strings.TrimSpace(v))
	if !worth(v) || c.seen[v+"\x00"+at] {
		return
	}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	c.seen[v+"\x00"+at] = true
	c.out = append(c.out, Value{V: v, At: at})
}

// RequestValues lists the values a request carries where a later fuzzer
// would put its input: path segments, query, headers, body fields.
func RequestValues(e traffic.Entry) []Value {
	var c collector
	if u, err := url.Parse(e.URL); err == nil {
		for i, s := range strings.Split(strings.Trim(u.EscapedPath(), "/"), "/") {
			if v, err := url.PathUnescape(s); err == nil {
				c.add(v, fmt.Sprintf("path:%d", i+1))
			}
		}
		for k, vs := range u.Query() {
			for _, v := range vs {
				c.add(v, "query:"+k)
			}
		}
	}
	for k, v := range e.Headers {
		if !plainHeader(k) {
			c.add(v, "header:"+strings.ToLower(k))
		}
	}
	if !e.BodyBase64 && e.Body.Body != "" {
		bodyValues(&c, e.Body.Body, e.Headers["content-type"], "body")
	}
	return capped(c.out)
}

// ResponseValues lists the values a response gives that a later request
// may carry: headers and cookies first, then body strings, then numbers.
func ResponseValues(e traffic.Entry) []Value {
	if e.Response == nil {
		return nil
	}
	var c collector
	for k, v := range e.Response.Headers {
		switch {
		case strings.EqualFold(k, "set-cookie"):
			for _, line := range strings.Split(v, "\n") {
				first, _, _ := strings.Cut(line, ";")
				if name, val, ok := strings.Cut(first, "="); ok {
					c.add(val, "cookie:"+strings.TrimSpace(name))
				}
			}
		case !plainHeader(k):
			c.add(v, "header:"+strings.ToLower(k))
		}
	}
	b := e.Response.Body
	if !b.BodyBase64 && b.Body != "" {
		bodyValues(&c, b.Body, e.Response.MIME, "json")
	}
	return capped(c.out)
}

var (
	looseJSONRe = regexp.MustCompile(`"([^"\\]{1,100})"\s*:\s*"([^"\\]{5,})"`)
	metaRe      = regexp.MustCompile(`(?i)<meta\s[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']+)["']`)
	inputRe     = regexp.MustCompile(`(?i)<input\s[^>]*name=["']([^"']+)["'][^>]*value=["']([^"']+)["']`)
)

// bodyValues reads a body as JSON, a form or HTML. JSON paths start with
// "$"; a request body's are prefixed "body:", a response's "json:".
func bodyValues(c *collector, body, mime, prefix string) {
	t := strings.TrimSpace(body)
	switch {
	case strings.HasPrefix(t, "{") || strings.HasPrefix(t, "["):
		dec := json.NewDecoder(strings.NewReader(t))
		dec.UseNumber()
		var v any
		if dec.Decode(&v) == nil {
			walkJSON(c, v, prefix+":$", 0)
			return
		}
		// Cut short by the body limit: take the pairs that are whole.
		for _, m := range looseJSONRe.FindAllStringSubmatch(t, -1) {
			c.add(m[2], prefix+":$.."+m[1])
		}
	case strings.Contains(mime, "html") || strings.HasPrefix(t, "<"):
		for _, m := range metaRe.FindAllStringSubmatch(t, -1) {
			c.add(m[2], "html:meta["+m[1]+"]")
		}
		for _, m := range inputRe.FindAllStringSubmatch(t, -1) {
			c.add(m[2], "html:input["+m[1]+"]")
		}
	case strings.Contains(mime, "x-www-form-urlencoded") || (prefix == "body" && strings.Contains(t, "=")):
		if q, err := url.ParseQuery(t); err == nil {
			for k, vs := range q {
				for _, v := range vs {
					c.add(v, "form:"+k)
				}
			}
		}
	}
}

func walkJSON(c *collector, v any, path string, depth int) {
	if depth > 20 || len(c.out) >= 4*maxValues {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkJSON(c, x[k], path+"."+k, depth+1)
		}
	case []any:
		for i, e := range x {
			walkJSON(c, e, path+"["+strconv.Itoa(i)+"]", depth+1)
		}
	case string:
		c.add(x, path)
	case json.Number:
		c.add(x.String(), path)
	}
}

// capped keeps maxValues values: headers, cookies, paths, queries and
// forms first, then strings, then numbers.
func capped(vs []Value) []Value {
	rank := func(v Value) int {
		switch {
		case strings.HasPrefix(v.At, "header:"), strings.HasPrefix(v.At, "cookie:"), strings.HasPrefix(v.At, "html:"):
			return 0
		case strings.HasPrefix(v.At, "path:"), strings.HasPrefix(v.At, "query:"), strings.HasPrefix(v.At, "form:"):
			return 1
		case isDigits(v.V):
			return 3
		}
		return 2
	}
	sort.SliceStable(vs, func(i, j int) bool { return rank(vs[i]) < rank(vs[j]) })
	if len(vs) > maxValues {
		vs = vs[:maxValues]
	}
	return vs
}

// dependsOn links each request value to the latest earlier response that
// gave it: a response counts once it has ended before the request began.
func dependsOn(reqs []Request) []Link {
	byStart := make([]int, len(reqs))
	byEnd := make([]int, 0, len(reqs))
	for i, r := range reqs {
		byStart[i] = i
		if !r.End.IsZero() && len(r.Provides) > 0 {
			byEnd = append(byEnd, i)
		}
	}
	sort.SliceStable(byStart, func(a, b int) bool { return reqs[byStart[a]].Time.Before(reqs[byStart[b]].Time) })
	sort.SliceStable(byEnd, func(a, b int) bool { return reqs[byEnd[a]].End.Before(reqs[byEnd[b]].End) })

	index := map[string]LinkEnd{}
	var out []Link
	next := 0
	for _, j := range byStart {
		r := reqs[j]
		for next < len(byEnd) && reqs[byEnd[next]].End.Before(r.Time) {
			src := reqs[byEnd[next]]
			for _, v := range src.Provides {
				if _, ok := index[v.V]; ok || len(index) < maxIndex {
					index[v.V] = LinkEnd{Request: src.ID, At: v.At}
				}
			}
			next++
		}
		if r.Internal {
			continue
		}
		done := map[string]bool{}
		for _, v := range r.Uses {
			from, ok := index[v.V]
			if !ok || from.Request == r.ID || done[v.At] {
				continue
			}
			done[v.At] = true
			out = append(out, Link{Request: r.ID, At: v.At, From: from})
		}
	}
	return out
}
