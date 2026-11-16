package export

import (
	"bytes"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// dropped are the headers a raw request file leaves out: hop-by-hop ones,
// those only HTTP/2 has, Content-Length (written again from the body), and
// Accept-Encoding, which would make ffuf get zstd it cannot read (Go adds
// gzip and decodes it when the header is absent).
var dropped = map[string]bool{"host": true, "connection": true, "keep-alive": true, "proxy-connection": true,
	"transfer-encoding": true, "te": true, "upgrade": true, "priority": true, "accept-encoding": true, "content-length": true}

// headerOrder is close to the order Chrome sends: CDP gives headers as a
// map, so the order on the wire is lost.
var headerOrder = []string{"content-type", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent",
	"accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-language", "cookie"}

// Raw is a request as an HTTP/1.1 message, for ffuf -request, sqlmap -r
// and Burp's Repeater (see docs/gd4-export-design.md, 3.1): origin-form
// request line, Host first, CRLF, the body as sent and its length.
type Raw struct {
	Bytes []byte
	// Incomplete says why the body is not all of what was sent: truncated
	// by the recorder, or shorter than the length the browser sent (a
	// multipart file CDP does not give).
	Incomplete string
	// Star says the request has a "*" sqlmap takes for an injection mark.
	Star bool
}

// RawRequest writes an entry as a raw request.
func RawRequest(e traffic.Entry) (Raw, error) {
	u, err := url.Parse(e.URL)
	if err != nil {
		return Raw{}, err
	}
	body := e.Body.Bytes()
	var out Raw
	var b bytes.Buffer
	target := requestTarget(e.URL)
	b.WriteString(e.Method + " " + target + " HTTP/1.1\r\n")
	b.WriteString("Host: " + u.Host + "\r\n")
	headers := Headers(e.Headers)
	for _, h := range headers {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	sent := -1
	for k, v := range e.Headers {
		if strings.EqualFold(k, "content-length") {
			sent, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if len(body) > 0 || sent >= 0 {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	out.Bytes = b.Bytes()
	switch {
	case e.BodyTruncated:
		out.Incomplete = "truncated"
	case sent > len(body):
		out.Incomplete = "short"
	}
	out.Star = strings.Contains(target, "*") || bytes.Contains(body, []byte("*"))
	for _, h := range headers {
		if strings.Contains(sqlmapSafe.ReplaceAllString(h[1], ""), "*") {
			out.Star = true
		}
	}
	return out, nil
}

// requestTarget is the path and query of a URL as the browser sent them:
// the URL's own text, which url.URL.RequestURI would escape again where it
// judges the path invalid ({}, |).
func requestTarget(raw string) string {
	raw, _, _ = strings.Cut(raw, "#")
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
		if j := strings.IndexAny(raw, "/?"); j >= 0 {
			raw = raw[j:]
		} else {
			raw = ""
		}
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return raw
}

// sqlmapSafe is what sqlmap strips from header values before it looks for
// its "*" mark (PROBLEMATIC_CUSTOM_INJECTION_PATTERNS).
var sqlmapSafe = regexp.MustCompile(`(;q=[^;'*]+)|(\*/\*)`)

// Headers lists a request's headers for a raw file: canonical names, in
// Chrome's order, without pseudo-headers and the dropped ones, and with
// repeated names joined.
func Headers(h map[string]string) [][2]string {
	merged := map[string]string{}
	var names []string
	for k, v := range h {
		n := strings.ToLower(strings.TrimSpace(k))
		if n == "" || strings.HasPrefix(n, ":") || dropped[n] {
			continue
		}
		// A header the browser sent twice comes as one value with newlines.
		sep := ", "
		if n == "cookie" {
			sep = "; "
		}
		v = strings.Join(strings.Split(v, "\n"), sep)
		if old, ok := merged[n]; ok {
			v = old + sep + v
		} else {
			names = append(names, n)
		}
		merged[n] = v
	}
	rank := func(n string) int {
		if n == "cookie" {
			return len(headerOrder)
		}
		if i := slices.Index(headerOrder, n); i >= 0 {
			return i
		}
		return len(headerOrder) - 1 // the application's own, before the cookie
	}
	slices.SortFunc(names, func(a, b string) int {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra - rb
		}
		return strings.Compare(a, b)
	})
	out := make([][2]string, len(names))
	for i, n := range names {
		out[i] = [2]string{textproto.CanonicalMIMEHeaderKey(n), merged[n]}
	}
	return out
}
