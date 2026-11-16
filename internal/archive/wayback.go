package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Capture is one row of an archive's index: a URL as it was at a time.
type Capture struct {
	URL    string    `json:"url"`
	Time   time.Time `json:"time"`
	MIME   string    `json:"mime,omitempty"`
	Status string    `json:"status,omitempty"` // "-" for a revisit
	Digest string    `json:"digest,omitempty"` // SHA-1, base32
	Source string    `json:"source"`
	// Timestamp is the archive's own (YYYYMMDDhhmmss), to fetch the capture.
	Timestamp string `json:"ts,omitempty"`
	// WARC is where Common Crawl keeps the capture's bytes.
	WARC *WARCRef `json:"warc,omitempty"`
}

const tsLayout = "20060102150405"

// Wayback lists and fetches from the Wayback Machine.
type Wayback struct {
	Base     string // https://web.archive.org
	Client   *Client
	Index    *Budget // the CDX server: slow
	Files    *Budget // mementos
	PageSize int
}

var cdxFields = []string{"timestamp", "original", "mimetype", "statuscode", "digest"}

// Page lists one page of a host's captures (its subdomains too), from a
// resume key ("" for the first). It returns the next page's key, "" when
// this was the last. The query has no filter: the CDX server answers a
// filtered query with 503s (docs/research-2026-11-02.md, 5).
func (w *Wayback) Page(ctx context.Context, host, resume string) ([]Capture, string, error) {
	q := url.Values{}
	q.Set("url", host)
	q.Set("matchType", "domain")
	q.Set("output", "json")
	q.Set("fl", strings.Join(cdxFields, ","))
	q.Set("showResumeKey", "true")
	q.Set("limit", fmt.Sprint(w.PageSize))
	if resume != "" {
		q.Set("resumeKey", resume)
	}
	u := w.Base + "/cdx/search/cdx?" + q.Encode()
	for try := 1; ; try++ {
		a, err := w.Client.Get(ctx, w.Index, u, 512<<20)
		if err != nil {
			return nil, "", err
		}
		if a.Status == 403 && bytes.Contains(a.Body, []byte("AdministrativeAccessControlException")) {
			return nil, "", ErrExcluded
		}
		if a.Status == 200 && offline(a.Body) {
			// The Internet Archive's "Temporarily Offline" page, sent as a
			// 200 (ARC-05): the same page again, after a while.
			if try >= w.Client.Tries {
				return nil, "", fmt.Errorf("%w: the CDX server answered %d times with a page: %s", ErrUnavailable, try, head(a.Body, 120))
			}
			if err := sleep(ctx, w.Client.Wait); err != nil {
				return nil, "", err
			}
			continue
		}
		if a.Status != 200 {
			return nil, "", fmt.Errorf("CDX: %d %s", a.Status, head(a.Body, 200))
		}
		return parseCDX(a.Body)
	}
}

// offline reports an answer that is a page, not the CDX server's JSON.
func offline(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '<'
}

// parseCDX reads the CDX server's JSON: a header row, the rows, then, when
// more remain, an empty row and the resume key's.
func parseCDX(b []byte) ([]Capture, string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		if len(bytes.TrimSpace(b)) == 0 {
			return nil, "", nil // nothing archived
		}
		return nil, "", fmt.Errorf("CDX: not a JSON array: %s", head(b, 120))
	}
	var header []string
	var out []Capture
	resume, afterEmpty := "", false
	for dec.More() {
		var row []string
		if err := dec.Decode(&row); err != nil {
			return out, "", fmt.Errorf("CDX row: %w", err)
		}
		switch {
		case header == nil:
			header = row
			continue
		case len(row) == 0:
			afterEmpty = true
			continue
		case afterEmpty && len(row) == 1:
			resume = row[0]
			continue
		}
		if len(row) != len(header) {
			continue
		}
		c := Capture{Source: "wayback"}
		for i, name := range header {
			switch name {
			case "timestamp":
				c.Timestamp = row[i]
				c.Time, _ = time.Parse(tsLayout, padTS(row[i]))
			case "original":
				c.URL = Normalize(row[i])
			case "mimetype":
				c.MIME = row[i]
			case "statuscode":
				c.Status = row[i]
			case "digest":
				c.Digest = row[i]
			}
		}
		out = append(out, c)
	}
	return out, resume, nil
}

// padTS completes a short Wayback timestamp (2019 → 20190101000000).
func padTS(ts string) string {
	const full = "00000101000000"
	if len(ts) < len(full) {
		ts += full[len(ts):]
	}
	return ts
}

// Normalize is a URL as the archives' rows give it, without a default
// port (http://example.com:80/ is http://example.com/).
func Normalize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
	}
	return u.String()
}

// Memento is a capture's file as it was archived: id_, without the
// Wayback's rewriting.
func (w *Wayback) Memento(c Capture) string {
	ts := c.Timestamp
	if ts == "" {
		ts = "2" // any time: the nearest capture (an OTX URL has no time)
	}
	return w.Base + "/web/" + ts + "id_/" + c.URL
}

func head(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
