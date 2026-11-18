package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
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
	Base        string  // https://web.archive.org
	Client      *Client // mementos (/web/...)
	IndexClient *Client // optional separate client for CDX (/cdx/search/cdx); defaults to Client
	Index       *Budget // the CDX server: slow
	Files       *Budget // mementos
	PageSize    int
	Collapse    string // adjacent field collapse (e.g. "digest")
	Sharded     bool   // use ZipNum showNumPages + parallel page=0..N-1 shards
}

func (w *Wayback) indexClient() *Client {
	if w.IndexClient != nil {
		return w.IndexClient
	}
	return w.Client
}

var cdxFields = []string{"timestamp", "original", "mimetype", "statuscode", "digest"}

func (w *Wayback) getCDX(ctx context.Context, u string) ([]byte, error) {
	ic := w.indexClient()
	for try := 1; ; try++ {
		a, err := ic.GetIndex(ctx, w.Index, u, 64<<20)
		if err != nil {
			return nil, err
		}
		if a.Status == 403 && bytes.Contains(a.Body, []byte("AdministrativeAccessControlException")) {
			return nil, ErrExcluded
		}
		if a.Status == 200 && offline(a.Body) {
			// The Internet Archive's "Temporarily Offline" page, sent as a
			// 200 (ARC-05): the same page again, after a while.
			if try >= ic.Tries {
				return nil, fmt.Errorf("%w: the CDX server answered %d times with a page: %s", ErrUnavailable, try, head(a.Body, 120))
			}
			if err := sleep(ctx, ic.Wait); err != nil {
				return nil, err
			}
			continue
		}
		if a.Status != 200 {
			return nil, fmt.Errorf("CDX: %d %s", a.Status, head(a.Body, 200))
		}
		return a.Body, nil
	}
}

// NumPages asks the CDX server how many ZipNum block pages exist for host.
// If the server is a mock/older endpoint that ignores showNumPages and returns
// a CDX JSON array instead, supported is false so the caller falls back to resumeKey.
func (w *Wayback) NumPages(ctx context.Context, host string) (pages int, supported bool, err error) {
	q := url.Values{}
	q.Set("url", host)
	q.Set("matchType", "domain")
	q.Set("showNumPages", "true")
	if w.Collapse != "" {
		q.Set("collapse", w.Collapse)
	}
	body, err := w.getCDX(ctx, w.Base+"/cdx/search/cdx?"+q.Encode())
	if err != nil {
		return 0, false, err
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return 0, true, nil
	}
	if n, err := strconv.Atoi(trimmed); err == nil && n >= 0 {
		return n, true, nil
	}
	var obj struct {
		Pages int `json:"pages"`
	}
	if strings.HasPrefix(trimmed, "{") && json.Unmarshal([]byte(trimmed), &obj) == nil {
		return obj.Pages, true, nil
	}
	return 0, false, nil
}

// ShardPage fetches a single independent ZipNum block shard (page=0..N-1),
// safe for concurrent workers and bounded on the server to one ZipNum slice.
func (w *Wayback) ShardPage(ctx context.Context, host string, page int) ([]Capture, error) {
	q := url.Values{}
	q.Set("url", host)
	q.Set("matchType", "domain")
	q.Set("output", "json")
	q.Set("fl", strings.Join(cdxFields, ","))
	q.Set("page", strconv.Itoa(page))
	if w.Collapse != "" {
		q.Set("collapse", w.Collapse)
	}
	body, err := w.getCDX(ctx, w.Base+"/cdx/search/cdx?"+q.Encode())
	if err != nil {
		return nil, err
	}
	caps, _, err := parseCDX(body)
	return caps, err
}

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
	if w.Collapse != "" && !w.Sharded {
		q.Set("collapse", w.Collapse)
	}
	if resume != "" {
		q.Set("resumeKey", resume)
	}
	body, err := w.getCDX(ctx, w.Base+"/cdx/search/cdx?"+q.Encode())
	if err != nil {
		return nil, "", err
	}
	return parseCDX(body)
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
