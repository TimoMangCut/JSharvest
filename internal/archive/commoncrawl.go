package archive

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CommonCrawl lists what Common Crawl's newest collections hold of a
// domain. Its index is "heavily rate limited": one request at a time, ten
// seconds apart at least. Each collection is an index of its own: one that
// fails leaves the others to list (MAX-01). A capture's bytes are in a
// WARC file on data.commoncrawl.org, which Fetch reads by range when the
// Wayback has no copy.
type CommonCrawl struct {
	Index       string // https://index.commoncrawl.org
	Data        string // https://data.commoncrawl.org
	Client      *Client
	Budget      *Budget
	Files       *Budget // the WARC files
	Collections int
}

// fullPage is the lines a page of the index holds at least when more pages
// may follow: a page is five blocks of 3000 lines, and a domain's lines run
// on from one block to the next. Fewer, and page 0 was all of it.
const fullPage = 3000

// Latest lists the ids of the newest collections (collinfo.json, newest
// first).
func (cc *CommonCrawl) Latest(ctx context.Context) ([]string, error) {
	a, err := cc.get(ctx, cc.Index+"/collinfo.json")
	if err != nil {
		return nil, err
	}
	var cols []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(a.Body, &cols); err != nil {
		return nil, fmt.Errorf("collinfo: %w", err)
	}
	var out []string
	for _, c := range cols {
		if len(out) < cc.Collections {
			out = append(out, c.ID)
		}
	}
	return out, nil
}

// Pages is how many pages a collection's index has for the domain.
func (cc *CommonCrawl) Pages(ctx context.Context, coll, host string) (int, error) {
	a, err := cc.get(ctx, cc.query(coll, host, -1))
	if err != nil {
		return 0, err
	}
	var r struct {
		Pages int `json:"pages"`
	}
	if err := json.Unmarshal(a.Body, &r); err != nil {
		return 0, fmt.Errorf("showNumPages: %w", err)
	}
	return r.Pages, nil
}

// Page lists one page of a collection: NDJSON, one capture a line.
func (cc *CommonCrawl) Page(ctx context.Context, coll, host string, page int) ([]Capture, error) {
	a, err := cc.get(ctx, cc.query(coll, host, page))
	if err != nil {
		return nil, err
	}
	var out []Capture
	sc := bufio.NewScanner(bytes.NewReader(a.Body))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var r struct {
			Timestamp    string `json:"timestamp"`
			URL          string `json:"url"`
			MIME         string `json:"mime"`
			MIMEDetected string `json:"mime-detected"`
			Status       string `json:"status"`
			Digest       string `json:"digest"`
			Filename     string `json:"filename"`
			Offset       string `json:"offset"`
			Length       string `json:"length"`
		}
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.URL == "" {
			continue
		}
		c := Capture{URL: Normalize(r.URL), Status: r.Status, Digest: r.Digest, Source: "commoncrawl", Timestamp: r.Timestamp, MIME: r.MIMEDetected}
		off, err1 := strconv.ParseInt(r.Offset, 10, 64)
		n, err2 := strconv.ParseInt(r.Length, 10, 64)
		if r.Filename != "" && err1 == nil && err2 == nil && off >= 0 && n > 0 {
			c.WARC = &WARCRef{File: r.Filename, Offset: off, Length: n}
		}
		if c.MIME == "" {
			c.MIME = r.MIME
		}
		c.Time, _ = time.Parse(tsLayout, padTS(r.Timestamp))
		out = append(out, c)
	}
	return out, sc.Err()
}

func (cc *CommonCrawl) query(coll, host string, page int) string {
	q := url.Values{}
	q.Set("url", "*."+host)
	q.Set("output", "json")
	if page < 0 {
		q.Set("showNumPages", "true")
	} else {
		q.Set("page", fmt.Sprint(page))
	}
	return cc.Index + "/" + url.PathEscape(coll) + "-index?" + q.Encode()
}

// get gets from the index; the client retries a 5xx it may outlast.
func (cc *CommonCrawl) get(ctx context.Context, u string) (*Answer, error) {
	a, err := cc.Client.Get(ctx, cc.Budget, u, 256<<20)
	if err != nil {
		return nil, err
	}
	switch {
	case a.Status == 404:
		return &Answer{Status: 404, Body: []byte(`{"pages":0}`)}, nil // nothing in that collection
	case a.Status != 200:
		return nil, fmt.Errorf("Common Crawl: %d %s", a.Status, head(a.Body, 200))
	}
	return a, nil
}

// List lists a collection's captures of a domain from page `from` on,
// handing each page to take: page 0 alone when it is not full (most hosts:
// one request, not two), the pages showNumPages counts when it is. It
// returns the next page to list when it stops on an error.
func (cc *CommonCrawl) List(ctx context.Context, coll, host string, from int, take func([]Capture)) (int, error) {
	pages := -1
	for page := from; pages < 0 || page < pages; page++ {
		caps, err := cc.Page(ctx, coll, host, page)
		if err != nil {
			return page, err
		}
		take(caps)
		if pages < 0 {
			if page == 0 && len(caps) < fullPage {
				return page + 1, nil
			}
			n, err := cc.Pages(ctx, coll, host)
			if err != nil {
				return page + 1, err
			}
			pages = n
		}
	}
	return pages, nil
}

// WARCRef is where Common Crawl keeps a capture: a range of a WARC file.
type WARCRef struct {
	File   string `json:"file"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

// Fetch reads a capture's record from its WARC file, by range (MAX-01):
// the bytes of a script the Wayback never archived.
func (cc *CommonCrawl) Fetch(ctx context.Context, w *WARCRef, max int) (*Record, error) {
	if cc.Data == "" || w == nil || w.Length > int64(max)+1<<20 || strings.Contains(w.File, "..") {
		return nil, fmt.Errorf("no WARC range to read")
	}
	h := http.Header{"Range": {fmt.Sprintf("bytes=%d-%d", w.Offset, w.Offset+w.Length-1)}}
	a, err := cc.Client.GetWith(ctx, cc.Files, strings.TrimSuffix(cc.Data, "/")+"/"+strings.TrimPrefix(w.File, "/"), w.Length, h)
	if err != nil {
		return nil, err
	}
	if a.Status != http.StatusPartialContent && a.Status != http.StatusOK {
		return nil, fmt.Errorf("WARC %s: %d", w.File, a.Status)
	}
	b := a.Body
	if a.Status == http.StatusOK && int64(len(b)) > w.Length {
		return nil, fmt.Errorf("WARC %s: the range was not honoured", w.File)
	}
	return ReadRecord(b, max)
}
