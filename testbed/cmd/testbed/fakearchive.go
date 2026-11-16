package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fakeArchive is the archives of archive-app (history.json): a Wayback
// CDX server and its mementos, OTX and Common Crawl's index, under /fake/.
// It answers as the real ones do (docs/gd5-archive-design.md, 7), with
// their troubles: the Internet Archive's "Temporarily Offline" page as a
// 200 for the first CDX query, a 503 on the second CDX page, a 502 on a
// later one, a 429 on the first memento, a memento that moves to its
// nearest capture (a revisit's, to the capture it revisits), a body the
// archive keeps gzip-coded. OTX answers its domain, hostname and IPv4
// sections alike: the gate reads which one was asked in the log. It is
// mounted before the mux: a memento's path holds http://, which the mux
// would "clean".
type fakeArchive struct {
	Wayback []struct {
		TS     string `json:"ts"`
		URL    string `json:"url"`
		MIME   string `json:"mime"`
		Status string `json:"status"`
		File   string `json:"file"`
		Body   string `json:"body"`
		Coded  bool   `json:"coded"`
		CDX    *bool  `json:"cdx"`
		bytes  []byte // as the archive keeps it
		digest string
	} `json:"wayback"`
	OTX []map[string]any `json:"otx"`
	CC  []map[string]any `json:"commoncrawl"`
	// URLScan: the scans of the target, and each one's URLs.
	URLScan []struct {
		ID   string   `json:"id"`
		Time string   `json:"time"`
		Page string   `json:"page"`
		URLs []string `json:"urls"`
	} `json:"urlscan"`

	warcFile  []byte // Common Crawl's WARC file: the records of the captures marked warc
	mu        sync.Mutex
	busyCC    bool // the newest collection answered a 504
	offline   bool // the first query had the offline page
	failedCDX bool
	badGW     bool // a 502 was sent
	limited   bool
}

// offlinePage is what web.archive.org sends, with a 200, when a CDX node is
// down (Reviewer round 16, ARC-05).
const offlinePage = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Internet Archive: Temporarily Offline</title></head><body>Temporarily Offline</body></html>`

func loadFakeArchive(app string) (*fakeArchive, error) {
	b, err := os.ReadFile(filepath.Join(app, "history.json"))
	if err != nil {
		return nil, err
	}
	// FAKE_ARCHIVE_REHOST=host:port serves the captures as the target's under
	// that name (testbed/proxy-check.sh: a name only a proxy resolves). Unset,
	// as in every other gate, nothing changes. The bodies are not touched:
	// their digests stay what the archive says.
	if to := os.Getenv("FAKE_ARCHIVE_REHOST"); to != "" {
		b = bytes.ReplaceAll(b, []byte("127.0.0.1:8770"), []byte(to))
	}
	var f fakeArchive
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for i := range f.Wayback {
		w := &f.Wayback[i]
		body := []byte(w.Body)
		if w.File != "" {
			if body, err = os.ReadFile(filepath.Join(app, "history", w.File)); err != nil {
				return nil, err
			}
		}
		if w.Coded {
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			zw.Write(body)
			zw.Close()
			body = b.Bytes()
		}
		w.bytes = body
		sum := sha1.Sum(body)
		w.digest = base32.StdEncoding.EncodeToString(sum[:])
	}
	// A Common Crawl capture of a file has its digest: of the payload, as
	// Common Crawl keeps it decoded. One marked warc has its record in the
	// WARC file, by range (Reviewer round 17, MAX-01).
	for _, c := range f.CC {
		if file, ok := c["file"].(string); ok {
			body, err := os.ReadFile(filepath.Join(app, "history", file))
			if err != nil {
				return nil, err
			}
			sum := sha1.Sum(body)
			c["digest"] = base32.StdEncoding.EncodeToString(sum[:])
			delete(c, "file")
			if w, _ := c["warc"].(bool); w {
				rec := warcRecord(c["url"].(string), body)
				f.warcFile = append(f.warcFile, bytes.Repeat([]byte{0}, 37)...) // records are never at 0
				c["filename"], c["offset"], c["length"] = "crawl-data/CC-MAIN-2024-18/fake.warc.gz", fmt.Sprint(len(f.warcFile)), fmt.Sprint(len(rec))
				f.warcFile = append(f.warcFile, rec...)
			}
			delete(c, "warc")
		}
	}
	sort.SliceStable(f.Wayback, func(i, j int) bool {
		if f.Wayback[i].URL != f.Wayback[j].URL {
			return f.Wayback[i].URL < f.Wayback[j].URL // the CDX's urlkey order, near enough
		}
		return f.Wayback[i].TS < f.Wayback[j].TS
	})
	return &f, nil
}

func (f *fakeArchive) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/fake/wayback/cdx/search/cdx":
		f.cdx(w, r)
	case strings.HasPrefix(r.RequestURI, "/fake/wayback/web/"):
		f.memento(w, r)
	case strings.HasPrefix(p, "/fake/otx/api/v1/indicators/") && strings.HasSuffix(p, "/url_list"):
		f.otx(w, r)
	case strings.HasPrefix(p, "/fake/ccdata/"):
		// data.commoncrawl.org: a WARC file, read by range.
		http.ServeContent(w, r, "fake.warc.gz", time.Time{}, bytes.NewReader(f.warcFile))
	case p == "/fake/urlscan/api/v1/search/":
		f.urlscanSearch(w, r)
	case strings.HasPrefix(p, "/fake/urlscan/api/v1/result/"):
		f.urlscanResult(w, r)
	case p == "/fake/cc/collinfo.json":
		fmt.Fprint(w, `[{"id":"CC-MAIN-2024-18","name":"April 2024"},{"id":"CC-MAIN-2024-10","name":"February 2024"}]`)
	case strings.HasPrefix(p, "/fake/cc/") && strings.HasSuffix(p, "-index"):
		f.cc(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeArchive) cdx(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	start, _ := strconv.Atoi(q.Get("resumeKey"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 1000
	}
	f.mu.Lock()
	switch {
	case !f.offline:
		f.offline = true
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, offlinePage)
		return
	case start > 0 && !f.failedCDX:
		f.failedCDX = true
		f.mu.Unlock()
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	case start >= 6 && !f.badGW:
		f.badGW = true
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, offlinePage)
		return
	}
	f.mu.Unlock()
	rows := [][]string{{"timestamp", "original", "mimetype", "statuscode", "digest"}}
	var listed []int
	for i, c := range f.Wayback {
		if c.CDX == nil || *c.CDX {
			listed = append(listed, i)
		}
	}
	end := min(start+limit, len(listed))
	for _, i := range listed[start:end] {
		c := f.Wayback[i]
		rows = append(rows, []string{c.TS, c.URL, c.MIME, c.Status, c.digest})
	}
	if end < len(listed) {
		rows = append(rows, []string{}, []string{strconv.Itoa(end)})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

func (f *fakeArchive) memento(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.RequestURI, "/fake/wayback/web/")
	ts, target, ok := strings.Cut(rest, "id_/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	first := !f.limited
	f.limited = true
	f.mu.Unlock()
	if first {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	if r.Header.Get("Accept-Encoding") != "identity" {
		// The Wayback codes a memento the client asked to be coded, and the
		// archive's digest no longer fits (the review's finding 1).
		http.Error(w, "the gate wants Accept-Encoding: identity", http.StatusBadRequest)
		return
	}
	var near string
	for _, c := range f.Wayback {
		if c.URL != target || c.Status != "200" {
			continue
		}
		if c.TS == ts {
			w.Header().Set("Content-Type", c.MIME)
			if c.Coded {
				w.Header().Set("Content-Encoding", "gzip")
			}
			w.Write(c.bytes)
			return
		}
		near = c.TS
	}
	if near != "" {
		// Absolute, as the Wayback's: http.Redirect would clean the
		// http:// in the path.
		w.Header().Set("Location", "http://"+r.Host+"/fake/wayback/web/"+near+"id_/"+target)
		w.WriteHeader(http.StatusFound)
		return
	}
	http.NotFound(w, r)
}

func (f *fakeArchive) otx(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	const size = 2
	start := (max(page, 1) - 1) * size
	end := min(start+size, len(f.OTX))
	if start > end {
		start = end
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"url_list": f.OTX[start:end], "has_next": end < len(f.OTX), "page_num": page})
}

func (f *fakeArchive) cc(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	busy := !f.busyCC && strings.Contains(r.URL.Path, "CC-MAIN-2024-18")
	f.busyCC = f.busyCC || busy
	f.mu.Unlock()
	if busy { // the newest collection, the busiest: once
		http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
		return
	}
	if strings.Contains(r.URL.Path, "CC-MAIN-2024-10") {
		http.Error(w, "No Captures found", http.StatusNotFound)
		return
	}
	if q.Get("showNumPages") == "true" {
		fmt.Fprint(w, `{"pages": 1, "pageSize": 5, "blocks": 1}`)
		return
	}
	if q.Get("page") != "0" {
		http.Error(w, "page out of range", http.StatusBadRequest)
		return
	}
	for _, c := range f.CC {
		b, _ := json.Marshal(c)
		w.Write(append(b, '\n'))
	}
}

// fakeArchiveFor mounts the fake archive before the mux, and the soft 404
// of archive-app's old path, when the app has a history.
func fakeArchiveFor(app string, next http.Handler) http.Handler {
	f, err := loadFakeArchive(app)
	if err != nil {
		return next
	}
	dist := filepath.Join(app, "dist")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/fake/"):
			f.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/legacy/"):
			// An old script's path, answered with the SPA's page: 200, HTML.
			w.Header().Set("Content-Type", "text/html")
			http.ServeFile(w, r, filepath.Join(dist, "index.html"))
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// warcRecord is a capture as Common Crawl keeps it: a gzip member holding a
// WARC response record.
func warcRecord(target string, body []byte) []byte {
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	rec := fmt.Sprintf("WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: %s\r\nContent-Type: application/http; msgtype=response\r\nContent-Length: %d\r\n\r\n%s\r\n\r\n",
		target, len(resp), resp)
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(rec))
	zw.Close()
	return b.Bytes()
}

func (f *fakeArchive) urlscanSearch(w http.ResponseWriter, r *http.Request) {
	var results []map[string]any
	for i, s := range f.URLScan {
		results = append(results, map[string]any{"_id": s.ID, "sort": []any{len(f.URLScan) - i, s.ID},
			"task": map[string]any{"url": s.Page, "time": s.Time},
			"page": map[string]any{"url": s.Page, "mimeType": "text/html", "status": "200"}})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"results": results, "total": len(results), "has_more": false})
}

func (f *fakeArchive) urlscanResult(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/fake/urlscan/api/v1/result/"), "/")
	for _, s := range f.URLScan {
		if s.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"lists": map[string]any{"urls": s.URLs}})
			return
		}
	}
	http.NotFound(w, r)
}
