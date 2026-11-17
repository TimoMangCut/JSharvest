package archive

// This file: the done log, and the captures grouped by canonical URL for the fetch.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"time"
)

func (r *runner) loadDone() {
	f, err := os.Open(filepath.Join(r.o.Dir, "done.log"))
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		r.done[sc.Text()] = true
	}
}

func (r *runner) isDone(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done[key]
}

func (r *runner) markDone(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done[key] {
		return
	}
	r.done[key] = true
	if r.o.Dir == "" {
		return
	}
	if r.doneBuf == nil {
		f, err := appendFile(filepath.Join(r.o.Dir, "done.log"))
		if err != nil {
			return
		}
		r.doneFile = f
		r.doneBuf = bufio.NewWriterSize(f, 64<<10)
	}
	fmt.Fprintln(r.doneBuf, key)
	_ = r.doneBuf.Flush()
}

// group is one content of the archives: the captures of one digest, or
// of one URL a source lists without a digest (OTX).
type group struct {
	key      string
	digest   string
	latest   Capture // the newest capture with a time stamp to fetch it by
	other    Capture // the newest of another archive, when the Wayback has none
	revisit  Capture // the newest revisit, when the Wayback has nothing else
	warc     Capture // the newest of Common Crawl's with a WARC range, for when the Wayback fails
	urls     []string
	sources  []string
	first    time.Time
	last     time.Time
	captures int
}

var vendorRe = regexp.MustCompile(`(?i)(^|[/._-])(vendors?|chunk-vendors|polyfills?|jquery|react(-dom)?|angular|vue|lodash|moment|bootstrap|gtag|analytics|gtm|recaptcha|hotjar|sentry|zone)([/._~-]|$)`)

func (r *runner) groups() ([]*group, error) {
	r.flushFiles()
	f, err := os.Open(filepath.Join(r.o.Dir, "js.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	by := map[string]*group{}
	digestOf := map[string]string{} // URL → a digest the CDX gives it
	var noDigest []Capture
	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	for {
		var c Capture
		if err := dec.Decode(&c); err == io.EOF {
			break
		} else if err != nil {
			break // a line cut by a kill: what came before stands
		}
		if c.Digest == "" {
			noDigest = append(noDigest, c)
			continue
		}
		digestOf[c.URL] = c.Digest
		g := by[c.Digest]
		if g == nil {
			g = &group{key: c.Digest, digest: c.Digest, first: c.Time}
			by[c.Digest] = g
		}
		g.captures++
		g.urls = appendNew(g.urls, c.URL)
		g.sources = appendNew(g.sources, c.Source)
		if !c.Time.IsZero() && (g.first.IsZero() || c.Time.Before(g.first)) {
			g.first = c.Time
		}
		if c.Time.After(g.last) {
			g.last = c.Time
		}
		if !revisit(c) && c.Source == "wayback" && c.Time.After(g.latest.Time) {
			g.latest = c
		}
		if !revisit(c) && c.Source != "wayback" && c.Time.After(g.other.Time) {
			g.other = c
		}
		if revisit(c) && c.Source == "wayback" && c.Timestamp != "" && c.Time.After(g.revisit.Time) {
			g.revisit = c
		}
		if c.WARC != nil && !revisit(c) && c.Time.After(g.warc.Time) {
			g.warc = c
		}
	}
	for _, g := range by {
		switch {
		case g.latest.URL != "":
		case g.other.URL != "":
			// A content only another archive has (Common Crawl): fetched
			// through the Wayback by its URL, at its time stamp, which the
			// Wayback takes to its nearest capture (Reviewer round 5,
			// NEW-5.3-02).
			g.latest = g.other
		case g.revisit.URL != "":
			// Only revisits since -since: the first capture of these bytes is
			// older. The Wayback serves a revisit's memento with the bytes it
			// revisits (ARC-03).
			g.latest = g.revisit
		}
	}
	for _, c := range noDigest {
		if d, ok := digestOf[c.URL]; ok && by[d].latest.URL != "" {
			continue // the CDX has it, with its digest, and it is fetched so (ARC-04)
		}
		k := "url:" + c.URL
		if by[k] == nil {
			by[k] = &group{key: k, latest: c, urls: []string{c.URL}, sources: []string{c.Source}, first: c.Time, last: c.Time}
		}
		by[k].captures++
	}
	var out []*group
	for _, g := range by {
		if g.latest.URL == "" {
			continue // nothing to fetch it by
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].last.Equal(out[j].last) {
			return out[i].last.After(out[j].last)
		}
		return out[i].key < out[j].key
	})
	return out, nil
}

func appendNew(xs []string, x string) []string {
	if slices.Contains(xs, x) || len(xs) >= 20 {
		return xs
	}
	return append(xs, x)
}
