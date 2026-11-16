package archive

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/htmlscan"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// Old pages (CF-04a). An SPA's archived scripts are few, its archived pages
// many: the Wayback keeps https://host/ as text/html, and that page names
// the bundles (<script src="/static/js/main.8f91a2.js">). A site whose
// front page is behind a challenge today often serves those files as they
// are, from the CDN. So the newest captures of a few pages are read for the
// scripts they load and their inline code; each script then goes the way of
// an archived one: asked of the live server first, then of the Wayback at
// the page's time.

// Sources of the captures this file makes up for the fetch.
const (
	fromHTML    = "archive-html"    // named by an archived page
	fromResolve = "archive-resolve" // named by a fetched script (resolve.Static)
)

// page reports whether a capture is of an HTML page worth reading: its
// MIME type, a 200, no revisit, and a time stamp to ask the Wayback by (a
// page urlscan saw is no capture of the Wayback's).
func page(c Capture) bool {
	m := strings.ToLower(c.MIME)
	return (strings.Contains(m, "html") || m == "unk" && !script(c)) && c.Status == "200" && c.Timestamp != ""
}

// pagePick chooses the pages to read: the newest capture of each URL, the
// site's root first (it names the entry bundles), then the shallowest
// paths, then the newest.
func pagePick(caps []Capture, max int) []Capture {
	newest := map[string]Capture{}
	for _, c := range caps {
		if o, ok := newest[c.URL]; !ok || c.Time.After(o.Time) {
			newest[c.URL] = c
		}
	}
	var out []Capture
	for _, c := range newest {
		out = append(out, c)
	}
	depth := func(c Capture) int {
		u, err := url.Parse(c.URL)
		if err != nil {
			return 99
		}
		p := strings.Trim(u.Path, "/")
		if p == "" || p == "index.html" {
			if u.RawQuery == "" {
				return -1
			}
			return 0
		}
		return strings.Count(p, "/") + 1
	}
	sort.SliceStable(out, func(i, j int) bool {
		if di, dj := depth(out[i]), depth(out[j]); di != dj {
			return di < dj
		}
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.After(out[j].Time)
		}
		return out[i].URL < out[j].URL
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// challengePage reports an archived page that is a bot challenge's or
// vendor deny page's: the Wayback archives those too, and their scripts are
// the vendor's.
func challengePage(p htmlscan.Page) bool {
	t := strings.ToLower(p.Title)
	if strings.Contains(t, "just a moment") ||
		strings.Contains(t, "attention required") ||
		(strings.Contains(t, "cloudflare") &&
			(strings.Contains(t, "access denied |") ||
				strings.Contains(t, "used cloudflare to restrict access") ||
				strings.Contains(t, "you are being rate limited"))) {
		return true
	}
	for _, f := range p.Files() {
		if detect.ChallengeURL(f) {
			return true
		}
	}
	for _, in := range p.Inline() {
		l := strings.ToLower(in)
		if detect.IsChallengeScript("", "", "inline", []byte(in), false) &&
			(strings.Contains(l, "_cf_chl_opt") || strings.Contains(l, "sparrow.cloudflare.com/api/v1/event")) {
			return true
		}
	}
	return false
}

// pages reads the newest captures of a few old pages for the scripts they
// name. Those go to js.jsonl as captures without a digest, so the fetch
// asks the live server for them, then the Wayback at the page's time; the
// inline code goes to the store.
func (r *runner) pages(ctx context.Context) error {
	if r.o.MaxHTML <= 0 {
		return nil
	}
	f, err := os.Open(filepath.Join(r.o.Dir, "html.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var caps []Capture
	dec := json.NewDecoder(f)
	for {
		var c Capture
		if err := dec.Decode(&c); err != nil {
			break // io.EOF, or a line cut by a kill: what came before stands
		}
		caps = append(caps, c)
	}
	f.Close()
	s := &r.st.Summary
	jsEnc := json.NewEncoder(r.js)
	// -max-html counts the pages read, not those tried: a capture that is
	// no 200 or a challenge's leaves its turn to the next (MAX-03). Those
	// read by a run before count too.
	read := 0
	for _, c := range pagePick(caps, 0) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if read >= r.o.MaxHTML {
			break
		}
		key := "html:" + c.Timestamp + " " + c.URL
		if r.done[key] {
			if r.done["read:"+key] {
				read++
			}
			continue
		}
		a, err := r.o.Wayback.Client.Get(ctx, r.o.Wayback.Files, r.o.Wayback.Memento(c), int64(r.o.MaxBody))
		if err != nil {
			if errors.Is(err, ErrBlocked) || ctx.Err() != nil {
				return err
			}
			s.Failed++
			r.o.Log("page %s: %v", c.URL, err)
			continue
		}
		if a.Status != 200 {
			s.Skipped["page memento not 200"]++
			r.markDone(key)
			continue
		}
		body, err := decode(a.Header.Get("Content-Encoding"), a.Body, r.o.MaxBody)
		if err != nil {
			body = a.Body
		}
		s.Pages++
		p := htmlscan.Scan(body, c.URL)
		if challengePage(p) {
			s.Skipped["challenge page"]++
			r.markDone(key)
			continue
		}
		read++
		meta := &store.ArchiveSeen{First: c.Time, Last: c.Time, Captures: 1}
		for _, code := range p.Inline() {
			if detect.IsChallengeScript("", "", "inline", []byte(code), false) {
				continue
			}
			if _, err := r.store.Add(store.Record{Body: []byte(code), URL: c.URL, Kind: "inline", Via: fromHTML, Source: "wayback",
				Tags: []string{"archive", fromHTML}, Archive: meta}); err == nil {
				s.Inline++
			}
		}
		for _, src := range append(p.Files(), p.NextManifests()...) {
			if r.named(src) {
				jsEnc.Encode(Capture{URL: src, Time: c.Time, Timestamp: c.Timestamp, Source: fromHTML})
				s.PageScripts++
			}
		}
		r.markDone("read:" + key)
		r.markDone(key)
	}
	return nil
}

// named reports whether a script an old page or script names may be
// fetched: in scope, no credential in its URL, not a vendor's challenge or
// CDN helper, and not filed before.
func (r *runner) named(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !r.o.InScope(u.Hostname()) {
		return false
	}
	if credential(u) || detect.ChallengeURL(raw) || detect.InfraURL(raw) {
		return false
	}
	if r.namedURLs[raw] {
		return false
	}
	r.namedURLs[raw] = true
	return true
}

// chunks finds the scripts a fetched one would load (resolve.Static: the
// bundler's chunk map, import(), a manifest), and files them for this
// fetch, and for a resumed one, as captures at the same time as the
// script's own.
func (r *runner) chunks(g *group, body []byte) []*group {
	if len(body) == 0 || len(body) > maxResolveBody {
		return nil
	}
	c := g.latest
	var out []*group
	jsEnc := json.NewEncoder(r.js)
	// The page that ran it is not known: its origin's root stands for it
	// (ARC-04). A worker's or Vite's path is the document's, not the
	// script's; webpack's chunks go by the script's URL either way.
	page := c.URL
	if u, err := url.Parse(c.URL); err == nil && u.Host != "" {
		page = u.Scheme + "://" + u.Host + "/"
	}
	var named []string
	switch assetKind(c) {
	case "manifest": // the scripts of a build (MAX-04)
		named = resolve.ManifestScripts(body, c.URL)
	case "map":
	default:
		for _, cand := range resolve.Static(body, c.URL, page) {
			named = append(named, cand.URL)
		}
		// The map the script names (an old build that shipped its maps).
		if ref, ok := sourcemap.Find(c.URL, nil, body, false); ok && ref.URL != "" {
			named = append(named, ref.URL)
		}
	}
	for _, u := range named {
		if !r.named(u) {
			continue
		}
		nc := Capture{URL: u, Time: c.Time, Timestamp: c.Timestamp, Source: fromResolve}
		jsEnc.Encode(nc)
		r.st.Summary.Resolved++
		out = append(out, &group{key: "url:" + u, latest: nc, urls: []string{u}, sources: []string{fromResolve},
			first: c.Time, last: c.Time, captures: 1})
	}
	return out
}

const maxResolveBody = 8 << 20
