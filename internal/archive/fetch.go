package archive

// This file: fetching: a group's check on the current server, then its memento or WARC record.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

func (r *runner) fetch(ctx context.Context) error {
	gs, err := r.groups()
	if err != nil {
		return err
	}
	s := &r.st.Summary
	s.Digests = len(gs)
	// What a pass leaves out is counted by each pass (a resumed one looks
	// at those again); the rest counts once, as it is done once.
	s.Skipped["vendor library"], s.Skipped["over -max-files"] = 0, 0
	defer func() {
		for k, v := range s.Skipped {
			if v == 0 {
				delete(s.Skipped, k)
			}
		}
	}()
	n := 0
	for _, g := range gs {
		for _, u := range g.urls {
			r.namedURLs[u] = true // filed already: a chunk naming it is not filed again
		}
	}
	for i := 0; i < len(gs); i++ { // the fetched scripts' chunks join gs as it goes
		g := gs[i]
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if r.done[g.key] {
			continue
		}
		u, _ := url.Parse(g.latest.URL)
		if !r.o.Vendor && vendorRe.MatchString(path.Base(u.Path)) {
			s.Skipped["vendor library"]++
			continue
		}
		meta := &store.ArchiveSeen{First: g.first, Last: g.last, Captures: g.captures}
		if g.digest != "" && r.cur.sha1[g.digest] {
			s.Known++ // today's crawls have it: its endpoints are theirs
			r.markDone(g.key)
			continue
		}
		if g.digest != "" {
			if sha := r.store.BySHA1(g.digest); sha != "" {
				// Fetched by a run before, under another listing (a URL
				// OTX named): its archive side only.
				// A live copy of the same bytes (a script an old page named,
				// filed before this row was listed) makes it live_same.
				same := false
				if e, ok := r.store.Entry(sha); ok && e.Alive != nil && *e.Alive && slices.Contains(e.Sources, "live") {
					same = true
				}
				for _, src := range g.sources {
					r.store.Add(store.Record{SHA256: sha, URL: g.latest.URL, Source: src, Archive: meta, LiveSame: same})
				}
				s.Merged++
				r.markDone(g.key)
				continue
			}
		}
		if r.o.MaxFiles > 0 && n >= r.o.MaxFiles {
			s.Skipped["over -max-files"]++
			continue
		}
		n++
		var bodies [][]byte
		if kind := assetKind(g.latest); kind == "map" || kind == "manifest" {
			bodies, err = r.fetchAsset(ctx, g, meta, kind)
		} else {
			bodies, err = r.fetchOne(ctx, g, meta)
		}
		for _, b := range bodies {
			more := r.chunks(g, b)
			s.Digests += len(more)
			gs = append(gs, more...)
		}
		if errors.Is(err, errNotArchived) {
			s.NotArchived++
			r.markDone(g.key)
			continue
		}
		if err != nil {
			if errors.Is(err, ErrBlocked) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			s.Failed++
			r.o.Log("fetch %s: %v", g.latest.URL, err)
			continue
		}
		r.markDone(g.key)
		if n%20 == 0 {
			r.store.Flush()
			r.save()
		}
	}
	return nil
}

// fromWARC reads a content from Common Crawl's WARC file, and stores it.
func (r *runner) fromWARC(ctx context.Context, g *group, meta *store.ArchiveSeen, alive *bool) ([]byte, bool) {
	s := &r.st.Summary
	rec, err := r.o.CC.Fetch(ctx, g.warc.WARC, r.o.MaxBody)
	if err != nil || rec.Status != 200 || htmlLike(rec.Body) {
		if err != nil {
			r.o.Log("WARC %s: %v", g.warc.URL, err)
		}
		return nil, false
	}
	tags := []string{"archive", "commoncrawl-warc"}
	if g.digest != "" && store.SHA1B32(rec.Body) != g.digest {
		tags = append(tags, "digest-mismatch")
		s.Mismatch++
	}
	if _, err := r.store.Add(store.Record{Body: rec.Body, URL: g.warc.URL, Kind: "file", Via: "archive-warc", Source: "commoncrawl",
		MIME: rec.Header.Get("Content-Type"), Tags: tags, Alive: alive, Archive: meta}); err != nil {
		return nil, false
	}
	s.Fetched++
	s.WARC++
	return rec.Body, true
}

// fetchAsset gets a source map or a build manifest the archives hold, or
// an old script names (MAX-04): from the live server first, then the
// Wayback, then Common Crawl's WARC file. A map's own sources go to the
// store (endpoints are read from them as from scripts); a manifest's
// scripts are filed for the fetch, by chunks.
func (r *runner) fetchAsset(ctx context.Context, g *group, meta *store.ArchiveSeen, kind string) ([][]byte, error) {
	s := &r.st.Summary
	c := g.latest
	var body []byte
	var alive *bool
	src := "wayback"
	if r.o.Live {
		var live []byte
		alive, live, _ = r.liveCheckAs(ctx, c.URL, kind)
		if alive != nil && *alive {
			body, src = live, "live"
		}
	}
	if body == nil {
		a, err := r.memento(ctx, g, c)
		switch {
		case errors.Is(err, ErrBlocked) || ctx.Err() != nil:
			return nil, err
		case err == nil && a.Status == 200:
			if body, err = decode(a.Header.Get("Content-Encoding"), a.Body, r.o.MaxBody); err != nil {
				body = a.Body
			}
		case g.warc.WARC != nil && r.o.CC != nil:
			rec, werr := r.o.CC.Fetch(ctx, g.warc.WARC, r.o.MaxBody)
			if werr != nil || rec.Status != 200 {
				return nil, fmt.Errorf("%s: not in the Wayback, nor in its WARC file", c.URL)
			}
			body, src = rec.Body, "commoncrawl"
		case err != nil:
			return nil, err
		case notArchived(a, g, c):
			return nil, errNotArchived
		default:
			return nil, fmt.Errorf("memento: %d", a.Status)
		}
	}
	if htmlLike(body) {
		s.NotJS++
		return nil, nil
	}
	if kind == "manifest" {
		s.Manifests++
		return [][]byte{body}, nil
	}
	sm, err := sourcemap.Parse(body)
	if err != nil {
		s.NotJS++
		return nil, nil
	}
	s.Maps++
	if os.MkdirAll(filepath.Join(r.o.Dir, "maps"), 0o700) == nil {
		sum := sha256.Sum256(body)
		os.WriteFile(filepath.Join(r.o.Dir, "maps", hex.EncodeToString(sum[:])+".map"), body, 0o600)
	}
	for _, f := range sm.Files() {
		if f.Vendor {
			continue // a dependency's: noise for the target's endpoints
		}
		if _, err := r.store.Add(store.Record{Body: []byte(f.Content), URL: c.URL + "#" + f.Path, Kind: "source", Via: "archive-sourcemap",
			Source: src, Tags: []string{"archive", "sourcemap", "source:" + f.Path}, Alive: alive, Archive: meta}); err == nil {
			s.MapSources++
		}
	}
	return nil, nil
}

// probeTimeout is how long a memento of a URL only named (no digest) may
// take, its tries included.
var probeTimeout = 50 * time.Second

// probe reports whether a capture is of a URL only named, without a
// digest: a page, a script, OTX or urlscan named it.
func probe(g *group, c Capture) bool {
	return g.digest == "" || c.Source == fromHTML || c.Source == fromResolve
}

// memento gets a capture from the Wayback: patiently for one its index
// listed, briefly for a URL only named, which it may never have had (its
// answer then can be a 403, or none for minutes).
func (r *runner) memento(ctx context.Context, g *group, c Capture) (*Answer, error) {
	if !probe(g, c) {
		return r.o.Wayback.Client.Get(ctx, r.o.Wayback.Files, r.o.Wayback.Memento(c), int64(r.o.MaxBody))
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	a, err := r.o.Wayback.Client.Get(pctx, r.o.Wayback.Files, r.o.Wayback.Memento(c), int64(r.o.MaxBody))
	if err != nil && ctx.Err() == nil && pctx.Err() != nil {
		return nil, fmt.Errorf("memento: no answer in %s", probeTimeout)
	}
	return a, err
}

// notArchived reports whether the Wayback's answer for a URL listed without
// a digest (a page, a script, OTX or urlscan named it) says it has no
// copy: a 404, or the 403 it gives a URL it never captured (but its
// owner's exclusion, which is no answer about the URL).
func notArchived(a *Answer, g *group, c Capture) bool {
	if !probe(g, c) {
		return false
	}
	switch a.Status {
	case 404:
		return true
	case 403:
		return !bytes.Contains(a.Body, []byte("AdministrativeAccessControlException"))
	}
	return false
}

// errNotArchived: a script an old page or script named is not in the
// Wayback. Not a failure: it may be alive (then the live server's copy is
// kept), or never archived.
var errNotArchived = errors.New("not archived")

// fetchOne gets one content: from its old URL on the live server when that
// still serves it, else (or also) from the Wayback. It returns the bodies it
// kept, for the chunks they name.
func (r *runner) fetchOne(ctx context.Context, g *group, meta *store.ArchiveSeen) ([][]byte, error) {
	var kept [][]byte
	s := &r.st.Summary
	c := g.latest
	var alive *bool
	var live []byte
	var liveURL string
	if r.o.Live {
		alive, live, liveURL = r.liveCheck(ctx, c.URL)
	}
	liveSame := alive != nil && *alive && g.digest != "" && store.SHA1B32(live) == g.digest
	if alive != nil && *alive && g.digest == "" && r.cur.sha1[store.SHA1B32(live)] {
		// A URL without a digest (urlscan, OTX) that serves today's script:
		// the crawls hold it; no history of it.
		s.HeldAfter++
		return nil, nil
	}
	if alive != nil && *alive {
		s.Alive++
		tags := []string{"archive-url"}
		if liveURL != c.URL {
			tags = append(tags, "https-upgrade")
		}
		r.store.Add(store.Record{Body: live, URL: liveURL, Kind: "file", Via: "archive-live", Source: "live", Tags: tags, Alive: alive})
		kept = append(kept, live)
	}
	if liveSame {
		s.LiveSame++
		r.store.Add(store.Record{Body: live, URL: c.URL, Kind: "file", Via: "archive-live", Source: "wayback", Tags: []string{"archive"},
			Alive: alive, LiveSame: true, Archive: meta})
		s.Fetched++
		return kept, nil
	}
	a, err := r.memento(ctx, g, c)
	if errors.Is(err, ErrBlocked) || ctx.Err() != nil {
		return kept, err
	}
	if (err != nil || a.Status != 200) && g.warc.WARC != nil && r.o.CC != nil {
		// The Wayback has no copy, Common Crawl's WARC file has (MAX-01).
		if body, ok := r.fromWARC(ctx, g, meta, alive); ok {
			return append(kept, body), nil
		}
	}
	if err != nil {
		return kept, err
	}
	if notArchived(a, g, c) {
		// A URL a page, a script, OTX or urlscan named, without a digest:
		// the Wayback need not have it (alive, it is kept from the live
		// server).
		return kept, errNotArchived
	}
	if a.Status != 200 {
		return kept, fmt.Errorf("memento: %d", a.Status)
	}
	tags := []string{"archive"}
	if g.digest != "" && store.SHA1B32(a.Body) != g.digest {
		// The digest is of the bytes the archive stored: a coded body, or a
		// capture the archive moved to the nearest one.
		tags = append(tags, "digest-mismatch")
		s.Mismatch++
	}
	body, err := decode(a.Header.Get("Content-Encoding"), a.Body, r.o.MaxBody)
	if err != nil {
		body, tags = a.Body, append(tags, "content-coded")
	}
	if g.digest == "" && r.cur.sha1[store.SHA1B32(body)] {
		s.HeldAfter++ // today's script, archived under a URL listed without a digest
		return kept, nil
	}
	if htmlLike(body) {
		s.NotJS++ // an archived error page
		return kept, nil
	}
	if c.Source == fromHTML || c.Source == fromResolve {
		tags = append(tags, c.Source)
	}
	if _, err := r.store.Add(store.Record{Body: body, URL: c.URL, Kind: "file", Via: "archive", Source: "wayback", MIME: a.Header.Get("Content-Type"),
		Tags: tags, Alive: alive, Archive: meta}); err != nil {
		return kept, err
	}
	s.Fetched++
	return append(kept, body), nil
}

// liveCheck asks the target for an old script's URL, as a browser would
// without a session, if its host is one the crawls reached (or the target
// itself) and the URL carries no credential: nil when not asked. The
// Wayback keeps most URLs as http://, which today's server sends on to
// https://: the same URL over https is asked then (ARC-01), and where the
// copy answered is returned.
func (r *runner) liveCheck(ctx context.Context, raw string) (*bool, []byte, string) {
	return r.liveCheckAs(ctx, raw, "script")
}

// liveCheckAs is liveCheck for a kind of asset: a map or a manifest is JSON.
// Each URL is asked once a run, whatever number of versions it has.
func (r *runner) liveCheckAs(ctx context.Context, raw, kind string) (*bool, []byte, string) {
	if u, err := url.Parse(raw); err != nil || r.o.Sender == nil || !r.o.LiveHosts[u.Host] || credential(u) {
		return nil, nil, ""
	}
	key := kind + " " + raw
	r.livesMu.Lock()
	if a, ok := r.lives[key]; ok {
		r.livesMu.Unlock()
		return a.alive, a.body, a.url
	}
	r.livesMu.Unlock()
	alive, body, at := r.liveAsk(ctx, raw, kind)
	if ctx.Err() == nil {
		r.livesMu.Lock()
		if r.lives == nil {
			r.lives = map[string]liveAns{}
		}
		r.lives[key] = liveAns{alive, body, at}
		r.livesMu.Unlock()
	}
	return alive, body, at
}

func (r *runner) liveAsk(ctx context.Context, raw, kind string) (*bool, []byte, string) {
	u, err := url.Parse(raw)
	if err != nil || r.o.Sender == nil || !r.o.LiveHosts[u.Host] || credential(u) {
		return nil, nil, ""
	}
	no := false
	ans, err := r.ask(ctx, u, raw)
	if up := upgrade(u, ans, err); up != nil && r.o.LiveHosts[up.Host] {
		u = up
		ans, err = r.ask(ctx, u, raw)
	}
	if errors.Is(err, replay.ErrHostBlocked) || err == nil && ans.Block != nil {
		// A CDN/WAF answered in the server's place: whether it still
		// serves the file is not known (round 25H); the archive's copy is
		// read all the same.
		return nil, nil, ""
	}
	if err != nil || ans.Err != "" {
		return &no, nil, ""
	}
	ct := strings.ToLower(ans.Header["content-type"])
	ok := ans.Status == 200 && !htmlLike(ans.Body) && (ct == "" || strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") || strings.Contains(ct, "text/plain"))
	if kind != "script" {
		b := bytes.TrimSpace(ans.Body)
		ok = ans.Status == 200 && len(b) > 0 && b[0] == '{' && (ct == "" || strings.Contains(ct, "json") || strings.Contains(ct, "text/plain") || strings.Contains(ct, "octet-stream"))
	}
	if !ok {
		return &no, nil, ""
	}
	yes := true
	return &yes, ans.Body, u.String()
}

func (r *runner) ask(ctx context.Context, u *url.URL, item string) (replay.Answer, error) {
	target := u.EscapedPath()
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}
	req := "GET " + target + " HTTP/1.1\r\nHost: " + u.Host + "\r\nAccept: */*\r\n\r\n"
	return r.o.Sender.Send(ctx, []byte(req), u.Scheme, "live-check", "archive", item, nil)
}

// upgrade is the https:// URL to ask after an http:// one: when the server
// sent it on to the same host's same path and query over https, or when
// nothing answered on port 80. Nil otherwise: a redirect elsewhere (a
// login page, a soft 404) is no copy of the script.
func upgrade(u *url.URL, ans replay.Answer, err error) *url.URL {
	if u.Scheme != "http" {
		return nil
	}
	if err != nil {
		return nil // not sent: out of scope, over the budget, the run stopped
	}
	if ans.Err != "" { // sent, and no answer: nothing listens on port 80
		if u.Port() != "" {
			return nil
		}
		up := *u
		up.Scheme = "https"
		return &up
	}
	switch ans.Status {
	case 301, 302, 303, 307, 308:
	default:
		return nil
	}
	loc, err := u.Parse(ans.Header["location"])
	if err != nil || loc.Scheme != "https" || !strings.EqualFold(loc.Hostname(), u.Hostname()) ||
		loc.EscapedPath() != u.EscapedPath() || loc.RawQuery != u.RawQuery {
		return nil
	}
	loc.Fragment, loc.User = "", nil
	return loc
}

// htmlLike reports whether a body is a page, not a script: an SPA's
// fallback, a soft 404, an archived error.
func htmlLike(b []byte) bool {
	t := strings.ToLower(strings.TrimSpace(string(b[:min(len(b), 512)])))
	return strings.HasPrefix(t, "<!doctype html") || strings.HasPrefix(t, "<html") || strings.HasPrefix(t, "<head") ||
		(strings.HasPrefix(t, "<") && strings.Contains(t, "<body"))
}
