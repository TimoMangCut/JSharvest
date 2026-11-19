package archive

// This file: listing: every source at once, and taking their captures (which are scripts, which are assets, which URLs carry a credential).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/resolve"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// list lists every source at once (MAX-05): each is its own service, with
// its own budget, and a slow or blocked one keeps no other waiting. What
// they share (the state, the files) is r.mu's. Only parent cancellation
// (SIGINT) ends them all; a blocked or failed source records its place so
// pages/fetch/history still process everything collected so far.
func (r *runner) list(ctx context.Context) error {
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var fatal error
	for _, src := range r.o.Sources {
		var list func(context.Context) error
		switch src {
		case "wayback":
			list = r.listWayback
		case "otx":
			list = r.listOTX
		case "commoncrawl":
			list = r.listCC
		case "urlscan":
			list = r.listURLScan
		default:
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := list(lctx)
			r.mu.Lock()
			defer r.mu.Unlock()
			switch {
			case err == nil:
			case ctx.Err() != nil:
				if fatal == nil {
					fatal = ctx.Err()
				}
				cancel()
			case errors.Is(err, ErrExcluded):
				r.noteLocked(src + ": " + err.Error())
			case errors.Is(err, ErrBlocked):
				r.recordBlockLocked(src, err)
				r.partial = true
			default:
				// One source down is no reason to leave the others (ARC-05):
				// its place is kept, and the next run lists it on.
				r.noteLocked(src + ": " + err.Error() + "; left for the next run, which lists it on")
				r.partial = true
			}
		}()
	}
	wg.Wait()
	r.flushFiles()
	return fatal
}

// took files a page of a source's captures and moves its place, at once.
func (r *runner) took(caps []Capture, move func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.take(caps)
	if move != nil {
		move()
	}
	r.saveMaybeLocked()
}

func (r *runner) listWayback(ctx context.Context) error {
	if r.st.Wayback.Done {
		return nil
	}
	if r.o.Mode == ModeResume {
		r.mu.Lock()
		r.partial = true
		if r.st.Wayback.NumPages > 0 {
			r.updateWaybackShardSummaryLocked(r.st.Wayback.NumPages)
		}
		r.mu.Unlock()
		return nil
	}
	if r.o.Wayback.Sharded && r.st.Wayback.Resume == "" {
		r.mu.Lock()
		np := r.st.Wayback.NumPages
		r.mu.Unlock()
		supported := np > 0
		if np == 0 {
			var err error
			np, supported, err = r.o.Wayback.NumPages(ctx, r.o.Host)
			if err != nil {
				return err
			}
			if supported {
				if np == 0 {
					r.mu.Lock()
					r.st.Wayback.Done = true
					r.saveLocked()
					r.mu.Unlock()
					return nil
				}
				r.mu.Lock()
				r.st.Wayback.NumPages = np
				if r.st.Wayback.PagesDone == nil {
					r.st.Wayback.PagesDone = map[int]bool{}
				}
				r.saveLocked()
				r.mu.Unlock()
			}
		}
		if supported && np > 0 {
			return r.listWaybackSharded(ctx, np)
		}
	}
	for pages := 0; !r.st.Wayback.Done; pages++ {
		if r.o.MaxPages > 0 && pages >= r.o.MaxPages {
			// Its place is kept: the next run lists on from it (Reviewer
			// round 5, NEW-5.3-04).
			r.mu.Lock()
			r.noteLocked("wayback: stopped at -max-pages; more remain, which the next run lists on")
			r.partial = true
			r.mu.Unlock()
			break
		}
		caps, next, err := r.o.Wayback.Page(ctx, r.o.Host, r.st.Wayback.Resume)
		if err != nil {
			return err
		}
		r.took(caps, func() { r.st.Wayback.Resume, r.st.Wayback.Done = next, next == "" })
		r.mu.Lock()
		n := r.st.Summary.Listed["wayback"]
		r.mu.Unlock()
		r.o.Log("wayback: %d captures listed", n)
	}
	return nil
}

func gcdInt(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// coprimeStrideOrder generates a deterministic permutation of 0..numPages-1
// starting at 0 and stepping by an integer coprime to numPages near the golden
// ratio (~0.618). When -max-pages or upstream rate limits stop a run early,
// sampled shards disperse evenly across the SURT keyspace instead of clustering
// inside a single URL prefix, while PagesDone tracks exact completion across runs.
func coprimeStrideOrder(numPages int) []int {
	if numPages <= 0 {
		return nil
	}
	out := make([]int, numPages)
	if numPages == 1 {
		return out
	}
	stride := max(1, int(float64(numPages)*0.6180339887))
	if stride >= numPages {
		stride = 1
	}
	for gcdInt(stride, numPages) != 1 {
		stride++
		if stride >= numPages {
			stride = 1
		}
	}
	for i := 0; i < numPages; i++ {
		out[i] = (i * stride) % numPages
	}
	return out
}

func (r *runner) updateWaybackShardSummaryLocked(numPages int) {
	if numPages <= 0 {
		return
	}
	done := len(r.st.Wayback.PagesDone)
	if done > numPages {
		done = numPages
	}
	r.st.Summary.WaybackShardsTotal = numPages
	r.st.Summary.WaybackShardsDone = done
	r.st.Summary.WaybackListedPct = math.Round(float64(done)*1000/float64(numPages)) / 10
}

func (r *runner) listWaybackSharded(ctx context.Context, numPages int) error {
	var pending []int
	order := coprimeStrideOrder(numPages)
	r.mu.Lock()
	if r.st.Wayback.PagesDone == nil {
		r.st.Wayback.PagesDone = map[int]bool{}
	}
	r.updateWaybackShardSummaryLocked(numPages)
	for _, p := range order {
		if r.st.Wayback.PagesDone[p] {
			continue
		}
		if r.o.MaxPages > 0 && len(pending) >= r.o.MaxPages {
			r.noteLocked("wayback: stopped at -max-pages; more remain, which the next run lists on")
			r.partial = true
			break
		}
		pending = append(pending, p)
	}
	r.mu.Unlock()

	if len(pending) > 0 {
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()

		if r.o.Wayback != nil && r.o.Wayback.Index != nil {
			r.o.Wayback.Index.SetOnThrottle(func() {
				r.prefetchHalted.Store(true)
			})
			defer r.o.Wayback.Index.SetOnThrottle(nil)
		}

		var prefetchWG sync.WaitGroup
		var prefetchCh chan *group
		if r.o.Mode != ModeListOnly && r.o.MaxFiles == 0 && r.store != nil && r.cur != nil {
			prefetchCh = make(chan *group, 512)
			r.mu.Lock()
			r.prefetchCh = prefetchCh
			r.prefetchSeen = map[string]bool{}
			r.prefetchFam = map[string]int{}
			r.prefetchFirst = map[string]time.Time{}
			r.mu.Unlock()
			prefetchWorkers := min(max(r.workers()/2, 4), 8)
			for range prefetchWorkers {
				prefetchWG.Add(1)
				go func() {
					defer prefetchWG.Done()
					r.prefetchWorker(sctx, prefetchCh)
				}()
			}
		}

		cdxWorkers := min(max(r.workers(), 8), 16)
		if cdxWorkers > len(pending) {
			cdxWorkers = len(pending)
		}
		ch := make(chan int, len(pending))
		for _, p := range pending {
			ch <- p
		}
		close(ch)

		var wg sync.WaitGroup
		var errMu sync.Mutex
		var fatal error
		var failed []string

		for range cdxWorkers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for p := range ch {
					if sctx.Err() != nil {
						return
					}
					caps, err := r.o.Wayback.ShardPage(sctx, r.o.Host, p)
					if err != nil {
						errMu.Lock()
						if errors.Is(err, ErrBlocked) || errors.Is(err, ErrExcluded) || ctx.Err() != nil {
							if fatal == nil {
								fatal = err
							}
							cancel()
						} else {
							failed = append(failed, fmt.Sprintf("page %d: %v", p, err))
						}
						errMu.Unlock()
						continue
					}
					r.took(caps, func() {
						r.st.Wayback.PagesDone[p] = true
						r.updateWaybackShardSummaryLocked(numPages)
					})
					r.mu.Lock()
					n := r.st.Summary.Listed["wayback"]
					doneCnt := len(r.st.Wayback.PagesDone)
					pct := r.st.Summary.WaybackListedPct
					r.mu.Unlock()
					if doneCnt%10 == 0 || doneCnt == numPages {
						r.o.Log("wayback: %d/%d shards (%.1f%%, %d captures listed)", doneCnt, numPages, pct, n)
					}
				}
			}()
		}
		wg.Wait()

		if prefetchCh != nil {
			r.mu.Lock()
			r.prefetchCh = nil
			r.mu.Unlock()
			close(prefetchCh)
			prefetchWG.Wait()
		}

		if fatal != nil {
			return fatal
		}
		if len(failed) > 0 {
			return fmt.Errorf("%d of %d shards failed (%s)", len(failed), numPages, failed[0])
		}
	}

	r.mu.Lock()
	r.updateWaybackShardSummaryLocked(numPages)
	if len(r.st.Wayback.PagesDone) >= numPages {
		r.st.Wayback.Done = true
		r.saveLocked()
	}
	r.mu.Unlock()
	return nil
}

func (r *runner) listOTX(ctx context.Context) error {
	for !r.st.OTX.Done {
		page := r.st.OTX.Page + 1
		caps, more, err := r.o.OTX.Page(ctx, r.o.Host, page)
		if err != nil {
			return err
		}
		r.took(caps, func() { r.st.OTX.Page, r.st.OTX.Done = page, !more })
	}
	return r.extra(ctx, "otx", func(hctx context.Context, host string) error {
		for page := 1; page <= extraPages; page++ {
			caps, more, err := r.o.OTX.Page(hctx, host, page)
			if err != nil {
				return err
			}
			r.took(caps, nil)
			if !more {
				break
			}
		}
		return nil
	})
}

// MaxExtraHosts bounds how many of the target's other hosts OTX and urlscan
// are asked of (0: unlimited); extraPages, how many pages of each.
const (
	MaxExtraHosts = 0
	extraPages    = 5
)

// extra lists a source's captures of each other host not listed yet,
// running multiple subdomains concurrently within the source's rate budget.
func (r *runner) extra(ctx context.Context, src string, list func(ctx context.Context, host string) error) error {
	var todo []string
	r.mu.Lock()
	for i, h := range r.o.ExtraHosts {
		if MaxExtraHosts > 0 && i >= MaxExtraHosts {
			break
		}
		key := src + " " + h
		if r.st.Extra[key] || strings.EqualFold(h, r.o.Host) {
			continue
		}
		todo = append(todo, h)
	}
	r.mu.Unlock()
	if len(todo) == 0 {
		return nil
	}

	ectx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := min(max(r.workers()/2, 2), 4)
	if workers > len(todo) {
		workers = len(todo)
	}
	ch := make(chan string, len(todo))
	for _, h := range todo {
		ch <- h
	}
	close(ch)

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var fatal error
	var firstErr error

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range ch {
				if ectx.Err() != nil {
					return
				}
				if err := list(ectx, h); err != nil {
					errMu.Lock()
					if errors.Is(err, ErrBlocked) || ctx.Err() != nil {
						if fatal == nil {
							fatal = fmt.Errorf("%s: %w", h, err)
						}
						cancel()
					} else if firstErr == nil {
						firstErr = fmt.Errorf("%s: %w", h, err)
					}
					errMu.Unlock()
					continue
				}
				key := src + " " + h
				r.mu.Lock()
				if r.st.Extra == nil {
					r.st.Extra = map[string]bool{}
				}
				r.st.Extra[key] = true
				r.saveLocked()
				r.mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if fatal != nil {
		return fatal
	}
	return firstErr
}

func (r *runner) listCC(ctx context.Context) error {
	cc := &r.st.CC
	if cc.Done {
		return nil
	}
	if r.o.Mode == ModeResume {
		r.mu.Lock()
		r.partial = true
		r.mu.Unlock()
		return nil
	}
	if cc.Collections == nil {
		cols, err := r.o.CC.Latest(ctx)
		if err != nil {
			return err
		}
		r.mu.Lock()
		cc.Collections = cols
		r.mu.Unlock()
	}
	r.mu.Lock()
	if cc.Next == nil {
		cc.Next = map[string]int{}
	}
	if cc.Listed == nil {
		cc.Listed = map[string]bool{}
	}
	cols := slices.Clone(cc.Collections)
	r.mu.Unlock()
	// Query Common Crawl collections concurrently within CC.Budget so a 504 on
	// the newest collection never stalls the older ones sequentially (MAX-01).
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var fatal error
	var failed []string
	for _, coll := range cols {
		r.mu.Lock()
		listed := cc.Listed[coll]
		startPage := cc.Next[coll]
		r.mu.Unlock()
		if listed {
			continue
		}
		wg.Add(1)
		go func(coll string, page int) {
			defer wg.Done()
			next, err := r.o.CC.List(cctx, coll, r.o.Host, page, func(caps []Capture) {
				page++
				r.took(caps, func() { cc.Next[coll] = page })
			})
			r.mu.Lock()
			cc.Next[coll] = next
			if err == nil {
				cc.Listed[coll] = true
			}
			r.saveMaybeLocked()
			r.mu.Unlock()
			if err != nil {
				errMu.Lock()
				if errors.Is(err, ErrBlocked) || ctx.Err() != nil {
					if fatal == nil {
						fatal = err
					}
					cancel()
				} else {
					failed = append(failed, coll+": "+err.Error())
				}
				errMu.Unlock()
			}
		}(coll, startPage)
	}
	wg.Wait()
	if fatal != nil {
		return fatal
	}
	if len(failed) > 0 {
		slices.Sort(failed)
		return fmt.Errorf("%d of %d collections failed (%s)", len(failed), len(cols), strings.Join(failed, "; "))
	}
	r.mu.Lock()
	cc.Done = true
	r.mu.Unlock()
	return nil
}

// URLLine is a line of urls.jsonl: a URL the archives hold, and what of.
type URLLine struct {
	URL      string    `json:"url"`
	Source   string    `json:"source"`
	First    time.Time `json:"first,omitzero"`
	Last     time.Time `json:"last,omitzero"`
	Captures int       `json:"captures"`
	MIME     string    `json:"mime,omitempty"`
	Statuses []string  `json:"statuses,omitempty"`
	Script   bool      `json:"script,omitempty"`
	// Credential says the URL carries one (masked here): never sent.
	Credential bool `json:"credential,omitempty"`
}

var scriptExtRe = regexp.MustCompile(`(?i)\.(m|c)?js$`)

// script reports whether a capture is of a script: by the extension of
// its path, or by a JavaScript MIME type.
func script(c Capture) bool {
	m := strings.ToLower(c.MIME)
	if strings.Contains(m, "javascript") || strings.Contains(m, "ecmascript") {
		return true
	}
	u, err := url.Parse(c.URL)
	return err == nil && scriptExtRe.MatchString(u.Path)
}

// assetKind is what an archived URL is to the fetch: a script, a source
// map, a build manifest naming a build's scripts (MAX-04); "" for none.
func assetKind(c Capture) string {
	if script(c) {
		return "script"
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return ""
	}
	if p := strings.ToLower(u.Path); strings.HasSuffix(p, ".js.map") || strings.HasSuffix(p, ".mjs.map") {
		return "map"
	}
	if resolve.Manifest(c.URL) != "" {
		return "manifest"
	}
	return ""
}

func revisit(c Capture) bool {
	return c.Status == "-" || strings.EqualFold(c.MIME, "warc/revisit")
}

// signedRe names query parameters that sign or carry a credential, past
// the redactor's names.
var signedRe = regexp.MustCompile(`(?i)^(x-amz-(signature|credential|security-token)|signature|sig|se|sp|sv|policy|key-pair-id|expires|access_token|id_token|code|state|ticket)$`)

// credential reports whether a URL carries a credential in its query.
func credential(u *url.URL) bool {
	for k := range u.Query() {
		if traffic.Sensitive(k) || signedRe.MatchString(k) {
			return true
		}
	}
	return false
}

var redactor = traffic.NewRedactor()

// take files a page of captures: the URLs, adjacent rows of one URL as
// one line, and the scripts' captures for the fetch.
func (r *runner) take(caps []Capture) {
	s := &r.st.Summary
	var cur *URLLine
	flush := func() {
		if cur != nil {
			r.encodeURLLocked(cur)
			cur = nil
		}
	}
	for _, c := range caps {
		s.Listed[c.Source]++
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !r.o.InScope(u.Hostname()) {
			s.Skipped["out of scope"]++
			continue
		}
		if !r.o.Since.IsZero() && !c.Time.IsZero() && c.Time.Before(r.o.Since) {
			s.Skipped["before -since"]++
			continue
		}
		cred := credential(u)
		shown := c.URL
		if cred {
			shown = redactor.URL(c.URL)
			if !r.cred[shown] && len(s.Credential) < 200 {
				r.cred[shown] = true
				s.Credential = append(s.Credential, shown)
			}
		}
		if r.seenURLs != nil && shown != "" {
			h := sha256.Sum256([]byte(shown))
			r.seenURLs[[16]byte(h[:16])] = struct{}{}
		}
		if cur == nil || cur.URL != shown || cur.Source != c.Source {
			flush()
			cur = &URLLine{URL: shown, Source: c.Source, MIME: c.MIME, Script: script(c), Credential: cred, First: c.Time}
		}
		cur.Captures++
		if c.Time.After(cur.Last) {
			cur.Last = c.Time
		}
		if !c.Time.IsZero() && (cur.First.IsZero() || c.Time.Before(cur.First)) {
			cur.First = c.Time
		}
		if c.Status != "" && !slices.Contains(cur.Statuses, c.Status) {
			cur.Statuses = append(cur.Statuses, c.Status)
		}
		if !cred && !revisit(c) && page(c) {
			s.HTML++
			r.takeHTMLLocked(c)
			if r.html != nil {
				_ = json.NewEncoder(r.html).Encode(c)
			}
		}
		kind := assetKind(c)
		if kind == "" || cred {
			continue
		}
		if revisit(c) {
			s.Revisits++
		} else if c.Status != "" && c.Status != "200" {
			continue
		}
		s.JS++
		r.encodeJSLocked(c)
		r.maybePrefetchLocked(c, u, kind)
	}
	flush()
}

// maybePrefetchLocked streams up to 2 representative digest-backed script
// captures per Canonical Family to background Memento Prefetch Workers while
// sharded Wayback CDX listing is still running. r.mu is held.
func (r *runner) maybePrefetchLocked(c Capture, u *url.URL, kind string) {
	if r.prefetchCh == nil || kind != "script" || c.Source != "wayback" || c.Digest == "" || revisit(c) || c.Status != "200" {
		return
	}
	if !r.o.Vendor && vendorRe.MatchString(path.Base(u.Path)) {
		return
	}
	if r.done[c.Digest] || r.done["pre:"+c.Digest] || r.done["dead:"+c.Digest] || r.prefetchSeen[c.Digest] {
		return
	}
	if r.cur != nil && r.cur.sha1[c.Digest] {
		return
	}
	if r.store != nil && r.store.BySHA1(c.Digest) != "" {
		return
	}
	fam := u.Host + u.Path
	if g := (&group{latest: c}); familyOfGroup(g) != "" {
		fam = familyOfGroup(g)
	}
	cnt := r.prefetchFam[fam]
	if cnt >= 2 {
		return
	}
	if cnt == 1 {
		first := r.prefetchFirst[fam]
		if c.Time.IsZero() || first.IsZero() || c.Time.Sub(first).Abs() < 60*24*time.Hour {
			return
		}
	}
	g := &group{
		key:      c.Digest,
		digest:   c.Digest,
		latest:   c,
		urls:     []string{c.URL},
		sources:  []string{c.Source},
		first:    c.Time,
		last:     c.Time,
		captures: 1,
	}
	select {
	case r.prefetchCh <- g:
		r.prefetchSeen[c.Digest] = true
		r.prefetchFam[fam] = cnt + 1
		if cnt == 0 && !c.Time.IsZero() {
			r.prefetchFirst[fam] = c.Time
		}
	default:
	}
}

func seedSeenURLs(p string, dst map[[16]byte]struct{}) {
	eachLine(p, func(b []byte) {
		var l struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(b, &l) == nil && l.URL != "" {
			h := sha256.Sum256([]byte(l.URL))
			dst[[16]byte(h[:16])] = struct{}{}
		}
	})
}

// distinctURLs counts the URLs urls.jsonl names, each once: a URL two
// sources list, or one listing's rows apart, is one (ARC-06).
func distinctURLs(p string) int {
	seen := map[[16]byte]struct{}{}
	seedSeenURLs(p, seen)
	return len(seen)
}
