package archive

// This file: listing: every source at once, and taking their captures (which are scripts, which are assets, which URLs carry a credential).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/resolve"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// list lists every source at once (MAX-05): each is its own service, with
// its own budget, and a slow one keeps no other waiting. What they share
// (the state, the files) is r.mu's. A source down is noted and listed on by
// the next run; an archive that refuses our connections, or a stop, ends
// them all.
func (r *runner) list(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
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
			err := list(ctx)
			r.mu.Lock()
			defer r.mu.Unlock()
			switch {
			case err == nil:
			case errors.Is(err, ErrExcluded):
				r.st.Summary.Notes = append(r.st.Summary.Notes, src+": "+err.Error())
			case errors.Is(err, ErrBlocked) || ctx.Err() != nil:
				// Refused, or stopped (SIGINT, or another source refused):
				// the run stops, its places kept.
				if fatal == nil {
					fatal = fmt.Errorf("%s: %w", src, err)
				}
				cancel()
			default:
				// One source down is no reason to leave the others (ARC-05):
				// its place is kept, and the next run lists it on.
				r.noteLocked(src + ": " + err.Error() + "; left for the next run, which lists it on")
				r.partial = true
			}
		}()
	}
	wg.Wait()
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
	r.saveLocked()
}

func (r *runner) listWayback(ctx context.Context) error {
	if r.st.Wayback.Done {
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

func (r *runner) listWaybackSharded(ctx context.Context, numPages int) error {
	var pending []int
	r.mu.Lock()
	if r.st.Wayback.PagesDone == nil {
		r.st.Wayback.PagesDone = map[int]bool{}
	}
	for p := 0; p < numPages; p++ {
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

		cdxWorkers := min(max(r.workers()/2, 2), 6)
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
					})
					r.mu.Lock()
					n := r.st.Summary.Listed["wayback"]
					doneCnt := len(r.st.Wayback.PagesDone)
					r.mu.Unlock()
					if doneCnt%5 == 0 || doneCnt == numPages {
						r.o.Log("wayback: %d/%d shards (%d captures listed)", doneCnt, numPages, n)
					}
				}
			}()
		}
		wg.Wait()

		if fatal != nil {
			return fatal
		}
		if len(failed) > 0 {
			return fmt.Errorf("%d of %d shards failed (%s)", len(failed), numPages, failed[0])
		}
	}

	r.mu.Lock()
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
	r.mu.Unlock()
	// Each collection on its own: one that fails (the newest is the most
	// asked, and answers 504 the most) leaves the others to list (MAX-01).
	var failed []string
	for _, coll := range cc.Collections {
		r.mu.Lock()
		listed := cc.Listed[coll]
		page := cc.Next[coll]
		r.mu.Unlock()
		if listed {
			continue
		}
		next, err := r.o.CC.List(ctx, coll, r.o.Host, page, func(caps []Capture) {
			page++
			r.took(caps, func() { cc.Next[coll] = page })
		})
		r.mu.Lock()
		cc.Next[coll] = next
		if err == nil {
			cc.Listed[coll] = true
		}
		r.saveLocked()
		r.mu.Unlock()
		if err != nil {
			if errors.Is(err, ErrBlocked) || ctx.Err() != nil {
				return err
			}
			failed = append(failed, coll+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d collections failed (%s)", len(failed), len(cc.Collections), strings.Join(failed, "; "))
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
	urlEnc, jsEnc, htmlEnc := json.NewEncoder(r.urls), json.NewEncoder(r.js), json.NewEncoder(r.html)
	var cur *URLLine
	flush := func() {
		if cur != nil {
			urlEnc.Encode(cur)
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
			htmlEnc.Encode(c)
		}
		if assetKind(c) == "" || cred {
			continue
		}
		if revisit(c) {
			s.Revisits++
		} else if c.Status != "" && c.Status != "200" {
			continue
		}
		s.JS++
		jsEnc.Encode(c)
	}
	flush()
}

// distinctURLs counts the URLs urls.jsonl names, each once: a URL two
// sources list, or one listing's rows apart, is one (ARC-06).
func distinctURLs(p string) int {
	seen := map[[16]byte]bool{}
	eachLine(p, func(b []byte) {
		var l struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(b, &l) == nil && l.URL != "" {
			h := sha256.Sum256([]byte(l.URL))
			seen[[16]byte(h[:16])] = true
		}
	})
	return len(seen)
}
