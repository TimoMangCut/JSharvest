package capture

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/chromedp/cdproto/cachestorage"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/detect"
)

// SweepCaches reads the JavaScript that service workers stored in
// CacheStorage for the given origins. A precaching service worker downloads
// every chunk of the app, but on its own schedule (Angular waits until the
// app is stable), and on a later run with the same profile it downloads
// nothing at all; the cache still has it all. It returns how many scripts
// it handed to the sink. ctx only stops the sweep early; the CDP calls run
// on the tab.
func (c *Capture) SweepCaches(ctx context.Context, origins []string) int {
	n := 0
	for _, origin := range origins {
		if ctx.Err() != nil {
			return n
		}
		cctx, cancel := context.WithTimeout(c.tab, c.opts.CallTimeout)
		res, err := chromedp.Call(cctx, cachestorage.RequestCacheNames, cachestorage.RequestCacheNamesParams{SecurityOrigin: origin})
		cancel()
		if err != nil {
			slog.Debug("cache names", "origin", origin, "err", err)
			continue
		}
		for _, cache := range res.Caches {
			n += c.sweepCache(ctx, cache)
		}
	}
	return n
}

func (c *Capture) sweepCache(ctx context.Context, cache *cachestorage.Cache) int {
	const pageSize = 200
	n := 0
	page := c.currentPage()
	for skip := int64(0); ctx.Err() == nil; skip += pageSize {
		cctx, cancel := context.WithTimeout(c.tab, c.opts.CallTimeout)
		res, err := chromedp.Call(cctx, cachestorage.RequestEntries, cachestorage.RequestEntriesParams{
			CacheID: cache.CacheID, SkipCount: skip, PageSize: pageSize,
		})
		cancel()
		if err != nil {
			slog.Debug("cache entries", "cache", cache.CacheName, "err", err)
			return n
		}
		for _, e := range res.CacheDataEntries {
			mime := cacheHeader(e.ResponseHeaders, "content-type")
			if e.ResponseStatus < 200 || e.ResponseStatus >= 400 || !cachedScript(e.RequestURL, mime) {
				continue
			}
			cctx, cancel := context.WithTimeout(c.tab, c.opts.CallTimeout)
			body, err := chromedp.Call(cctx, cachestorage.RequestCachedResponse, cachestorage.RequestCachedResponseParams{
				CacheID: cache.CacheID, RequestURL: e.RequestURL, RequestHeaders: e.RequestHeaders,
			})
			cancel()
			if err != nil || body.Response == nil || len(body.Response.Body) == 0 {
				c.lost("cache")
				continue
			}
			c.emit(Script{
				Body: body.Response.Body, Kind: "file", Via: "cache_storage", URL: e.RequestURL,
				Target: "cache", TargetURL: cache.CacheName, Page: page,
				Status: e.ResponseStatus, MIME: mime,
				Headers: map[string]string{"content-type": mime},
				Tags:    detect.ScriptTags(e.RequestURL),
			})
			n++
		}
		if len(res.CacheDataEntries) < pageSize {
			return n
		}
	}
	return n
}

func cachedScript(rawURL, mime string) bool {
	if isJSMime(mime) {
		return true
	}
	return hasJSExt(rawURL) && !strings.Contains(strings.ToLower(mime), "html")
}

func cacheHeader(h []*cachestorage.Header, name string) string {
	for _, x := range h {
		if strings.EqualFold(x.Name, name) {
			return x.Value
		}
	}
	return ""
}

// Origins returns the origin of the page and of every service worker the
// capture attached to, the places a cache can belong to.
func (c *Capture) Origins() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		o := u.Scheme + "://" + u.Host
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	add(c.page)
	// Service workers stop when idle, so their sessions may be gone by now.
	for _, u := range c.swURLs {
		add(u)
	}
	return out
}
