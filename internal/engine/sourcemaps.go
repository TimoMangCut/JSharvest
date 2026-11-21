package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// sourceMaps reads the maps of the scripts captured since the last round
// (MAX-07): the one the Debugger or a SourceMap header names, the
// sourceMappingURL comment, or with GuessMaps <script>.map for the app's
// scripts (not a library bundle's). A map is fetched through the page, as
// a chunk is, under the scope policy and within -resolve-max; its own
// sources (not node_modules) go to the store, where the endpoints are read
// from them. It reports false when the target asked to stop.
func (e *engine) sourceMaps(ctx context.Context, refs []ref, policy *resolve.Policy, limit *limiter, fetched *int) bool {
	if !e.cfg.SourceMaps {
		return true
	}
	stats := &e.run.Resolver
	for _, r := range refs {
		h := map[string]string{}
		for k, v := range r.headers {
			h[k] = v
		}
		if r.mapURL != "" {
			h["sourcemap"] = r.mapURL
		}
		guess := e.cfg.GuessMaps && r.url != r.page && !frontier.Vendor(r.url)
		m, ok := sourcemap.Find(r.url, h, r.body, guess)
		if !ok {
			continue
		}
		body := m.Inline
		where := r.url + "#inline-map"
		if body == nil {
			k := normURL(m.URL)
			e.mu.Lock()
			seen := e.mapsSeen[k]
			e.mapsSeen[k] = true
			e.mu.Unlock()
			if seen || policy.Check(m.URL) != resolve.Allow {
				continue
			}
			if m.Guess && !e.mapGuesses.Allow(m.URL) {
				stats.MapGuessesHeld++
				continue // the origin ships no maps: no more guesses there
			}
			if e.storeCapped.Load() {
				stats.Stopped = storeBudgetLabel(e.cfg.MaxStoreBytes)
				return true
			}
			if e.cfg.ResolveMax > 0 && *fetched >= e.cfg.ResolveMax {
				stats.Stopped = fmt.Sprintf("reached -resolve-max %d", e.cfg.ResolveMax)
				return true
			}
			if limit.wait(ctx) != nil {
				return false
			}
			res, err := e.pageFetchText(m.URL, true, "default", maxMapText)
			*fetched++
			if res.Status == 429 || res.Challenge {
				stats.Stopped = fmt.Sprintf("target answered %d%s; stopped to stay polite", res.Status, map[bool]string{true: " with a challenge", false: ""}[res.Challenge])
				e.warn("resolver: " + stats.Stopped)
				return false
			}
			if err != nil || res.Status != 200 || res.Text == "" {
				if m.Guess {
					e.mapGuesses.Done(m.URL, false)
				}
				continue // a guess not there: one 404
			}
			body, where = []byte(res.Text), m.URL
		}
		sm, err := sourcemap.Parse(body)
		if m.Guess {
			e.mapGuesses.Done(m.URL, err == nil)
		}
		if err != nil {
			continue
		}
		stats.Maps++
		own := 0
		for _, f := range sm.FilesFor(r.url) {
			if f.Vendor {
				continue // a dependency's: noise for the target's endpoints
			}
			if !e.claimSourceSlot() {
				stats.SourcesCapped++
				continue
			}
			key, isNew, err := e.st.Put(store.Record{Body: []byte(f.Content), URL: where + "#" + f.Path, Kind: "source", Via: "sourcemap",
				Target: "page", Page: r.page, Tags: []string{"sourcemap", "source:" + f.Path}, Source: "live",
				Initiator: &store.Initiator{Type: "sourcemap", URL: r.url}})
			if err != nil {
				e.mapSourcesStored.Add(-1)
				if errors.Is(err, store.ErrStoreBudget) {
					e.storeError("store_budget")
					if !e.storeCapped.Swap(true) {
						msg := storeBudgetLabel(e.cfg.MaxStoreBytes) + ": scripts past it were not stored (-max-store-mb to raise it)"
						slog.Warn(msg)
						e.warn(msg)
					}
					stats.Stopped = storeBudgetLabel(e.cfg.MaxStoreBytes)
					break
				}
				continue
			}
			e.noteScript(key, isNew)
			own++
		}
		stats.MapSources += own
		slog.Info("source map", "url", logSourceMapURL(where), "sources", len(sm.Sources), "own", own)
	}
	return true
}
