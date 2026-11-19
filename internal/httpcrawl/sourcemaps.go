package httpcrawl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
)

// mapDedupEntry is a map fetched once for a bundle several hosts serve.
// It keeps the sources' references, not their content: the content is in
// the store, by its SHA-256 (round 37.1, D).
type mapDedupEntry struct {
	ready    chan struct{}
	ok       bool
	ownRefs  []SourceRef
	sourcesN int
}

func sourceRefs(own []sourcemap.File) []SourceRef {
	refs := make([]SourceRef, 0, len(own))
	for _, f := range own {
		sum := sha256.Sum256([]byte(f.Content))
		refs = append(refs, SourceRef{Path: f.Path, SHA256: hex.EncodeToString(sum[:])})
	}
	return refs
}

func mapDedupeKey(scriptURL string, scriptBody []byte, ref sourcemap.Ref) string {
	if ref.RelRef == "" || len(scriptBody) == 0 {
		return ""
	}
	sum := sha256.Sum256(scriptBody)
	return hex.EncodeToString(sum[:]) + "|" + sourcemap.LibraryClassKey(scriptURL) + "|" + ref.RelRef
}

func extractOwnMapFiles(sm *sourcemap.Map, scriptURL string) []sourcemap.File {
	var own []sourcemap.File
	for _, f := range sm.FilesFor(scriptURL) {
		if !f.Vendor {
			own = append(own, f)
		}
	}
	return own
}

// sourceMap fetches the map a script names (SourceMap header, the
// sourceMappingURL comment), or with GuessMaps <script>.map, and hands it
// on when it reads as a source map v3. A guess that is not there costs one
// 404 a script: it is made for the app's scripts, not a library bundle's
// (MAX-04: a production build often drops the comment, not the file).
//
// When identical JS bytes on multiple hosts reference the same relative .map
// and the first fetched map carries full sourcesContent, singleflight dedup
// reuses its extracted app sources (re-attributing Page to each host's ScriptURL)
// without re-downloading multi-MB maps across every subdomain.
func (cr *crawler) sourceMap(ctx context.Context, a answer, j job, h map[string]string) {
	ref, ok := sourcemap.Find(a.URL, h, a.Body, cr.o.GuessMaps && !frontier.Vendor(a.URL))
	if !ok {
		return
	}
	if ref.Inline != nil {
		if sm, err := sourcemap.Parse(ref.Inline); err == nil {
			cr.count(func(st *Stats) { st.SourceMaps++ })
			cr.o.SourceMap(SourceMap{
				ScriptURL: a.URL,
				Body:      ref.Inline,
				Parsed:    sm,
				OwnFiles:  extractOwnMapFiles(sm, a.URL),
				SourcesN:  len(sm.Sources),
			})
		}
		return
	}
	if v := cr.policy.Check(ref.URL); v != "allow" {
		return
	}
	dedupKey := mapDedupeKey(a.URL, a.Body, ref)
	var myFlight *mapDedupEntry
	if dedupKey != "" {
		for {
			cr.mapMu.Lock()
			if cached, hit := cr.mapCache[dedupKey]; hit {
				cr.mapMu.Unlock()
				// No request to this origin: its guesses learn nothing
				// (round 37.1, F2).
				cr.count(func(st *Stats) { st.SourceMaps++ })
				cr.o.SourceMap(SourceMap{
					URL:       ref.URL,
					ScriptURL: a.URL,
					OwnRefs:   cached.ownRefs,
					SourcesN:  cached.sourcesN,
					Reused:    true,
				})
				return
			}
			if inflight, busy := cr.mapInflight[dedupKey]; busy {
				wait := inflight.ready
				cr.mapMu.Unlock()
				select {
				case <-wait:
					continue
				case <-ctx.Done():
					return
				}
			}
			if cr.mapInflight == nil {
				cr.mapInflight = map[string]*mapDedupEntry{}
			}
			myFlight = &mapDedupEntry{ready: make(chan struct{})}
			cr.mapInflight[dedupKey] = myFlight
			cr.mapMu.Unlock()
			break
		}
	}
	// finishFlight publishes the map to the hosts waiting on the same
	// bundle. It runs only after SourceMap has stored the sources (the
	// callback stores them before it returns), so a reuse never names a
	// source the store does not have yet; the deferred call releases the
	// waiters, with nothing to reuse, on every other way out.
	finishFlight := func(sm *sourcemap.Map, own []sourcemap.File) {
		if myFlight == nil {
			return
		}
		cr.mapMu.Lock()
		delete(cr.mapInflight, dedupKey)
		if sm != nil && sm.CompleteSourcesContent() {
			myFlight.ok = true
			myFlight.ownRefs = sourceRefs(own)
			myFlight.sourcesN = len(sm.Sources)
			if cr.mapCache == nil {
				cr.mapCache = map[string]*mapDedupEntry{}
			}
			cr.mapCache[dedupKey] = myFlight
		}
		close(myFlight.ready)
		myFlight = nil
		cr.mapMu.Unlock()
	}
	defer finishFlight(nil, nil)

	if ref.Guess && !cr.guesses.Allow(ref.URL) {
		cr.count(func(st *Stats) { st.MapGuessesHeld++ })
		return // the origin ships no maps: no more guesses there
	}
	if ok, _ := cr.claim(ref.URL); !ok {
		return
	}
	m := cr.fetch(ctx, ref.URL, j.page, dataReq, "Other")
	cr.politeAt(m, j.page, j.depth)
	var sm *sourcemap.Map
	ok = m.Err == nil && m.Status == 200 && !htmlLike(m.Body)
	if ok {
		var err error
		sm, err = sourcemap.Parse(m.Body)
		ok = err == nil
	}
	if ref.Guess {
		cr.guesses.Done(ref.URL, ok)
	}
	if !ok {
		return
	}
	own := extractOwnMapFiles(sm, a.URL)
	cr.count(func(st *Stats) { st.SourceMaps++ })
	cr.o.SourceMap(SourceMap{
		URL:       ref.URL,
		ScriptURL: a.URL,
		Body:      m.Body,
		Parsed:    sm,
		OwnFiles:  own,
		SourcesN:  len(sm.Sources),
	})
	finishFlight(sm, own) // stored: now the waiting hosts may reuse it
}
