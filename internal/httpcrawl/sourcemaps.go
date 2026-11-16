package httpcrawl

import (
	"context"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
)

// sourceMap fetches the map a script names (SourceMap header, the
// sourceMappingURL comment), or with GuessMaps <script>.map, and hands it
// on when it reads as a source map v3. A guess that is not there costs one
// 404 a script: it is made for the app's scripts, not a library bundle's
// (MAX-04: a production build often drops the comment, not the file).
func (cr *crawler) sourceMap(ctx context.Context, a answer, j job, h map[string]string) {
	ref, ok := sourcemap.Find(a.URL, h, a.Body, cr.o.GuessMaps && !frontier.Vendor(a.URL))
	if !ok {
		return
	}
	if ref.Inline != nil {
		if _, err := sourcemap.Parse(ref.Inline); err == nil {
			cr.count(func(st *Stats) { st.SourceMaps++ })
			cr.o.SourceMap(SourceMap{ScriptURL: a.URL, Body: ref.Inline})
		}
		return
	}
	if v := cr.policy.Check(ref.URL); v != "allow" {
		return
	}
	if ref.Guess && !cr.guesses.Allow(ref.URL) {
		cr.count(func(st *Stats) { st.MapGuessesHeld++ })
		return // the origin ships no maps: no more guesses there
	}
	if ok, _ := cr.claim(ref.URL); !ok {
		return
	}
	m := cr.fetch(ctx, ref.URL, j.page, dataReq, "Other")
	cr.politeAt(m, j.page, j.depth)
	ok = m.Err == nil && m.Status == 200 && !htmlLike(m.Body)
	if ok {
		_, err := sourcemap.Parse(m.Body)
		ok = err == nil
	}
	if ref.Guess {
		cr.guesses.Done(ref.URL, ok)
	}
	if !ok {
		return
	}
	cr.count(func(st *Stats) { st.SourceMaps++ })
	cr.o.SourceMap(SourceMap{URL: ref.URL, ScriptURL: a.URL, Body: m.Body})
}
