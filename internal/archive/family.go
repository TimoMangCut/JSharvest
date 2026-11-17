package archive

import (
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

const (
	// familyStrideMin is the minimum number of distinct digests in a Canonical
	// Family before Coarse-Stride + Binary Zoom-In sampling engages. Families
	// with <= 8 versions are always fetched exhaustively.
	familyStrideMin   = 8
	familyCoarseCount = 8
	familyMaxZoom     = 24
)

func originOfGroup(g *group) string {
	u, err := url.Parse(g.latest.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func familyOfGroup(g *group) string {
	if g == nil || g.latest.URL == "" {
		return ""
	}
	if ck := store.CanonicalKey(g.latest.URL); ck != "" {
		return ck
	}
	return g.latest.URL
}

// --- Two-Tier Fair-Share Scheduler (Origin -> CanonicalFamily) ---

type familyBucket struct {
	key   string
	items []*group
}

type originBucket struct {
	host     string
	families []*familyBucket
	byFam    map[string]*familyBucket
	famIdx   int
}

// drrQueue schedules archive fetch groups with two-tier fair-share round-robin
// (Origin -> CanonicalFamily) so one noisy CMS subdomain or 300-version bundle
// never starves smaller subdomains or newly resolved chunks.
type drrQueue struct {
	origins []*originBucket
	byHost  map[string]*originBucket
	origIdx int
	total   int
}

func newDRRQueue() *drrQueue {
	return &drrQueue{byHost: map[string]*originBucket{}}
}

func (q *drrQueue) len() int { return q.total }

func (q *drrQueue) push(g *group) {
	host := originOfGroup(g)
	fam := familyOfGroup(g)
	ob := q.byHost[host]
	if ob == nil {
		ob = &originBucket{host: host, byFam: map[string]*familyBucket{}}
		q.byHost[host] = ob
		q.origins = append(q.origins, ob)
	}
	fb := ob.byFam[fam]
	if fb == nil {
		fb = &familyBucket{key: fam}
		ob.byFam[fam] = fb
		ob.families = append(ob.families, fb)
	}
	fb.items = append(fb.items, g)
	q.total++
}

func (q *drrQueue) pop() (*group, bool) {
	if q.total == 0 || len(q.origins) == 0 {
		return nil, false
	}
	for range len(q.origins) {
		if q.origIdx >= len(q.origins) {
			q.origIdx = 0
		}
		ob := q.origins[q.origIdx]
		q.origIdx++
		for range len(ob.families) {
			if ob.famIdx >= len(ob.families) {
				ob.famIdx = 0
			}
			fb := ob.families[ob.famIdx]
			ob.famIdx++
			if len(fb.items) > 0 {
				g := fb.items[0]
				fb.items = fb.items[1:]
				q.total--
				return g, true
			}
		}
	}
	return nil, false
}

// --- Canonical Family Coarse-Stride & Binary Zoom-In Controller ---

type familyEntry struct {
	g    *group
	done bool
	ok   bool
	sig  [32]byte
}

type familyTracker struct {
	key       string
	members   []familyEntry // sorted chronologically oldest -> newest
	idxByGKey map[string]int
	scheduled []int // sorted indices currently scheduled or completed
	zoomed    int
	settled   map[[2]int]bool
}

type familyController struct {
	mu       sync.Mutex
	families map[string]*familyTracker // familyKey -> tracker
	byGroup  map[string]*familyTracker // group.key -> tracker
}

func newFamilyController(r *runner, gs []*group) (initial []*group, fc *familyController) {
	fc = &familyController{
		families: map[string]*familyTracker{},
		byGroup:  map[string]*familyTracker{},
	}
	if r.o.MaxFiles > 0 {
		// Preserve exact newest-first cap semantics when -max-files is set.
		for _, g := range gs {
			if r.prepareGroup(g) {
				initial = append(initial, g)
			}
		}
		return initial, fc
	}

	byFam := map[string][]*group{}
	var passthrough []*group
	for _, g := range gs {
		if !r.prepareGroup(g) {
			continue
		}
		if g.digest == "" || assetKind(g.latest) != "script" {
			passthrough = append(passthrough, g)
			continue
		}
		fk := familyOfGroup(g)
		if fk == "" {
			passthrough = append(passthrough, g)
			continue
		}
		byFam[fk] = append(byFam[fk], g)
	}

	initial = append(initial, passthrough...)

	// Process families in deterministic key order.
	famKeys := make([]string, 0, len(byFam))
	for fk := range byFam {
		famKeys = append(famKeys, fk)
	}
	sort.Strings(famKeys)

	for _, fk := range famKeys {
		members := byFam[fk]
		if len(members) <= familyStrideMin {
			initial = append(initial, members...)
			continue
		}
		// Sort oldest -> newest along the timeline for stride & bisection.
		sort.Slice(members, func(i, j int) bool {
			if !members[i].first.Equal(members[j].first) {
				return members[i].first.Before(members[j].first)
			}
			if !members[i].last.Equal(members[j].last) {
				return members[i].last.Before(members[j].last)
			}
			return members[i].key < members[j].key
		})

		ft := &familyTracker{
			key:       fk,
			members:   make([]familyEntry, len(members)),
			idxByGKey: make(map[string]int, len(members)),
			settled:   map[[2]int]bool{},
		}
		for i, g := range members {
			ft.members[i] = familyEntry{g: g}
			ft.idxByGKey[g.key] = i
			fc.byGroup[g.key] = ft
		}
		fc.families[fk] = ft

		anchors := coarseIndices(len(members), familyCoarseCount)
		ft.scheduled = anchors
		// Enqueue newest anchor first so live checks hit fresh paths early.
		for i := len(anchors) - 1; i >= 0; i-- {
			initial = append(initial, ft.members[anchors[i]].g)
		}
	}
	return initial, fc
}

func coarseIndices(n, k int) []int {
	if n <= k {
		out := make([]int, n)
		for i := range n {
			out[i] = i
		}
		return out
	}
	seen := map[int]bool{}
	var out []int
	for i := 0; i < k; i++ {
		idx := (i * (n - 1)) / (k - 1)
		if !seen[idx] {
			seen[idx] = true
			out = append(out, idx)
		}
	}
	sort.Ints(out)
	return out
}

// recordFetched updates a family's timeline with the semantic API signature of
// a fetched script and returns any interior zoom-in groups that must be fetched
// because adjacent anchors differed, plus the count of unchanged interior
// versions pruned.
func (fc *familyController) recordFetched(r *runner, g *group, bodies [][]byte, ok bool) (zoom []*group, pruned int) {
	if fc == nil {
		return nil, 0
	}
	var sig [32]byte
	if ok && len(bodies) > 0 {
		// Extract AST in memory (warming MemCache + static/<sha>.json for history()).
		res := endpoints.ExtractCached(r.o.Dir, bodies[len(bodies)-1], g.latest.URL)
		sig, _ = endpoints.SemanticAPISig(res)
	} else if ok {
		// Even without alarge body, compute empty semantic sig.
		sig, _ = endpoints.SemanticAPISig(endpoints.ExtractCached("", nil, ""))
	}

	fc.mu.Lock()
	ft := fc.byGroup[g.key]
	if ft == nil {
		fc.mu.Unlock()
		return nil, 0
	}
	idx, exists := ft.idxByGKey[g.key]
	if !exists {
		fc.mu.Unlock()
		return nil, 0
	}
	ft.members[idx].done = true
	ft.members[idx].ok = ok
	ft.members[idx].sig = sig

	var toSkip []*group
	// Inspect adjacent scheduled intervals; loop in case new midpoints settle
	// zero-width intervals immediately.
	for i := 0; i+1 < len(ft.scheduled); i++ {
		a, b := ft.scheduled[i], ft.scheduled[i+1]
		if b-a <= 1 || ft.settled[[2]int{a, b}] {
			continue
		}
		ma, mb := ft.members[a], ft.members[b]
		if !ma.done || !mb.done {
			continue
		}
		ft.settled[[2]int{a, b}] = true
		if ma.ok && mb.ok && ma.sig == mb.sig {
			// Identical semantic API signatures at both ends -> interior builds are UI/CMS churn.
			for k := a + 1; k < b; k++ {
				if !ft.members[k].done {
					ft.members[k].done = true
					toSkip = append(toSkip, ft.members[k].g)
				}
			}
			continue
		}
		if ft.zoomed < familyMaxZoom {
			mid := (a + b) / 2
			if mid > a && mid < b && !ft.members[mid].done {
				ft.zoomed++
				ft.scheduled = append(ft.scheduled, mid)
				sort.Ints(ft.scheduled)
				zoom = append(zoom, ft.members[mid].g)
				// Adjust loop index since ft.scheduled grew.
				i++
			}
		}
	}
	fc.mu.Unlock()

	for _, sg := range toSkip {
		r.markDone(sg.key)
	}
	return zoom, len(toSkip)
}
