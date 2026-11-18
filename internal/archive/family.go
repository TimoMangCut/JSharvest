package archive

import (
	"net/url"
	"path"
	"slices"
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
	familyStrideMin        = 8
	familyCoarseCount      = 8
	familyMaxZoom          = 24
	maxDeadBoundaryRetries = 4
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

// --- Two-Tier Self-Compacting O(1) Fair-Share Scheduler (Origin -> CanonicalFamily) ---

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
// (Origin -> CanonicalFamily) and O(1) in-place compaction of drained buckets so
// one noisy CMS subdomain or 300-version bundle never starves smaller subdomains.
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
	for q.total > 0 && len(q.origins) > 0 {
		if q.origIdx >= len(q.origins) {
			q.origIdx = 0
		}
		oIdx := q.origIdx
		ob := q.origins[oIdx]
		if len(ob.families) == 0 {
			delete(q.byHost, ob.host)
			copy(q.origins[oIdx:], q.origins[oIdx+1:])
			q.origins[len(q.origins)-1] = nil
			q.origins = q.origins[:len(q.origins)-1]
			if q.origIdx >= len(q.origins) {
				q.origIdx = 0
			}
			continue
		}

		if ob.famIdx >= len(ob.families) {
			ob.famIdx = 0
		}
		fIdx := ob.famIdx
		fb := ob.families[fIdx]
		if len(fb.items) == 0 {
			delete(ob.byFam, fb.key)
			copy(ob.families[fIdx:], ob.families[fIdx+1:])
			ob.families[len(ob.families)-1] = nil
			ob.families = ob.families[:len(ob.families)-1]
			if ob.famIdx >= len(ob.families) {
				ob.famIdx = 0
			}
			continue
		}

		g := fb.items[0]
		fb.items[0] = nil
		fb.items = fb.items[1:]
		q.total--

		if len(fb.items) == 0 {
			delete(ob.byFam, fb.key)
			copy(ob.families[fIdx:], ob.families[fIdx+1:])
			ob.families[len(ob.families)-1] = nil
			ob.families = ob.families[:len(ob.families)-1]
			if ob.famIdx >= len(ob.families) {
				ob.famIdx = 0
			}
		} else {
			ob.famIdx++
		}

		if len(ob.families) == 0 {
			delete(q.byHost, ob.host)
			copy(q.origins[oIdx:], q.origins[oIdx+1:])
			q.origins[len(q.origins)-1] = nil
			q.origins = q.origins[:len(q.origins)-1]
			if q.origIdx >= len(q.origins) {
				q.origIdx = 0
			}
		} else {
			q.origIdx++
		}
		return g, true
	}
	return nil, false
}

// --- Canonical Family 4-State Coarse-Stride & Binary Zoom-In Controller ---

type memberState uint8

const (
	memberPending memberState = iota
	memberValid               // Verified historical script body + valid SemanticAPISig
	memberDead                // errNotArchived, soft-404 HTML, or failed fetch (NEVER matches to prune)
	memberPruned              // Proven redundant between two memberValid anchors with identical sig
)

type familyEntry struct {
	g     *group
	state memberState
	sig   [32]byte
}

type familyTracker struct {
	key              string
	members          []familyEntry // sorted chronologically oldest -> newest
	idxByGKey        map[string]int
	scheduled        []int // sorted distinct indices scheduled or pre-seeded
	zoomed           int
	leftDeadRetries  int
	rightDeadRetries int
	settled          map[[2]int]bool
}

type familyController struct {
	mu       sync.Mutex
	families map[string]*familyTracker // familyKey -> tracker
	byGroup  map[string]*familyTracker // group.key -> tracker
}

func (r *runner) seedFamilyMember(g *group) (memberState, [32]byte) {
	meta := &store.ArchiveSeen{First: g.first, Last: g.last, Captures: g.captures}
	if r.isDone(g.key) {
		if g.digest != "" && r.store != nil {
			if sha := r.store.BySHA1(g.digest); sha != "" {
				if sig, ok := endpoints.LoadOrExtractSig(r.o.Dir, sha, g.latest.URL); ok {
					return memberValid, sig
				}
			}
		}
		if g.digest != "" && r.cur != nil {
			if cs, ok := r.cur.bySHA1[g.digest]; ok {
				if sig, ok := endpoints.LoadOrExtractSig(cs.dir, cs.sha256, cs.url); ok {
					return memberValid, sig
				}
			}
		}
		return memberDead, [32]byte{}
	}
	if r.isDone("dead:" + g.key) {
		r.markDone(g.key)
		return memberDead, [32]byte{}
	}
	if g.digest != "" && r.cur != nil && r.cur.sha1[g.digest] {
		r.sum(func(s *Summary) { s.Known++ })
		r.markDone(g.key)
		if cs, ok := r.cur.bySHA1[g.digest]; ok {
			if sig, ok := endpoints.LoadOrExtractSig(cs.dir, cs.sha256, cs.url); ok {
				return memberValid, sig
			}
		}
		return memberDead, [32]byte{}
	}
	if r.isDone("pre:" + g.key) {
		var sha string
		if g.digest != "" && r.store != nil {
			if sha = r.store.BySHA1(g.digest); sha != "" {
				same := false
				if e, ok := r.store.Entry(sha); ok && e.Alive != nil && *e.Alive && slices.Contains(e.Sources, "live") {
					same = true
				}
				for _, src := range g.sources {
					r.store.Add(store.Record{SHA256: sha, URL: g.latest.URL, Source: src, Archive: meta, LiveSame: same})
				}
			}
		}
		r.markDone(g.key)
		if sha != "" {
			if sig, ok := endpoints.LoadOrExtractSig(r.o.Dir, sha, g.latest.URL); ok {
				return memberValid, sig
			}
		}
		return memberDead, [32]byte{}
	}
	if g.digest != "" && r.store != nil {
		if sha := r.store.BySHA1(g.digest); sha != "" {
			same := false
			if e, ok := r.store.Entry(sha); ok && e.Alive != nil && *e.Alive && slices.Contains(e.Sources, "live") {
				same = true
			}
			for _, src := range g.sources {
				r.store.Add(store.Record{SHA256: sha, URL: g.latest.URL, Source: src, Archive: meta, LiveSame: same})
			}
			r.sum(func(s *Summary) { s.Merged++ })
			r.markDone(g.key)
			if sig, ok := endpoints.LoadOrExtractSig(r.o.Dir, sha, g.latest.URL); ok {
				return memberValid, sig
			}
			return memberDead, [32]byte{}
		}
	}
	return memberPending, [32]byte{}
}

func newFamilyController(r *runner, gs []*group) (initial []*group, fc *familyController) {
	fc = &familyController{
		families: map[string]*familyTracker{},
		byGroup:  map[string]*familyTracker{},
	}
	if r.o.MaxFiles > 0 && r.o.MaxFiles <= familyStrideMin {
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
		if u, err := url.Parse(g.latest.URL); err == nil && !r.o.Vendor && vendorRe.MatchString(path.Base(u.Path)) {
			r.sum(func(s *Summary) { s.Skipped["vendor library"]++ })
			continue
		}
		if g.digest == "" || assetKind(g.latest) != "script" {
			if r.prepareGroup(g) {
				passthrough = append(passthrough, g)
			}
			continue
		}
		fk := familyOfGroup(g)
		if fk == "" {
			if r.prepareGroup(g) {
				passthrough = append(passthrough, g)
			}
			continue
		}
		byFam[fk] = append(byFam[fk], g)
	}

	initial = append(initial, passthrough...)

	famKeys := make([]string, 0, len(byFam))
	for fk := range byFam {
		famKeys = append(famKeys, fk)
	}
	if r.o.MaxFiles > 0 {
		// Prioritize families with the freshest captures when -max-files is set.
		sort.Slice(famKeys, func(i, j int) bool {
			mi, mj := byFam[famKeys[i]], byFam[famKeys[j]]
			ti, tj := mi[0].last, mj[0].last
			if !ti.Equal(tj) {
				return ti.After(tj)
			}
			return famKeys[i] < famKeys[j]
		})
	} else {
		sort.Strings(famKeys)
	}

	var prePruned []*group
	for _, fk := range famKeys {
		members := byFam[fk]
		if len(members) <= familyStrideMin {
			for _, g := range members {
				if r.prepareGroup(g) {
					initial = append(initial, g)
				}
			}
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
		schedSet := map[int]bool{}
		for i, g := range members {
			st, sig := r.seedFamilyMember(g)
			ft.members[i] = familyEntry{g: g, state: st, sig: sig}
			ft.idxByGKey[g.key] = i
			fc.byGroup[g.key] = ft
			if st == memberValid {
				schedSet[i] = true
			}
		}
		fc.families[fk] = ft

		for _, idx := range coarseIndices(len(members), familyCoarseCount) {
			switch ft.members[idx].state {
			case memberValid, memberPending:
				schedSet[idx] = true
			case memberDead:
				if nb, ok := nearestPending(ft.members, idx, 0, len(members)-1); ok {
					schedSet[nb] = true
				}
			}
		}

		sched := make([]int, 0, len(schedSet))
		for idx := range schedSet {
			sched = append(sched, idx)
		}
		sort.Ints(sched)
		ft.scheduled = sched

		// Settle any intervals already bracketed by pre-seeded Valid members.
		_, skipped := ft.settleIntervalsLocked()
		prePruned = append(prePruned, skipped...)

		// Enqueue pending scheduled anchors newest-first so live checks hit fresh paths early.
		for i := len(ft.scheduled) - 1; i >= 0; i-- {
			idx := ft.scheduled[i]
			if ft.members[idx].state == memberPending {
				initial = append(initial, ft.members[idx].g)
			}
		}
	}

	if len(prePruned) > 0 {
		for _, sg := range prePruned {
			r.markDone(sg.key)
		}
		r.sum(func(s *Summary) { s.Skipped["family unchanged"] += len(prePruned) })
	}
	return initial, fc
}

func nearestPending(ms []familyEntry, target, lo, hi int) (int, bool) {
	best := -1
	bestDist := len(ms) + 1
	for i := lo; i <= hi; i++ {
		if ms[i].state != memberPending {
			continue
		}
		d := i - target
		if d < 0 {
			d = -d
		}
		if d < bestDist {
			best, bestDist = i, d
		}
	}
	return best, best >= 0
}

func insertSortedUnique(s []int, v int) []int {
	i := sort.SearchInts(s, v)
	if i < len(s) && s[i] == v {
		return s
	}
	s = append(s, 0)
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
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

func (ft *familyTracker) settleIntervalsLocked() (zoom []*group, toSkip []*group) {
	n := len(ft.members)
	if n == 0 || len(ft.scheduled) == 0 {
		return nil, nil
	}

	// 1. Recover dead outer boundaries using a dedicated retry budget so dead
	// early/late captures never exhaust familyMaxZoom bisection slots.
	firstActivePos := -1
	lastActivePos := -1
	for pos, idx := range ft.scheduled {
		st := ft.members[idx].state
		if st == memberPending || st == memberValid {
			if firstActivePos < 0 {
				firstActivePos = pos
			}
			lastActivePos = pos
		}
	}
	if firstActivePos < 0 {
		// Every scheduled anchor so far died -> probe inward from left if budget allows.
		if ft.leftDeadRetries < maxDeadBoundaryRetries {
			target := min((1<<ft.leftDeadRetries), n-1)
			if nb, ok := nearestPending(ft.members, target, 0, n-1); ok {
				ft.leftDeadRetries++
				ft.scheduled = insertSortedUnique(ft.scheduled, nb)
				zoom = append(zoom, ft.members[nb].g)
			}
		}
		return zoom, nil
	}

	firstActiveIdx := ft.scheduled[firstActivePos]
	if firstActivePos > 0 && ft.leftDeadRetries < maxDeadBoundaryRetries {
		target := min((1<<ft.leftDeadRetries), firstActiveIdx-1)
		if nb, ok := nearestPending(ft.members, target, 0, firstActiveIdx-1); ok {
			ft.leftDeadRetries++
			ft.scheduled = insertSortedUnique(ft.scheduled, nb)
			zoom = append(zoom, ft.members[nb].g)
		}
	}

	lastActiveIdx := ft.scheduled[lastActivePos]
	if lastActivePos < len(ft.scheduled)-1 && ft.rightDeadRetries < maxDeadBoundaryRetries {
		target := max((n-1)-(1<<ft.rightDeadRetries), lastActiveIdx+1)
		if nb, ok := nearestPending(ft.members, target, lastActiveIdx+1, n-1); ok {
			ft.rightDeadRetries++
			ft.scheduled = insertSortedUnique(ft.scheduled, nb)
			zoom = append(zoom, ft.members[nb].g)
		}
	}

	// 2. Build active anchor list (memberPending | memberValid), skipping ONLY
	// resolved memberDead/memberPruned points — NEVER skipping memberPending.
	active := make([]int, 0, len(ft.scheduled))
	for _, idx := range ft.scheduled {
		st := ft.members[idx].state
		if st == memberPending || st == memberValid {
			active = append(active, idx)
		}
	}

	var newMids []int
	for j := 0; j+1 < len(active); j++ {
		a, b := active[j], active[j+1]
		if b-a <= 1 || ft.settled[[2]int{a, b}] {
			continue
		}
		ma, mb := ft.members[a], ft.members[b]
		if ma.state != memberValid || mb.state != memberValid {
			continue
		}
		ft.settled[[2]int{a, b}] = true
		if ma.sig == mb.sig {
			for k := a + 1; k < b; k++ {
				if ft.members[k].state == memberPending {
					ft.members[k].state = memberPruned
					toSkip = append(toSkip, ft.members[k].g)
				}
			}
			continue
		}
		if ft.zoomed < familyMaxZoom {
			if mid, ok := nearestPending(ft.members, (a+b)/2, a+1, b-1); ok {
				ft.zoomed++
				newMids = append(newMids, mid)
				zoom = append(zoom, ft.members[mid].g)
			}
		}
	}
	for _, mid := range newMids {
		ft.scheduled = insertSortedUnique(ft.scheduled, mid)
	}
	return zoom, toSkip
}

// recordFetched updates a family's timeline with the semantic API signature of
// the historical script archBody. Only ferr == nil && len(archBody) > 0 becomes
// memberValid; errors, errNotArchived, and HTML soft-404s become memberDead and
// can never falsely prune interior versions.
func (fc *familyController) recordFetched(r *runner, g *group, archBody []byte, ferr error) (zoom []*group, pruned int) {
	if fc == nil {
		return nil, 0
	}
	valid := ferr == nil && len(archBody) > 0
	var sig [32]byte
	if valid {
		res := endpoints.ExtractCached(r.o.Dir, archBody, g.latest.URL)
		sig, _ = endpoints.SemanticAPISig(res)
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
	if valid {
		ft.members[idx].state = memberValid
		ft.members[idx].sig = sig
	} else {
		ft.members[idx].state = memberDead
	}

	zoom, toSkip := ft.settleIntervalsLocked()
	fc.mu.Unlock()

	for _, sg := range toSkip {
		r.markDone(sg.key)
	}
	return zoom, len(toSkip)
}
