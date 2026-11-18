package httpcrawl

import (
	"crypto/sha256"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

const (
	// skelFanoutThreshold is how many distinct non-ID child segments under the
	// same parent path prefix must be observed before collapsing that position
	// into {slug}. Keeping it at 8 preserves feature tabs (/account/billing,
	// /account/security, /account/api-keys) while collapsing CMS article slugs.
	skelFanoutThreshold = 8
	skelMinVisits       = 6
	skelMaxEmptyStreak  = 5
)

var (
	skelUUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	skelDateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

type skelNode struct {
	collapsed bool
	children  map[string]*skelNode
	wild      *skelNode
}

type skelStat struct {
	visits      int
	emptyStreak int
	saturated   bool
}

// skeletonController implements Marginal Information-Gain (ΔInformation)
// tracking per (origin, pathSkeleton, queryKeySet) using a fan-out Prefix Trie.
// Only dynamic/parameterized or query-paginated skeletons can saturate, so
// static unique application pages are never skipped.
type skeletonController struct {
	roots      map[string]*skelNode          // origin -> root trie node
	stats      map[string]*skelStat          // skelKey -> visit/streak stats
	seenInline map[string]map[[32]byte]bool  // origin -> inline SemanticAPISig/hash
	seenForms  map[string]map[string]bool    // origin -> form signature
	seenLinks  map[string]map[string]bool    // origin -> child link skeletons
	seenScript map[string]map[string]bool    // origin -> canonical external script key
}

func newSkeletonController() *skeletonController {
	return &skeletonController{
		roots:      map[string]*skelNode{},
		stats:      map[string]*skelStat{},
		seenInline: map[string]map[[32]byte]bool{},
		seenForms:  map[string]map[string]bool{},
		seenLinks:  map[string]map[string]bool{},
		seenScript: map[string]map[string]bool{},
	}
}

func isImmediateParamSegment(seg string) bool {
	if seg == "" {
		return false
	}
	allDigits := true
	hasDigit, hasLetter := false, false
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			allDigits = false
			hasLetter = true
		default:
			allDigits = false
		}
	}
	if allDigits {
		return true
	}
	if skelUUIDRe.MatchString(seg) || skelDateRe.MatchString(seg) {
		return true
	}
	// Long mixed hex/token IDs (e.g. Mongo ObjectId, ULID, session/article hash).
	if len(seg) >= 16 && hasDigit && hasLetter && !strings.Contains(seg, ".") {
		return true
	}
	return false
}

// skeletonKey registers rawURL in the origin's Prefix Trie and returns its
// structural key (origin + collapsed path + sorted query parameter names) and
// whether the key represents a dynamic/paginated template.
func (sc *skeletonController) skeletonKey(rawURL string, register bool) (key string, dynamic bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	root := sc.roots[origin]
	if root == nil {
		if !register {
			return origin + u.Path, false
		}
		root = &skelNode{}
		sc.roots[origin] = root
	}

	trimmed := strings.Trim(u.Path, "/")
	var outSegs []string
	cur := root
	if trimmed != "" {
		segs := strings.Split(trimmed, "/")
		for _, seg := range segs {
			if isImmediateParamSegment(seg) {
				dynamic = true
				outSegs = append(outSegs, "{id}")
				if cur != nil {
					if cur.wild == nil && register {
						cur.wild = &skelNode{}
					}
					cur = cur.wild
				}
				continue
			}
			if cur != nil && cur.collapsed {
				dynamic = true
				outSegs = append(outSegs, "{slug}")
				if cur.wild == nil && register {
					cur.wild = &skelNode{}
				}
				cur = cur.wild
				continue
			}
			if cur != nil && register {
				if cur.children == nil {
					cur.children = map[string]*skelNode{}
				}
				nx := cur.children[seg]
				if nx == nil {
					nx = &skelNode{}
					cur.children[seg] = nx
					if len(cur.children) >= skelFanoutThreshold {
						cur.collapsed = true
						if cur.wild == nil {
							cur.wild = &skelNode{}
						}
						// Merge existing children's subtrees conservatively by switching
						// future lookups at this node to {slug}.
						dynamic = true
						outSegs = append(outSegs, "{slug}")
						cur = cur.wild
						continue
					}
				}
				cur = nx
			} else if cur != nil {
				cur = cur.children[seg]
			}
			outSegs = append(outSegs, seg)
		}
	}

	pathSkel := "/"
	if len(outSegs) > 0 {
		pathSkel = "/" + strings.Join(outSegs, "/")
	}
	var qKeys []string
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			qKeys = append(qKeys, k)
		}
		sort.Strings(qKeys)
		if len(qKeys) > 0 {
			dynamic = true
		}
	}
	key = origin + pathSkel
	if len(qKeys) > 0 {
		key += "?" + strings.Join(qKeys, "&")
	}
	return key, dynamic
}

// shouldSkip reports whether rawURL belongs to a dynamic SSR/paginated template
// that has already yielded zero marginal information across repeated visits.
func (sc *skeletonController) shouldSkip(rawURL string) bool {
	if specURL(rawURL) {
		return false
	}
	key, dynamic := sc.skeletonKey(rawURL, true)
	if !dynamic || key == "" {
		return false
	}
	st := sc.stats[key]
	return st != nil && st.saturated
}

// observe records what a visited page contributed and returns whether it
// yielded positive marginal information (ΔInfo > 0).
func (sc *skeletonController) observe(cr *crawler, pageURL string, status int, admittedJobs []job, inlineSigs [][32]byte, links []frontier.Found, b *bucket) bool {
	key, dynamic := sc.skeletonKey(pageURL, true)
	if key == "" {
		return false
	}
	origin := originOf(pageURL)
	gained := false

	if len(admittedJobs) > 0 {
		gained = true
	}
	if sc.seenScript[origin] == nil {
		sc.seenScript[origin] = map[string]bool{}
	}
	for _, j := range admittedJobs {
		ck := store.CanonicalKey(j.url)
		if ck == "" {
			ck = j.url
		}
		sc.seenScript[origin][ck] = true
	}

	if sc.seenInline[origin] == nil {
		sc.seenInline[origin] = map[[32]byte]bool{}
	}
	for _, sig := range inlineSigs {
		if !sc.seenInline[origin][sig] {
			sc.seenInline[origin][sig] = true
			gained = true
		}
	}

	if b != nil && (len(b.found) > 0 || len(b.origins) > 0) {
		// Check whether script findings named any new route/origin skeleton.
		if sc.seenLinks[origin] == nil {
			sc.seenLinks[origin] = map[string]bool{}
		}
		for _, f := range b.found {
			lk, _ := sc.skeletonKey(f.f.URL, false)
			if lk != "" && !sc.seenLinks[origin]["js:"+lk] {
				sc.seenLinks[origin]["js:"+lk] = true
				gained = true
			}
		}
		for _, o := range b.origins {
			if !sc.seenLinks[origin]["orig:"+o.f.URL] {
				sc.seenLinks[origin]["orig:"+o.f.URL] = true
				gained = true
			}
		}
	}

	if sc.seenForms[origin] == nil {
		sc.seenForms[origin] = map[string]bool{}
	}
	if sc.seenLinks[origin] == nil {
		sc.seenLinks[origin] = map[string]bool{}
	}
	for _, l := range links {
		if l.How == frontier.Form {
			u, err := url.Parse(l.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}
			inScope := (cr != nil && cr.o.InScope != nil && cr.o.InScope(u.Hostname())) ||
				((cr == nil || cr.o.InScope == nil) && originOf(l.URL) == origin)
			if !inScope {
				continue
			}
			lk, _ := sc.skeletonKey(l.URL, true)
			if lk == "" {
				continue
			}
			fk := l.Method + " " + lk
			if !sc.seenForms[origin][fk] {
				sc.seenForms[origin][fk] = true
				gained = true
			}
			continue
		}
		if !l.Visit {
			continue
		}
		lk, _ := sc.skeletonKey(l.URL, true)
		if lk != "" && !sc.seenLinks[origin][lk] {
			sc.seenLinks[origin][lk] = true
			gained = true
		}
	}

	if status < 200 || status >= 400 || !dynamic {
		return gained
	}
	st := sc.stats[key]
	if st == nil {
		st = &skelStat{}
		sc.stats[key] = st
	}
	st.visits++
	if gained {
		st.emptyStreak = 0
	} else {
		st.emptyStreak++
		if st.visits >= skelMinVisits && st.emptyStreak >= skelMaxEmptyStreak {
			st.saturated = true
		}
	}
	return gained
}

// recordAsyncFindings deterministically records route and API-origin skeletons
// discovered by external <script src> bundles after drain() finishes at level commit.
func (sc *skeletonController) recordAsyncFindings(pageURL string, fs []found, origins []string) {
	if sc == nil || (len(fs) == 0 && len(origins) == 0) {
		return
	}
	origin := originOf(pageURL)
	if origin == "" {
		return
	}
	if sc.seenLinks[origin] == nil {
		sc.seenLinks[origin] = map[string]bool{}
	}
	for _, x := range fs {
		if lk, _ := sc.skeletonKey(x.f.URL, false); lk != "" {
			sc.seenLinks[origin]["js:"+lk] = true
		}
	}
	for _, o := range origins {
		if o != "" {
			sc.seenLinks[origin]["orig:"+o] = true
		}
	}
}

func inlineSemanticSig(cr *crawler, sc *skeletonController, code []byte, pageURL string) ([32]byte, bool) {
	res := cr.extractScript(code, pageURL)
	base, _ := url.Parse(pageURL)
	norm := func(raw string) string {
		if sc != nil && base != nil && (strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")) {
			if u, err := base.Parse(raw); err == nil {
				if sk, _ := sc.skeletonKey(u.String(), false); sk != "" {
					return sk
				}
			}
		}
		return raw
	}
	var parts []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	for _, e := range res.Endpoints {
		if e.Collector {
			continue
		}
		u := e.URL
		if e.Kind == "string" || e.Kind == "navigation" {
			u = norm(u)
		}
		add("ep:" + e.Method + "|" + e.Kind + "|" + norm(e.Base) + "|" + u + "|" + strings.Join(e.Query, ",") + "|" + strings.Join(e.Body, ","))
	}
	for _, b := range res.Bases {
		add("b:" + norm(b))
	}
	for _, pb := range res.PropBases {
		add("pb:" + pb.Name + "=" + norm(pb.Value))
	}
	for _, h := range res.ClientHeaders {
		add("ch:" + strings.ToLower(h.Name) + "=" + h.Value)
	}
	for _, k := range res.Keys {
		add("k:" + k.Name + "=" + k.Value)
	}
	for _, s := range res.Settings {
		add("s:" + s.Name + "=" + norm(s.Value))
	}
	for _, c := range res.Cloud {
		add("cl:" + c)
	}
	for _, op := range res.Operations {
		add("op:" + op)
	}
	for _, r := range res.Routes {
		add("r:" + norm(r))
	}
	for _, p := range res.Paths {
		add("p:" + norm(p))
	}
	if len(parts) == 0 {
		return [32]byte{}, false
	}
	sort.Strings(parts)
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p + "\x00"))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, true
}
