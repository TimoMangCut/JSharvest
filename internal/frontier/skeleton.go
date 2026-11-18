package frontier

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	// SkelFanoutThreshold is how many distinct slug-candidate child segments
	// under the same parent path prefix may appear before collapsing further
	// slug candidates at that position into {slug}.
	SkelFanoutThreshold = 8
	// SkelStaticFanoutThreshold bounds plain 1-word / short 2-word child names
	// at depth >= 1 (preserving large /admin/* or /settings/* menus and static
	// page directories while still collapsing multi-thousand /users/<handle> trees).
	SkelStaticFanoutThreshold = 32
	SkelMinVisits             = 6
	SkelMaxEmptyStreak        = 5

	maxQueryKeysInSkel    = 8
	maxSkelOrigins        = 256
	maxSkelNodesPerOrigin = 8192
	maxSkelStats          = 16384
	maxSeenPerOrigin      = 32768
)

var (
	skelUUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	skelDateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

	staticPageExts = map[string]bool{
		".html": true, ".htm": true, ".xhtml": true,
		".php": true, ".asp": true, ".aspx": true, ".jsp": true,
	}
	techIdentifiers = map[string]bool{
		"oauth2": true, "saml2": true, "web3": true, "2fa": true,
		"s3": true, "r2": true, "ec2": true, "k8s": true,
		"i18n": true, "l10n": true, "a11y": true,
		"b2b": true, "b2c": true, "p2p": true,
		"h2": true, "http2": true, "http3": true,
		"3d": true, "2d": true, "ipv4": true, "ipv6": true,
		"sha1": true, "sha256": true, "md5": true, "base64": true,
	}
)

type skelNode struct {
	collapsed       bool
	staticCollapsed bool
	children        map[string]*skelNode // slug-candidate children
	staticChildren  map[string]*skelNode // short controller / feature / static page names
	wild            *skelNode
}

type skelStat struct {
	visits      int
	emptyStreak int
	saturated   bool
}

// Observation describes what a visited page contributed so Skeleton.Observe
// can compute marginal information gain (ΔInformation).
type Observation struct {
	PageURL      string
	Status       int
	NewScripts   []string          // canonical keys or SHA256s of newly seen external scripts
	InlineSigs   [][32]byte        // semantic signatures of inline <script> blocks
	JSFoundURLs  []string          // raw URLs of routes/paths discovered in page scripts
	JSAPIOrigins []string          // API origins discovered in page scripts
	Links        []Found           // HTML/DOM links and forms discovered on the page
	InScope      func(string) bool // page/host scope filter
	ExtraGain    bool              // e.g. explore actions discovered interactive state
}

// Skeleton implements thread-safe Marginal Information-Gain (ΔInformation)
// tracking per (origin, pathSkeleton, queryKeySet) using a bounded two-tier
// Prefix Trie shared by both the HTTP crawler and the CDP browser frontier.
type Skeleton struct {
	mu         sync.Mutex
	roots      map[string]*skelNode
	nodeCount  map[string]int
	stats      map[string]*skelStat
	seenInline map[string]map[[32]byte]bool
	seenForms  map[string]map[string]bool
	seenLinks  map[string]map[string]bool
	seenScript map[string]map[string]bool
}

// NewSkeleton creates a new bounded Prefix-Trie skeleton tracker.
func NewSkeleton() *Skeleton {
	return &Skeleton{
		roots:      map[string]*skelNode{},
		nodeCount:  map[string]int{},
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
	if len(seg) >= 16 && hasDigit && hasLetter && !strings.ContainsAny(seg, ".-") {
		return true
	}
	return false
}

func isTechIdentifier(s string) bool {
	low := strings.ToLower(s)
	if techIdentifiers[low] {
		return true
	}
	if len(low) >= 2 && low[0] == 'v' {
		ok := true
		for i := 1; i < len(low); i++ {
			c := low[i]
			if (c < '0' || c > '9') && c != '.' {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// isSlugCandidate reports whether seg has the morphology of a CMS/article/item
// slug (multi-hyphen title slug, long handle, or numbered item like post-1)
// rather than a short static controller/section/page identifier (/admin,
// /billing, /api-keys, /pages/area.html).
func isSlugCandidate(seg string) bool {
	ext := strings.ToLower(path.Ext(seg))
	isPageFile := staticPageExts[ext]
	base := seg
	if isPageFile {
		base = strings.TrimSuffix(seg, path.Ext(seg))
	}
	if strings.Count(base, "-") >= 2 || len(base) > 26 {
		return true
	}
	if isPageFile || isTechIdentifier(base) {
		return false
	}
	for i := 0; i < len(base); i++ {
		if base[i] >= '0' && base[i] <= '9' {
			return true
		}
	}
	return false
}

func skelOriginOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if p := u.Port(); (scheme == "http" && p == "80") || (scheme == "https" && p == "443") {
		host = strings.ToLower(u.Hostname())
	}
	return scheme + "://" + host
}

// Key registers (when register is true) rawURL in its origin's Prefix Trie and
// returns its structural key and whether it belongs to a dynamic/paginated template.
func (s *Skeleton) Key(rawURL string, register bool) (key string, dynamic bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyLocked(rawURL, register)
}

func (s *Skeleton) ensureWildLocked(origin string, cur *skelNode, register bool) *skelNode {
	if cur == nil {
		return nil
	}
	if cur.wild == nil && register && s.nodeCount[origin] < maxSkelNodesPerOrigin {
		cur.wild = &skelNode{}
		s.nodeCount[origin]++
	}
	return cur.wild
}

func (s *Skeleton) keyLocked(rawURL string, register bool) (key string, dynamic bool) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	origin := skelOriginOf(rawURL)
	if origin == "" {
		return "", false
	}
	root := s.roots[origin]
	if root == nil && register && len(s.roots) < maxSkelOrigins {
		root = &skelNode{}
		s.roots[origin] = root
		s.nodeCount[origin] = 1
	}

	trimmed := strings.Trim(u.Path, "/")
	var outSegs []string
	cur := root
	if trimmed != "" {
		segs := strings.Split(trimmed, "/")
		for segIdx, seg := range segs {
			if isImmediateParamSegment(seg) {
				dynamic = true
				outSegs = append(outSegs, "{id}")
				cur = s.ensureWildLocked(origin, cur, register)
				continue
			}
			// Always check already-established static/known child subtrees BEFORE
			// checking collapsed flags so previously discovered routes are never
			// retroactively swallowed into {slug}.
			if cur != nil {
				if nx := cur.staticChildren[seg]; nx != nil {
					cur = nx
					outSegs = append(outSegs, seg)
					continue
				}
				if nx := cur.children[seg]; nx != nil {
					cur = nx
					outSegs = append(outSegs, seg)
					continue
				}
			}

			if !isSlugCandidate(seg) {
				// Root-level controller/section names (/about, /pricing, /admin,
				// /billing, /api-keys...) NEVER collapse into /{slug}.
				if segIdx > 0 && cur != nil && cur.staticCollapsed {
					dynamic = true
					outSegs = append(outSegs, "{slug}")
					cur = s.ensureWildLocked(origin, cur, register)
					continue
				}
				if cur != nil && register {
					if segIdx > 0 && len(cur.staticChildren)+1 >= SkelStaticFanoutThreshold {
						cur.staticCollapsed = true
						dynamic = true
						outSegs = append(outSegs, "{slug}")
						cur = s.ensureWildLocked(origin, cur, true)
						continue
					}
					if s.nodeCount[origin] < maxSkelNodesPerOrigin {
						if cur.staticChildren == nil {
							cur.staticChildren = map[string]*skelNode{}
						}
						nx := &skelNode{}
						cur.staticChildren[seg] = nx
						s.nodeCount[origin]++
						cur = nx
					} else {
						cur = nil
					}
				} else {
					cur = nil
				}
				outSegs = append(outSegs, seg)
				continue
			}

			// Slug-candidate branch (>= 2 hyphens, > 26 chars, or numbered item).
			if cur != nil && cur.collapsed {
				dynamic = true
				outSegs = append(outSegs, "{slug}")
				cur = s.ensureWildLocked(origin, cur, register)
				continue
			}
			if cur != nil && register {
				if len(cur.children)+1 >= SkelFanoutThreshold {
					cur.collapsed = true
					dynamic = true
					outSegs = append(outSegs, "{slug}")
					cur = s.ensureWildLocked(origin, cur, true)
					continue
				}
				if s.nodeCount[origin] < maxSkelNodesPerOrigin {
					if cur.children == nil {
						cur.children = map[string]*skelNode{}
					}
					nx := &skelNode{}
					cur.children[seg] = nx
					s.nodeCount[origin]++
					cur = nx
				} else {
					cur = nil
				}
			} else {
				cur = nil
			}
			outSegs = append(outSegs, seg)
		}
	}

	pathSkel := "/"
	if len(outSegs) > 0 {
		pathSkel = "/" + strings.Join(outSegs, "/")
	}
	key = origin + pathSkel
	if u.RawQuery != "" {
		q := u.Query()
		if len(q) > 0 {
			qKeys := make([]string, 0, len(q))
			for k := range q {
				qKeys = append(qKeys, k)
			}
			sort.Strings(qKeys)
			dynamic = true
			if len(qKeys) > maxQueryKeysInSkel {
				rem := len(qKeys) - maxQueryKeysInSkel
				qKeys = append(qKeys[:maxQueryKeysInSkel:maxQueryKeysInSkel], "+"+itoaSmall(rem))
			}
			key += "?" + strings.Join(qKeys, "&")
		}
	}
	return key, dynamic
}

func itoaSmall(n int) string {
	if n <= 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// IsSaturated reports whether structural key k has already saturated.
func (s *Skeleton) IsSaturated(k string) bool {
	if s == nil || k == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats[k]
	return st != nil && st.saturated
}

// ShouldSkip reports whether rawURL belongs to a dynamic SSR/paginated template
// that has already yielded zero marginal information across repeated visits.
func (s *Skeleton) ShouldSkip(rawURL string) bool {
	if s == nil {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || SpecFile(u.Path) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, dynamic := s.keyLocked(rawURL, true)
	if !dynamic || key == "" {
		return false
	}
	st := s.stats[key]
	return st != nil && st.saturated
}

func (s *Skeleton) markSeenLinkLocked(origin, k string) bool {
	m := s.seenLinks[origin]
	if m == nil {
		if len(s.seenLinks) >= maxSkelOrigins {
			return false
		}
		m = map[string]bool{}
		s.seenLinks[origin] = m
	}
	if m[k] {
		return false
	}
	if len(m) < maxSeenPerOrigin {
		m[k] = true
	}
	return true
}

// Observe records what a visited page contributed and returns whether it
// yielded positive marginal information (ΔInfo > 0).
func (s *Skeleton) Observe(obs Observation) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key, dynamic := s.keyLocked(obs.PageURL, true)
	if key == "" {
		return false
	}
	origin := skelOriginOf(obs.PageURL)
	if origin == "" {
		return false
	}
	gained := obs.ExtraGain

	if len(obs.NewScripts) > 0 {
		gained = true
		m := s.seenScript[origin]
		if m == nil && len(s.seenScript) < maxSkelOrigins {
			m = map[string]bool{}
			s.seenScript[origin] = m
		}
		if m != nil {
			for _, ck := range obs.NewScripts {
				if ck != "" && len(m) < maxSeenPerOrigin {
					m[ck] = true
				}
			}
		}
	}

	if len(obs.InlineSigs) > 0 {
		m := s.seenInline[origin]
		if m == nil && len(s.seenInline) < maxSkelOrigins {
			m = map[[32]byte]bool{}
			s.seenInline[origin] = m
		}
		for _, sig := range obs.InlineSigs {
			if m == nil || !m[sig] {
				if m != nil && len(m) < maxSeenPerOrigin {
					m[sig] = true
				}
				gained = true
			}
		}
	}

	for _, raw := range obs.JSFoundURLs {
		lk, _ := s.keyLocked(raw, false)
		if lk != "" && s.markSeenLinkLocked(origin, "js:"+lk) {
			gained = true
		}
	}
	for _, orig := range obs.JSAPIOrigins {
		if orig != "" && s.markSeenLinkLocked(origin, "orig:"+orig) {
			gained = true
		}
	}

	for _, l := range obs.Links {
		u, err := url.Parse(l.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		inScope := (obs.InScope != nil && obs.InScope(u.Hostname())) ||
			(obs.InScope == nil && skelOriginOf(l.URL) == origin)
		if !inScope {
			continue
		}
		if l.How == Form {
			lk, _ := s.keyLocked(l.URL, true)
			if lk == "" {
				continue
			}
			fk := l.Method + " " + lk
			fm := s.seenForms[origin]
			if fm == nil && len(s.seenForms) < maxSkelOrigins {
				fm = map[string]bool{}
				s.seenForms[origin] = fm
			}
			if fm == nil || !fm[fk] {
				if fm != nil && len(fm) < maxSeenPerOrigin {
					fm[fk] = true
				}
				gained = true
			}
			continue
		}
		if !l.Visit {
			continue
		}
		lk, _ := s.keyLocked(l.URL, true)
		if lk != "" && s.markSeenLinkLocked(origin, lk) {
			gained = true
		}
	}

	if obs.Status < 200 || obs.Status >= 400 || !dynamic {
		return gained
	}
	st := s.stats[key]
	if st == nil {
		if len(s.stats) >= maxSkelStats {
			return gained
		}
		st = &skelStat{}
		s.stats[key] = st
	}
	st.visits++
	if gained {
		st.emptyStreak = 0
	} else {
		st.emptyStreak++
		if st.visits >= SkelMinVisits && st.emptyStreak >= SkelMaxEmptyStreak {
			st.saturated = true
		}
	}
	return gained
}

// RecordAsync deterministically records route and API-origin skeletons
// discovered by external <script src> bundles after async level drain finishes.
func (s *Skeleton) RecordAsync(pageURL string, foundURLs, origins []string) {
	if s == nil || (len(foundURLs) == 0 && len(origins) == 0) {
		return
	}
	origin := skelOriginOf(pageURL)
	if origin == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range foundURLs {
		if lk, _ := s.keyLocked(raw, false); lk != "" {
			s.markSeenLinkLocked(origin, "js:"+lk)
		}
	}
	for _, o := range origins {
		if o != "" {
			s.markSeenLinkLocked(origin, "orig:"+o)
		}
	}
}
