package roles

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/store"
)

// scripts compares the scripts of the roles, by canonical key: the
// versions of one file across builds share it. It also notes, by SHA-256,
// the role each gated script belongs to, for the endpoints in it.
func (c *comparer) scripts() ([]Item, []string) {
	type entries []store.Entry
	by := make([]map[string]entries, len(c.roles))
	keys := map[string]bool{}
	for i, d := range c.roles {
		by[i] = map[string]entries{}
		for _, e := range d.scripts {
			if len(e.CanonicalKeys) == 0 || ownOrThirdParty(e) {
				continue
			}
			k := e.CanonicalKeys[0]
			by[i][k] = append(by[i][k], e)
			keys[k] = true
		}
	}
	c.scriptNative = map[string]int{}
	var out []Item
	builds := 0
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		states := make([]State, len(c.roles))
		ev := make([]*Evidence, len(c.roles))
		var pages []string // where the roles that have it loaded it
		for i := range c.roles {
			es := by[i][k]
			if len(es) == 0 {
				continue
			}
			states[i] = Code
			e := &Evidence{}
			for _, x := range es {
				if !resolvedOnly(x) {
					states[i] = Used
				}
				if c.roles[i].latest.IsZero() || !x.LastSeen.Before(c.roles[i].latest) {
					e.SHA256 = uniq(e.SHA256, x.SHA256)
				}
				for _, p := range x.Pages {
					pages = uniq(pages, pageKey(p))
					if len(e.Pages) < 5 {
						e.Pages = uniq(e.Pages, c.o.Redact(p))
					}
				}
			}
			slices.Sort(e.SHA256)
			ev[i] = e
		}
		for i := range c.roles {
			if states[i] == "" {
				states[i] = Absent
				if !c.visited(i, pages) {
					states[i] = Unknown
				}
			}
		}
		it := c.item("script", k, states, -1, ev)
		if it.Class == HigherOnly {
			it.Class = ServerGated
		}
		// One file, other contents for each role: rendered by role. Files
		// with a build hash in their name differ between builds instead.
		differs := false
		var first []string
		for i := range c.roles {
			if !states[i].uses() || ev[i] == nil {
				continue
			}
			if first == nil {
				first = ev[i].SHA256
			} else if !slices.Equal(first, ev[i].SHA256) {
				differs = true
			}
		}
		switch {
		case differs && strings.Contains(k, "[h]"):
			builds++
		case differs && !strings.Contains(k, "#"):
			if it.Class == Same {
				it.Class = ContentDiffers
			} else {
				it.Also = append(it.Also, ContentDiffers)
			}
		}
		if lowest := slices.Index(c.roleNames(), it.Lowest); lowest > 0 && (it.Class == ClientGated || it.Class == ServerGated) {
			for i := range c.roles {
				for _, x := range by[i][k] {
					c.scriptNative[x.SHA256] = lowest
				}
			}
		}
		if it.Class != "" {
			out = append(out, it)
		}
	}
	var warn []string
	if builds > 0 {
		warn = append(warn, fmt.Sprintf("%d script(s) with a build hash in their name differ between the roles: the target may have been deployed between the crawls; compare crawls of one build", builds))
	}
	return out, warn
}

// resolvedOnly reports whether only the resolver fetched a script: no page
// loaded it, and V8 never compiled it.
func resolvedOnly(e store.Entry) bool {
	return slices.Contains(e.Tags, "resolved") && !slices.Contains(e.Via, "debugger")
}

func ownOrThirdParty(e store.Entry) bool {
	for _, t := range e.Tags {
		if t == "third-party" || strings.Contains(t, "jsharvest") {
			return true
		}
	}
	return false
}

func (c *comparer) roleNames() []string {
	out := make([]string, len(c.roles))
	for i, r := range c.roles {
		out[i] = r.name
	}
	return out
}
