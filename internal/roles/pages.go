package roles

import (
	"net/url"
	"slices"
	"sort"
	"strings"
)

// pageKey is a page's path with digits as "#", its client-side route
// (#/x) and the query parameters that name a view, so that /item/41 and
// /item/42 are one page and /?page=admin is not /.
func pageKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := strings.TrimRight(u.EscapedPath(), "/")
	if p == "" {
		p = "/"
	}
	k := norm(p)
	if f := u.Fragment; strings.HasPrefix(f, "/") || strings.HasPrefix(f, "!/") {
		k += "#" + norm(strings.TrimRight(f, "/"))
	}
	q := u.Query()
	var view []string
	for name := range q {
		if viewParams[strings.ToLower(name)] {
			view = append(view, name+"="+norm(q.Get(name)))
		}
	}
	sort.Strings(view)
	if len(view) > 0 {
		k += "?" + strings.Join(view, "&")
	}
	return k
}

var viewParams = map[string]bool{"page": true, "view": true, "tab": true, "action": true, "section": true, "module": true, "route": true}

// pageState reads one line of pages.jsonl.
func (d *roleData) pageState(p pageLine) (State, bool) {
	if !p.Visited {
		switch p.Reason {
		case "depth", "limit":
			return Unknown, true // not reached for want of budget: no sign
		case "destructive":
			return Code, true
		}
		return "", false
	}
	switch {
	case p.Status == 401 || p.Status == 403:
		return Denied, true
	case p.FinalURL != "" && d.isLogin(p.FinalURL) && !d.isLogin(p.URL):
		return Denied, true
	case p.FinalURL != "" && pathOf(p.FinalURL) != pathOf(p.URL):
		// A server redirect, or the app's own guard sending the page
		// elsewhere (a SPA answers 200 for every route).
		return Redirected, true
	case p.Status >= 200 && p.Status < 400:
		return Used, true
	}
	return Unknown, true
}

// pages compares the pages each role visited. It also keeps, by role, the
// state of each page, so that the other layers can tell a role that went
// where an item is from one that did not.
func (c *comparer) pages() []Item {
	type seen struct {
		state State
		ev    *Evidence
	}
	by := make([]map[string]seen, len(c.roles))
	keys := map[string]bool{}
	for i, d := range c.roles {
		by[i] = map[string]seen{}
		// Lines in the order written: a later run's word on a page wins,
		// and a visit over a mere mention.
		for _, p := range d.pages {
			st, ok := d.pageState(p)
			if !ok {
				continue
			}
			k := pageKey(p.URL)
			if prev, had := by[i][k]; had && !p.Visited && prev.state != Unknown && prev.state != Code {
				continue
			}
			ev := &Evidence{Status: p.Status, Reason: p.Reason}
			if p.FinalURL != "" && p.FinalURL != p.URL {
				ev.FinalURL = c.o.Redact(p.FinalURL)
			}
			by[i][k] = seen{st, ev}
			keys[k] = true
		}
	}
	c.pageStates = make([]map[string]State, len(c.roles))
	for i := range c.roles {
		c.pageStates[i] = map[string]State{}
		for k, s := range by[i] {
			c.pageStates[i][k] = s.state
		}
	}
	c.pageItems = map[string]Item{}
	var out []Item
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		states := make([]State, len(c.roles))
		ev := make([]*Evidence, len(c.roles))
		for i := range c.roles {
			if s, ok := by[i][k]; ok {
				states[i], ev[i] = s.state, s.ev
			} else {
				states[i] = Absent
			}
		}
		it := c.item("page", k, states, c.nativeByPath(k), ev)
		if it.Class == "" {
			continue
		}
		c.pageItems[k] = it
		out = append(out, it)
	}
	return out
}

// visited tells whether role i went to one of the pages (and was let in
// or turned away there): then an item it did not meet is absent for it,
// and not merely unknown.
func (c *comparer) visited(i int, pages []string) bool {
	if len(pages) == 0 {
		return true
	}
	return slices.ContainsFunc(pages, func(k string) bool {
		s := c.pageStates[i][k]
		return s == Used || s == Denied || s == Redirected
	})
}

// nativeMarks are path segments that name an area of higher roles.
var nativeMarks = []string{"admin", "administrator", "manage", "management", "manager", "internal", "staff", "backoffice", "superuser", "moderator"}

// nativeByPath gives the highest role to a path that names an
// administrative area, so that a lower role using it is reported.
func (c *comparer) nativeByPath(p string) int {
	for _, seg := range strings.FieldsFunc(strings.ToLower(p), func(r rune) bool { return r == '/' || r == '?' || r == '#' || r == '=' || r == '&' || r == ' ' }) {
		for _, m := range nativeMarks {
			if seg == m || strings.HasPrefix(seg, m+"-") || strings.HasPrefix(seg, m+"_") {
				return len(c.roles) - 1
			}
		}
	}
	return -1
}
