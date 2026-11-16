package roles

import (
	"slices"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/flow"
)

// featureKey names an action as the same on any role's page: by the
// element's id, name or target before its text, which may hold the user's
// name or a count ("Hi, alice", "Inbox (3)").
func featureKey(f flow.Flow) string {
	who := ""
	if el := f.Element; el != nil {
		switch {
		case el.ID != "":
			who = "#" + norm(el.ID)
		case el.Name != "":
			who = "name=" + norm(el.Name)
		case el.Href != "":
			who = "href=" + pageKey(el.Href)
		case el.Action != "" && f.Kind == "submit":
			who = "action=" + pageKey(el.Action)
		default:
			who = el.Tag + "/" + el.Role + " " + labelKey(el.Label)
		}
	} else {
		who = labelKey(f.Label)
	}
	return f.Kind + " " + pageKey(f.Page) + " " + who
}

func labelKey(s string) string {
	return norm(emailRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "{email}"))
}

// features compares the actions of the roles: a person's in watch, or
// explore's, with the requests they sent.
func (c *comparer) features() []Item {
	type agg struct {
		obs
		label  string
		writes int
		eps    []string
	}
	by := make([]map[string]*agg, len(c.roles))
	keys := map[string]bool{}
	pagesOf := map[string][]string{}
	for i, d := range c.roles {
		by[i] = map[string]*agg{}
		for _, fo := range d.flows {
			f := fo.f
			if f.Kind == "load" || f.Kind == "background" {
				continue
			}
			k := featureKey(f)
			a := by[i][k]
			if a == nil {
				a = &agg{label: f.Label}
				by[i][k] = a
			}
			keys[k] = true
			pagesOf[k] = uniq(pagesOf[k], pageKey(f.Page))
			a.writes += len(f.Writes)
			for _, ep := range f.Endpoints {
				a.eps = uniq(a.eps, ep.Method+" "+ep.Template)
			}
			for _, r := range f.Requests {
				q, ok := d.res.Request(fo.run, r.ID)
				if !ok {
					continue
				}
				a.refs = append(a.refs, Ref{fo.run, r.ID})
				switch {
				case strings.HasPrefix(q.Outcome, "held_back"):
					a.held++
				case q.Status > 0 && !slices.Contains(a.statuses, q.Status):
					a.statuses = append(a.statuses, q.Status)
				}
			}
		}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []Item
	for _, k := range sorted {
		states := make([]State, len(c.roles))
		ev := make([]*Evidence, len(c.roles))
		for i := range c.roles {
			a := by[i][k]
			if a == nil {
				states[i] = Absent
				if !c.visited(i, pagesOf[k]) {
					states[i] = Unknown
				}
				continue
			}
			states[i] = Used // an action that sent nothing is there all the same
			if len(a.refs) > 0 {
				if s := callState(a.obs); s != Unknown {
					states[i] = s
				}
			}
			slices.Sort(a.statuses)
			if len(a.refs) > 5 {
				a.refs = a.refs[:5]
			}
			ev[i] = &Evidence{Label: c.o.Redact(a.label), Statuses: a.statuses, Writes: a.writes, Params: a.eps, Refs: a.refs}
		}
		it := c.item("feature", k, states, c.nativeByPages(pagesOf[k]), ev)
		if it.Class != "" {
			out = append(out, it)
		}
	}
	return out
}
