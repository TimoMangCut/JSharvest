package monitor

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Severities, highest first.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
	Info   = "info"
)

var severityRank = map[string]int{High: 0, Medium: 1, Low: 2, Info: 3}

// AtLeast reports whether a severity is s or higher.
func AtLeast(severity, s string) bool { return severityRank[severity] <= severityRank[s] }

// Change is a line of changes.jsonl.
type Change struct {
	Kind     string   `json:"kind"`
	Severity string   `json:"severity"`
	Layer    string   `json:"layer"` // endpoint, param, status, script
	Key      string   `json:"key"`
	Roles    []string `json:"roles"`
	Before   string   `json:"before,omitempty"`
	After    string   `json:"after,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// roleCompare is one role's sides: today's content, the baseline's, and
// what the earlier comparable snapshots knew (for "new").
type roleCompare struct {
	role    string
	cur     *Content
	base    *Content   // nil: no baseline for the role
	known   []*Content // the last comparable snapshots, the baseline among them
	partial string     // why the sides do not compare ("" when they do)
	session bool       // the runs lost the session and got it back
}

// interestRe names what a tester looks at first on a new endpoint: an
// admin's or a developer's area.
var interestRe = regexp.MustCompile(`(?i)(^|[/._-])(admin|administrator|internal|debug|staff|manage|management|backoffice|superuser|moderator|swagger|openapi|api-docs|graphiql|playground|actuator|metrics|env|trace|heapdump|beta|preview|test|dev|console|private|impersonat\w*|sudo)([/._-]|$)`)

// riskyParams are the parameter names a tester tries first.
var riskyParams = map[string]bool{
	"role": true, "roles": true, "admin": true, "is_admin": true, "isadmin": true, "permission": true, "permissions": true, "scope": true,
	"debug": true, "include_deleted": true, "internal": true, "impersonate": true, "as_user": true, "sudo": true,
	"owner_id": true, "account_id": true, "org_id": true, "user_id": true, "tenant": true, "tenant_id": true,
	"url": true, "redirect": true, "redirect_uri": true, "next": true, "return_to": true, "returnurl": true, "callback": true,
	"file": true, "path": true, "template": true, "lang": true, "cmd": true,
	"fields": true, "expand": true, "include": true, "price": true, "amount": true, "discount": true,
}

func paramSeverity(name string) (string, string) {
	leaf := strings.ToLower(name)
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}
	switch {
	case riskyParams[leaf]:
		return High, "a parameter testers try first"
	case traffic.Sensitive(leaf):
		return Medium, "a credential's name"
	}
	return Medium, ""
}

// newEndpointSeverity ranks a new endpoint.
func newEndpointSeverity(e *Endpoint, rc *roleCompare, newHost bool) (string, string) {
	switch {
	case newHost:
		return High, "on a host no earlier run reached"
	case interestRe.MatchString(e.Path) || interestRe.MatchString(e.Op):
		return High, "an admin's or a developer's area"
	case e.Method != "" && e.Method != "GET" && e.Method != "HEAD":
		return Medium, "a write"
	case guard.Destructive("http://h" + e.Path):
		return Medium, "names a destructive action"
	}
	return Medium, ""
}

func knows(cs []*Content, e *Endpoint) *Endpoint {
	for _, c := range cs {
		for _, o := range c.Endpoints {
			if same(o, e) {
				return o
			}
		}
	}
	return nil
}

// compareRole lists one role's changes.
func compareRole(rc *roleCompare) []Change {
	var out []Change
	add := func(c Change) {
		c.Roles = []string{rc.role}
		if rc.partial != "" && isLoss(c.Kind) {
			c.Severity, c.Reason = Info, strings.TrimPrefix(c.Reason+"; ", "; ")+"not comparable: "+rc.partial
		}
		out = append(out, c)
	}
	if rc.base == nil {
		return nil // a role's first runs: its baseline
	}
	hosts := map[string]bool{}
	for _, k := range rc.known {
		for h := range k.Hosts {
			hosts[h] = true
		}
		for _, e := range k.Endpoints {
			hosts[e.Host] = true
		}
	}

	for _, e := range rc.cur.Endpoints {
		old := knows(rc.known, e)
		if old == nil {
			sev, why := newEndpointSeverity(e, rc, !hosts[e.Host])
			kind := "endpoint_new"
			if e.Op != "" {
				kind = "operation_new"
			}
			add(Change{Kind: kind, Severity: sev, Layer: "endpoint", Key: e.Key(), After: describe(e), Reason: why})
			continue
		}
		// New parameters: names no earlier comparable snapshot had.
		var names []string
		for n := range e.Params {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			had := false
			for _, k := range rc.known {
				for _, o := range k.Endpoints {
					if same(o, e) && o.Params[n] {
						had = true
					}
				}
			}
			if !had {
				sev, why := paramSeverity(n)
				add(Change{Kind: "param_new", Severity: sev, Layer: "param", Key: e.Key() + " " + n, After: n, Reason: why})
			}
		}
		if b := knows([]*Content{rc.base}, e); b != nil {
			if c, ok := statusChange(b, e, rc.session); ok {
				c.Key = e.Key()
				add(c)
			}
		}
	}

	// Gone: only on evidence. A code endpoint whose script is still there,
	// rebuilt, without it; anything else is told, as info.
	for _, b := range rc.base.Endpoints {
		if knows([]*Content{rc.cur}, b) != nil {
			continue
		}
		c := Change{Kind: "endpoint_gone", Layer: "endpoint", Key: b.Key(), Before: describe(b), Severity: Info}
		switch {
		case b.Code && len(b.Scripts) > 0 && allPresent(b.Scripts, rc.cur.Scripts):
			c.Severity, c.Reason = Medium, "its script is still served and no longer calls it: the server may still answer"
		case b.Code:
			c.Reason = "its script was not seen this time"
		default:
			c.Reason = "seen in traffic only: the crawl may not have triggered it"
		}
		add(c)
	}

	// Scripts: files; a build hash in the name is a rebuild, not news.
	for k, shas := range rc.cur.Scripts {
		hashed := strings.Contains(k, "[h]")
		inKnown := false
		for _, kc := range rc.known {
			if _, ok := kc.Scripts[k]; ok {
				inKnown = true
			}
		}
		switch {
		case !inKnown && hashed:
			add(Change{Kind: "script_new", Severity: Info, Layer: "script", Key: k})
		case !inKnown:
			add(Change{Kind: "script_new", Severity: Low, Layer: "script", Key: k})
		case !hashed && rc.base.Scripts[k] != nil && !slices.Equal(rc.base.Scripts[k], shas):
			add(Change{Kind: "script_changed", Severity: Low, Layer: "script", Key: k, Reason: "the same file, another content"})
		}
	}
	for k := range rc.base.Scripts {
		if _, ok := rc.cur.Scripts[k]; !ok {
			add(Change{Kind: "script_gone", Severity: Info, Layer: "script", Key: k})
		}
	}
	return out
}

func isLoss(kind string) bool {
	return strings.HasSuffix(kind, "_gone")
}

func allPresent(keys []string, scripts map[string][]string) bool {
	for _, k := range keys {
		if _, ok := scripts[k]; !ok {
			return false
		}
	}
	return true
}

// statusChange compares how a role's requests to an endpoint fared: high
// only when every earlier one (two at least) was refused and every one now
// succeeds.
func statusChange(b, c *Endpoint, session bool) (Change, bool) {
	before, after := fares(b), fares(c)
	if before == after || before == "" || after == "" {
		return Change{}, false
	}
	ch := Change{Kind: "status_changed", Layer: "status", Before: before, After: after}
	switch {
	case session:
		ch.Severity, ch.Reason = Info, "the session was lost and put back during the runs"
	case before == "refused" && after == "ok" && b.Refused >= 2:
		ch.Severity, ch.Reason = High, "refused before, answered now: an authorization that went"
	case before == "refused" && after == "ok":
		ch.Severity, ch.Reason = Medium, "refused before (once), answered now"
	case before == "ok" && after == "refused":
		ch.Severity, ch.Reason = Low, "answered before, refused now"
	default:
		ch.Severity = Low
	}
	return ch, true
}

// fares sums an endpoint's answers: ok, refused, mixed, or "" for none.
func fares(e *Endpoint) string {
	switch {
	case e.OK > 0 && e.Refused > 0:
		return "mixed"
	case e.OK > 0:
		return "ok"
	case e.Refused > 0:
		return "refused"
	}
	return ""
}

func describe(e *Endpoint) string {
	var parts []string
	if e.Code {
		parts = append(parts, "in code")
	}
	if e.Traffic {
		parts = append(parts, "in traffic")
	}
	if s := fares(e); s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// merge folds the roles' changes: one line for each change, with the
// roles it holds for, at its highest severity.
func merge(all []Change) []Change {
	by := map[string]*Change{}
	var order []string
	for _, c := range all {
		k := c.Layer + "\x00" + c.Kind + "\x00" + c.Key + "\x00" + c.Before + "\x00" + c.After
		if o := by[k]; o != nil {
			o.Roles = appendNew(o.Roles, c.Roles[0])
			if severityRank[c.Severity] < severityRank[o.Severity] {
				o.Severity, o.Reason = c.Severity, c.Reason
			}
			continue
		}
		cp := c
		by[k] = &cp
		order = append(order, k)
	}
	out := make([]Change, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank[out[i].Severity] != severityRank[out[j].Severity] {
			return severityRank[out[i].Severity] < severityRank[out[j].Severity]
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Counts tallies changes by severity.
func Counts(cs []Change) map[string]int {
	m := map[string]int{}
	for _, c := range cs {
		m[c.Severity]++
	}
	return m
}

func (c Change) String() string {
	return fmt.Sprintf("%-6s %-15s %s [%s]", c.Severity, c.Kind, c.Key, strings.Join(c.Roles, ","))
}
