package roles

import (
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// apiTypes are the requests that call endpoints (as package endpoints
// counts them).
var apiTypes = map[string]bool{"Fetch": true, "XHR": true, "EventSource": true, "WebSocket": true, "Ping": true, "": true}

// call is one API request of one role, with its endpoint key.
type call struct {
	role   int
	req    *results.Req
	key    string
	op     string // GraphQL operation, or discriminator=value
	params []string
}

// obs is what one role did with one endpoint.
type obs struct {
	statuses []int64
	held     int
	samples  []string
	refs     []Ref
	pages    []string
	params   []string
}

// endpoints compares the endpoints the roles called, templated together
// (so that their templates agree: a slug of the user, an id of the admin),
// and pairs the endpoints only in code with them.
func (c *comparer) endpoints(_ []Item, _ []Item) []Item {
	host := c.host()
	var calls []call
	var tcalls []traffic.Entry // what the templates need: method, URL, stack
	for i, d := range c.roles {
		for _, q := range d.reqs {
			if q.Internal || q.Challenge || !apiTypes[q.ResourceType] {
				continue
			}
			u, err := url.Parse(q.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ws" && u.Scheme != "wss") || !c.o.InScope(u.Hostname()) {
				continue
			}
			cl := call{role: i, req: q}
			slim := traffic.Entry{Method: q.Method, URL: q.URL}
			var more []call // a GraphQL batch: a call for each operation after the first
			if entry, err := d.res.Entry(q.Run, q.ID); err == nil {
				ct := entry.Headers["content-type"]
				cl.params, cl.op = paramNames(q.Method, u, ct, entry.Body.Body)
				slim.Initiator = entry.Initiator
				if parts := flow.SplitBatch(entry.Body.Body); parts != nil {
					for k, p := range parts {
						c1 := call{role: i, req: q}
						c1.params, c1.op = paramNames(q.Method, u, ct, p.Body)
						c1.op = p.Op
						if k == 0 {
							cl = c1
						} else {
							more = append(more, c1)
						}
					}
				}
			}
			calls = append(calls, cl)
			tcalls = append(tcalls, slim)
			for _, m := range more {
				calls = append(calls, m)
				tcalls = append(tcalls, slim)
			}
		}
	}
	// Templated as the flows are: by the application's frame under its
	// request wrapper, which every call goes through.
	templates := flow.EntryTemplates(tcalls, func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && (u.Scheme == "http" || u.Scheme == "https") && !c.o.InScope(u.Hostname())
	})
	byKey := map[string][]obs{}
	order := []string{}
	itemTemplate := map[string]string{} // key -> METHOD host template, without operation
	itemOp := map[string]string{}
	for n := range calls {
		cl := &calls[n]
		u, _ := url.Parse(cl.req.URL)
		params := cl.params
		base := cl.req.Method + " " + u.Host + templates[n]
		cl.key = base
		if cl.op != "" {
			cl.key += " " + cl.op
		}
		if _, ok := byKey[cl.key]; !ok {
			byKey[cl.key] = make([]obs, len(c.roles))
			order = append(order, cl.key)
			itemTemplate[cl.key], itemOp[cl.key] = base, cl.op
		}
		o := &byKey[cl.key][cl.role]
		switch {
		case strings.HasPrefix(cl.req.Outcome, "held_back"):
			o.held++
		case cl.req.Status > 0 && !slices.Contains(o.statuses, cl.req.Status):
			o.statuses = append(o.statuses, cl.req.Status)
		}
		if len(o.samples) < 5 {
			o.samples = uniq(o.samples, u.EscapedPath())
		}
		if len(o.refs) < 5 {
			o.refs = append(o.refs, Ref{cl.req.Run, cl.req.ID})
		}
		if cl.req.Page != "" {
			o.pages = uniq(o.pages, pageKey(cl.req.Page))
		}
		for _, p := range params {
			o.params = uniq(o.params, p)
		}
	}

	// The endpoints only in code: paired with what the roles called when
	// their template matches it; the rest are items of their own.
	code := make([]map[string]bool, len(c.roles)) // by role, keys known as code
	gates := map[string][]int{}                   // by key, the gate of each catalog endpoint that is it
	staticOnly := map[string][]bool{}
	var staticOrder []string
	for i, d := range c.roles {
		code[i] = map[string]bool{}
		for _, e := range d.catalog {
			if e.ThirdParty || (e.Host != "" && !c.o.InScope(hostname(e.Host))) {
				continue
			}
			matched := c.pair(e, host, order, itemTemplate, itemOp, byKey)
			gated := c.gatedBy(e)
			for _, k := range matched {
				// Code of this role: an endpoint it never called, or an
				// operation of one (a GraphQL mutation, an RPC action) its
				// code names and it never sent.
				if e.Status == "static" || (itemOp[k] != "" && namesOp(e, itemOp[k])) {
					code[i][k] = true
				}
				if len(e.Static) > 0 { // seen in traffic only: says nothing of the scripts
					gates[k] = append(gates[k], gated)
				}
			}
			if len(matched) > 0 || e.Status != "static" || generic(e) {
				continue
			}
			k := staticKey(e, host)
			if staticOnly[k] == nil {
				staticOnly[k] = make([]bool, len(c.roles))
				staticOrder = append(staticOrder, k)
			}
			staticOnly[k][i] = true
			gates[k] = append(gates[k], gated)
		}
	}
	native := map[string]int{}
	for k, g := range gates {
		if n := nativeOf(g); n >= 0 {
			native[k] = n
		}
	}

	var out []Item
	for _, k := range order {
		os := byKey[k]
		states := make([]State, len(c.roles))
		ev := make([]*Evidence, len(c.roles))
		var pages []string
		for i := range c.roles {
			pages = append(pages, os[i].pages...)
		}
		for i := range c.roles {
			o := os[i]
			if len(o.refs) == 0 {
				switch {
				case code[i][k]:
					states[i] = Code
				case c.visited(i, pages):
					states[i] = Absent
				default:
					states[i] = Unknown
				}
				continue
			}
			states[i] = callState(o)
			slices.Sort(o.statuses)
			e := &Evidence{Statuses: o.statuses, Refs: o.refs, Params: o.params, Mixed: mixed(o.statuses)}
			for _, s := range o.samples {
				e.Samples = append(e.Samples, c.o.Redact(s))
			}
			for _, p := range o.pages {
				if len(e.Pages) < 5 {
					e.Pages = append(e.Pages, c.o.Redact(p))
				}
			}
			slices.Sort(e.Params)
			ev[i] = e
		}
		n, ok := native[k]
		if !ok {
			n = -1
		}
		n = max(n, c.nativeByPath(itemTemplate[k]), c.nativeByPages(pages))
		it := c.item("endpoint", k, states, n, ev)
		if it.Class == "" {
			continue
		}
		if extra := shapeDiffers(states, ev); extra {
			if it.Class == Same {
				it.Class = ShapeDiffers
			} else {
				it.Also = append(it.Also, ShapeDiffers)
			}
		}
		out = append(out, it)
	}
	sort.Strings(staticOrder)
	for _, k := range staticOrder {
		states := make([]State, len(c.roles))
		for i, has := range staticOnly[k] {
			if has {
				states[i] = Code
			} else {
				states[i] = Absent
			}
		}
		n, ok := native[k]
		if !ok {
			n = -1
		}
		it := c.item("endpoint", k, states, max(n, c.nativeByPath(k)), nil)
		if it.Class != "" {
			out = append(out, it)
		}
	}
	return out
}

// callState is a role's state from its calls: a success, a refusal, or a
// write the guard held back. A call that failed or got no answer says
// nothing.
func callState(o obs) State {
	ok, refused, moved := false, false, false
	for _, s := range o.statuses {
		switch {
		case s >= 200 && s < 300:
			ok = true
		case s == 401 || s == 403:
			refused = true
		case s >= 300 && s < 400:
			moved = true
		}
	}
	switch {
	case ok:
		return Used
	case refused:
		return Denied
	case moved:
		return Redirected
	case o.held > 0:
		return Held
	case len(o.statuses) > 0:
		return Denied // answered, never with success (404, 500): not the role's to use
	}
	return Unknown
}

func mixed(statuses []int64) bool {
	ok := slices.ContainsFunc(statuses, func(s int64) bool { return s >= 200 && s < 300 })
	no := slices.ContainsFunc(statuses, func(s int64) bool { return s == 401 || s == 403 || s == 404 })
	return ok && no
}

// shapeDiffers reports whether a higher role sent parameters the lowest
// role that used the endpoint did not.
func shapeDiffers(states []State, ev []*Evidence) bool {
	base := -1
	for i, s := range states {
		if !s.uses() || ev[i] == nil {
			continue
		}
		if base < 0 {
			base = i
			continue
		}
		for _, p := range ev[i].Params {
			if !slices.Contains(ev[base].Params, p) {
				return true
			}
		}
	}
	return false
}

// paramNames lists the names of a request's parameters (query:, json:,
// form:) and its operation: a GraphQL operation's name, or the value of a
// discriminating query parameter.
func paramNames(method string, u *url.URL, contentType, body string) (names []string, op string) {
	q := u.Query()
	for k := range q {
		names = append(names, "query:"+k)
	}
	op = flow.Operation(u, contentType, body)
	body = strings.TrimSpace(body)
	switch {
	case strings.Contains(contentType, "json") || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "["):
		var v any
		if json.Unmarshal([]byte(body), &v) == nil {
			jsonNames(v, "json:", &names)
		}
	case strings.Contains(contentType, "x-www-form-urlencoded") || (body != "" && !strings.ContainsAny(body, " \n{<")):
		if f, err := url.ParseQuery(body); err == nil {
			for k := range f {
				names = append(names, "form:"+k)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names), op
}

func jsonNames(v any, prefix string, out *[]string) {
	if len(*out) > 100 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			*out = append(*out, prefix+k)
			jsonNames(x, prefix+k+".", out)
		}
	case []any:
		for _, x := range t {
			jsonNames(x, prefix, out)
		}
	}
}

// pair finds the called endpoints a catalog endpoint is: its template
// (with its client's base, preferred when known) matches a path one of
// the roles called, with the same method and host. An operation of a
// GraphQL or RPC endpoint pairs only with code that names it.
func (c *comparer) pair(e endpoints.Endpoint, host string, order []string, tmpl, op map[string]string, by map[string][]obs) []string {
	if generic(e) {
		return nil
	}
	var exact, bare []*regexp.Regexp
	allowedHosts := map[string]bool{}
	if e.Host != "" {
		allowedHosts[strings.ToLower(hostname(e.Host))] = true
	}
	switch {
	case e.Base != "":
		exact = append(exact, templateRe(joinRoleBasePath(e.Base, e.Path)))
	case len(e.Bases) > 0:
		for _, b := range e.Bases {
			if e.Host == "" {
				if u, err := url.Parse(b); err == nil && u.Host != "" {
					allowedHosts[strings.ToLower(u.Hostname())] = true
				} else if strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") && host != "" {
					allowedHosts[strings.ToLower(hostname(host))] = true
				}
			}
			exact = append(exact, templateRe(joinRoleBasePath(b, e.Path)))
		}
		bare = append(bare, templateRe(strings.TrimPrefix(e.Path, "{}")))
	default:
		exact = append(exact, templateRe(strings.TrimPrefix(e.Path, "{}")))
	}
	if len(allowedHosts) == 0 && host != "" {
		allowedHosts[strings.ToLower(hostname(host))] = true
	}
	match := func(res []*regexp.Regexp) []string {
		var out []string
		for _, k := range order {
			method, rest, _ := strings.Cut(tmpl[k], " ")
			if e.Method != "" && !strings.EqualFold(method, e.Method) {
				continue
			}
			h, _, _ := strings.Cut(rest, "/")
			if len(allowedHosts) > 0 && !allowedHosts[strings.ToLower(hostname(h))] {
				continue
			}
			if o := op[k]; o != "" && !namesOp(e, o) {
				continue
			}
			hit := false
			for _, os := range by[k] {
				for _, s := range os.samples {
					if slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(s) }) {
						hit = true
					}
				}
			}
			if hit {
				out = append(out, k)
			}
		}
		return out
	}
	if m := match(exact); len(m) > 0 {
		return m
	}
	return match(bare)
}

// gatedBy is the role an endpoint's code belongs to: when every script
// that calls it is one only a higher role runs (or is given), the lowest
// such role; -1 when any caller is a script lower roles run too.
func (c *comparer) gatedBy(e endpoints.Endpoint) int {
	n := -1
	for _, s := range e.Static {
		g, ok := c.scriptNative[s.SHA256]
		if !ok {
			return -1
		}
		if n < 0 || g < n {
			n = g
		}
	}
	return n
}

// nativeOf is the role an endpoint's code gives it, from the gate of each
// catalog endpoint that is it: none (-1) when any of them is called from a
// script lower roles have too, else the highest.
func nativeOf(gates []int) int {
	n := -1
	for _, g := range gates {
		if g < 0 {
			return -1
		}
		n = max(n, g)
	}
	return n
}

// namesOp reports whether a catalog endpoint's code names an operation.
func namesOp(e endpoints.Endpoint, op string) bool {
	name, value, _ := strings.Cut(op, "=")
	if name == "op" {
		// Operations read "mutation PurgeUsers".
		return slices.ContainsFunc(e.Operations, func(o string) bool {
			f := strings.Fields(o)
			return o == value || (len(f) > 0 && f[len(f)-1] == value)
		})
	}
	for _, s := range e.Static {
		if strings.Contains(strings.ToLower(s.Snippet), strings.ToLower(name+"="+value)) {
			return true
		}
	}
	return false
}

var placeRe = regexp.MustCompile(`\\\{[^}]*\\\}`)

// templateRe matches the paths of a template: {…} is one segment.
func templateRe(t string) *regexp.Regexp {
	t, _, _ = strings.Cut(t, "?")
	return regexp.MustCompile("^" + placeRe.ReplaceAllString(regexp.QuoteMeta(strings.TrimRight(t, "/")), `[^/]+`) + "/?$")
}

func joinRoleBasePath(base, path string) string {
	bp := strings.TrimRight(base, "/")
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		bp = strings.TrimRight(u.EscapedPath(), "/")
	}
	p := strings.TrimPrefix(path, "{}")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if bp != "" && (p == bp || strings.HasPrefix(p, bp+"/")) {
		return p
	}
	return bp + p
}

// generic reports whether a catalog endpoint's template says too little
// to pair with: fewer than two fixed segments (/api/{} of a wrapper).
func generic(e endpoints.Endpoint) bool {
	full := joinRoleBasePath(e.Base, e.Path)
	if e.Base == "" && len(e.Bases) > 0 {
		full = joinRoleBasePath(e.Bases[0], e.Path)
	}
	fixed := 0
	for _, seg := range strings.Split(strings.Trim(full, "/"), "/") {
		if seg != "" && !strings.Contains(seg, "{") {
			fixed++
		}
	}
	return fixed < 2
}

// staticKey keys an endpoint only in code: {…} as {}, its base when known.
func staticKey(e endpoints.Endpoint, host string) string {
	h := e.Host
	p := joinRoleBasePath(e.Base, e.Path)
	if e.Base == "" && len(e.Bases) == 1 {
		if u, err := url.Parse(e.Bases[0]); err == nil && u.Host != "" && h == "" {
			h = u.Host
		}
		p = joinRoleBasePath(e.Bases[0], e.Path)
	}
	if h == "" {
		h = host
	}
	p = regexp.MustCompile(`\{[^}]*\}`).ReplaceAllString(strings.TrimRight(p, "/"), "{}")
	m := e.Method
	if m == "" {
		m = "GET"
	}
	return m + " " + h + p
}

// nativeByPages gives an endpoint called from the pages of a higher role
// (pages a lower role was refused, or never had) that role.
func (c *comparer) nativeByPages(pages []string) int {
	n := -1
	for _, p := range pages {
		it, ok := c.pageItems[p]
		if !ok || (it.Class != DeniedBelow && it.Class != HigherOnly && it.Class != NotCovered) {
			continue
		}
		n = max(n, slices.Index(c.roleNames(), it.Lowest))
	}
	return n
}

func (c *comparer) host() string {
	for _, d := range c.roles {
		for _, q := range d.reqs {
			if u, err := url.Parse(q.URL); err == nil && c.o.InScope(u.Hostname()) {
				return u.Host
			}
		}
	}
	return ""
}

func hostname(h string) string {
	if u, err := url.Parse("http://" + h); err == nil {
		return u.Hostname()
	}
	return h
}
