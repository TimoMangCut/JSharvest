// Package frontier decides which pages a crawl visits next: it finds URLs
// in a page (its DOM, forms, headers, the HTML hidden in noscript and
// comments, its text, its scripts), keeps a queue of the pages to visit,
// and records the URLs it will not visit, with why. It does no I/O: the
// engine feeds it what the browser saw.
package frontier

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"golang.org/x/net/html"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// How a URL was found. The order of the list is the order in which pages
// of one depth are visited: links first, scripts last.
const (
	Seed     = "seed"
	Link     = "link"
	Form     = "form"
	Redirect = "redirect" // the page went there itself, or a header sent it
	Header   = "header"
	Robots   = "robots"
	Sitemap  = "sitemap"
	Route    = "route" // a client-side route the scripts name
	JS       = "js"
	Popup    = "popup"
	Explore  = "explore"  // where explore's actions sent the page (held), or its route
	Resource = "resource" // an attribute the browser loads, or names, but no page
	Text     = "text"     // a URL written in the page's text
)

var rank = map[string]int{Seed: 0, Link: 1, Form: 2, Redirect: 3, Explore: 3, Header: 4, Robots: 5, Sitemap: 5, Route: 6, JS: 7, Popup: 8, Resource: 9, Text: 9}

// Found is a URL found in a page.
type Found struct {
	URL    string `json:"url"`
	How    string `json:"how"`
	Method string `json:"method,omitempty"` // a form's; GET when empty
	// Visit says the URL is meant to be opened (a link, a GET form, a
	// redirect); otherwise it is only named (an image, a cite).
	Visit bool `json:"-"`
}

func resolve(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") && !hashRoute(ref[1:]) {
		return ""
	}
	low := strings.ToLower(ref)
	for _, p := range []string{"javascript:", "data:", "mailto:", "tel:", "blob:", "about:", "sms:"} {
		if strings.HasPrefix(low, p) {
			return ""
		}
	}
	u, err := base.Parse(ref)
	if err != nil {
		return ""
	}
	return u.String()
}

// hashRoute reports whether a fragment is a client-side route (#/x, #!x).
func hashRoute(frag string) bool {
	return strings.HasPrefix(frag, "/") || strings.HasPrefix(frag, "!")
}

// collector gathers the URLs of one document.
type collector struct {
	out  []Found
	seen map[string]bool
}

func (c *collector) add(base *url.URL, ref, how string, visit bool) {
	if u := resolve(base, ref); u != "" {
		c.addURL(Found{URL: u, How: how, Visit: visit})
	}
}

func (c *collector) addURL(f Found) {
	key := f.URL + " " + f.How + " " + f.Method
	if c.seen[key] {
		return
	}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	c.seen[key] = true
	c.out = append(c.out, f)
}

// resourceAttrs name URLs the browser loads, or that a page only names.
var resourceAttrs = []string{"src", "poster", "data", "codebase", "cite", "longdesc", "lowsrc", "dynsrc", "background",
	"manifest", "profile", "xlink:href", "action"}

var refreshRe = regexp.MustCompile(`(?i)^\s*\d*\s*[;,]?\s*url\s*=\s*['"]?([^'"]+)`)

// element reads one element's URLs. attr gives its attributes.
func (c *collector) element(tag string, attr map[string]string, base *url.URL, svg bool) {
	switch tag {
	case "a", "area":
		if h, ok := attr["href"]; ok {
			if code, ok := strings.CutPrefix(strings.TrimSpace(h), "javascript:"); ok {
				c.script(code, base)
			} else {
				c.add(base, h, Link, true)
			}
		}
		if svg {
			c.add(base, attr["xlink:href"], Link, true)
		}
	case "iframe", "frame":
		c.add(base, attr["src"], Link, true)
	case "link":
		switch rel := strings.ToLower(attr["rel"]); {
		case strings.Contains(rel, "alternate"), strings.Contains(rel, "next"), strings.Contains(rel, "prev"),
			strings.Contains(rel, "canonical"):
			c.add(base, attr["href"], Link, true)
		default:
			c.add(base, attr["href"], Resource, false)
		}
	case "meta":
		if strings.EqualFold(attr["http-equiv"], "refresh") {
			if m := refreshRe.FindStringSubmatch(attr["content"]); m != nil {
				c.add(base, m[1], Redirect, true)
			}
		} else {
			c.text(attr["content"], base)
		}
	case "base":
		c.add(base, attr["href"], Resource, false)
	case "isindex":
		c.add(base, attr["action"], Link, true)
	case "param":
		if v := attr["value"]; strings.Contains(v, "/") {
			c.add(base, v, Resource, false)
		}
	case "applet":
		for _, a := range strings.FieldsFunc(attr["archive"], func(r rune) bool { return r == ',' || r == ' ' }) {
			c.add(base, a, Resource, false)
		}
	}
	for _, a := range resourceAttrs {
		if tag == "isindex" && a == "action" || tag == "form" && a == "action" {
			continue
		}
		if v, ok := attr[a]; ok {
			c.add(base, v, Resource, false)
		}
	}
	if svg && tag != "a" {
		c.add(base, attr["href"], Resource, false)
	}
	for _, a := range []string{"srcset", "imagesrcset"} {
		for _, part := range strings.Split(attr[a], ",") {
			if f := strings.Fields(part); len(f) > 0 {
				c.add(base, f[0], Resource, false)
			}
		}
	}
	for _, p := range strings.Fields(attr["ping"]) {
		c.add(base, p, Resource, false)
	}
	for name, v := range attr {
		if strings.HasPrefix(name, "on") && len(name) > 2 && v != "" {
			c.script(v, base)
		}
	}
}

// script reads the URLs of a bit of JavaScript: an inline handler or a
// javascript: link.
func (c *collector) script(code string, base *url.URL) {
	r := jsapi.Extract([]byte(code))
	for _, f := range FromScript(r, base, false) {
		c.addURL(f)
	}
}

// FromScript turns what jsapi found in a script into URLs to visit: the
// GET endpoints and navigations that are no API's, the routes, and the
// paths. API calls stay in the endpoint catalog. A vendor bundle's routes
// and paths are its libraries' (SheetJS's "/!DocumentSummaryInformation",
// SockJS's "/xhr_send"), never the app's pages: vendor drops them.
func FromScript(r jsapi.Result, base *url.URL, vendor bool) []Found {
	var c collector
	for _, e := range r.Endpoints {
		if strings.Contains(e.URL, "{}") || e.Client || internalPath(e.URL) {
			continue
		}
		switch {
		case e.Kind == "navigation":
			c.add(base, e.URL+query(e.Query), Link, true)
		case e.Method == "GET" || e.Method == "":
			c.add(base, e.URL, JS, e.Kind != "websocket" && e.Kind != "sse")
		}
	}
	if vendor {
		return c.out
	}
	ids := routeIDs(r)
	for _, p := range r.Routes {
		if !strings.Contains(p, "{}") && !strings.Contains(p, ":") && !ids[p] && !internalPath(p) {
			c.add(base, p, Route, true)
		}
	}
	for _, p := range r.Paths {
		if !ids[p] && !internalPath(p) {
			c.add(base, p, JS, true)
		}
	}
	return c.out
}

// internalSegs are the first segments of a framework's own names, which
// its runtime holds as strings: Next.js's and Turbopack's route tree
// (/_head, /_tree, /ROOT/), its pages' internals (/_app, /_error), and
// the build's directories (/_next/, /_vite/) without a file.
var internalSegs = map[string]bool{"_head": true, "_index": true, "_not-found": true, "_tree": true, "_error": true, "_app": true,
	"_document": true, "ROOT": true, "__PAGE__": true, "__DEFAULT__": true}

// internalPath reports whether a path a script names is a framework's
// name rather than a page: those above; /_next and /_vite themselves and
// their directories (/_next/image, /_next/static/immutable) where a file
// would be; a parser's test (/a/b, /a/i: every segment one letter); a
// list (a,b) or a pattern (*).
func internalPath(raw string) bool {
	p := raw
	if i := strings.Index(p, "://"); i > 0 {
		rest := p[i+3:]
		host, path, _ := strings.Cut(rest, "/")
		if strings.ContainsAny(host, ",*") {
			return true
		}
		p = "/" + path
	}
	p, _, _ = strings.Cut(p, "?")
	if strings.ContainsAny(p, ",*") {
		return true
	}
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return false
	}
	if internalSegs[segs[0]] {
		return true
	}
	if segs[0] == "_next" || segs[0] == "_vite" {
		return !strings.Contains(segs[len(segs)-1], ".")
	}
	short := len(segs) >= 2
	for _, s := range segs {
		short = short && len(s) == 1
	}
	return short
}

// layoutSeg is a pathless layout route's segment in a route id
// (TanStack's /_authenticated/home is the page /home).
var layoutSeg = regexp.MustCompile(`^_[A-Za-z][\w-]*$`)

// routeIDs finds the route ids among a script's paths: a path with a
// layout segment (_auth) whose page, without those segments, the script
// names too, or, where the router's root id __root__ is named, is the
// site's root. The page is visited; its id would only be the shell or a
// 404 (/_next/ and /_vite/ are never stripped to a path also named, so
// they stay).
func routeIDs(r jsapi.Result) map[string]bool {
	all := map[string]bool{}
	root := false
	for _, list := range [][]string{r.Routes, r.Paths} {
		for _, p := range list {
			p, _, _ = strings.Cut(p, "?")
			all[p] = true
			root = root || p == "/__root__" || p == "__root__"
		}
	}
	ids := map[string]bool{}
	layouts := map[string]bool{} // segments some id proved a layout's
	var only [][]string          // paths of layout segments alone: /_auth
	for _, list := range [][]string{r.Routes, r.Paths} {
		for _, p := range list {
			if !strings.HasPrefix(p, "/") {
				continue
			}
			segs := strings.Split(p, "/")
			var kept, gone []string
			for _, s := range segs {
				if layoutSeg.MatchString(s) {
					gone = append(gone, s)
				} else {
					kept = append(kept, s)
				}
			}
			if len(gone) == 0 {
				continue
			}
			page := strings.Join(kept, "/")
			if page == "" {
				page = "/"
			}
			switch {
			case page != "/" && (all[page] || all[strings.TrimSuffix(page, "/")]):
				ids[p] = true
				for _, s := range gone {
					layouts[s] = true
				}
			case page == "/" && root:
				ids[p] = true
			case page == "/":
				only = append(only, append([]string{p}, gone...))
			}
		}
	}
	// /_auth is the layout's own id when /_auth/home was one.
	for _, o := range only {
		all := true
		for _, s := range o[1:] {
			all = all && layouts[s]
		}
		if all {
			ids[o[0]] = true
		}
	}
	return ids
}

// vendorRe is the file name of a bundle of libraries only: webpack's
// vendors and chunk-vendors, vendors~main, polyfills, runtime, Next's
// framework.
// A name of the app's own after a dash (vendor-admin-page.js) is no vendor
// bundle's: a hash or node_modules is.
var vendorRe = regexp.MustCompile(`(?i)^(?:chunk-vendors|vendors?|polyfills?|runtime|framework|turbopack|webpack)(?:[.~][\w.~-]*|[-_](?:[0-9a-f]{6,}|node_modules)[\w.~-]*)?\.m?js$`)

// Vendor reports whether a script loaded from one of urls is a bundle of
// libraries.
func Vendor(urls ...string) bool {
	for _, u := range urls {
		p, _, _ := strings.Cut(u, "?")
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			p = p[i+1:]
		}
		if vendorRe.MatchString(p) {
			return true
		}
	}
	return false
}

// query gives a navigation's query names a sample value each, so that
// /search?q= becomes a URL that can be opened.
func query(names []string) string {
	if len(names) == 0 {
		return ""
	}
	v := url.Values{}
	for _, n := range names {
		v.Set(n, "1")
	}
	return "?" + v.Encode()
}

var textURLRe = regexp.MustCompile(`(?i)(?:https?:)?//[a-z0-9][^\s"'<>()\[\]{}]*|(?:\.{1,2}/|/)[\w\-.~%]+(?:/[\w\-.~%]+)*\.[a-z0-9]{2,8}\b`)

// text reads the URLs written in text: absolute ones, and paths that end
// in a file name. They are only named.
func (c *collector) text(s string, base *url.URL) {
	if !strings.Contains(s, "/") {
		return
	}
	for _, m := range textURLRe.FindAllString(s, 50) {
		m = strings.TrimRight(m, ".,;:")
		if strings.HasPrefix(m, "//") && !strings.Contains(m[2:], ".") {
			continue
		}
		c.add(base, m, Text, false)
	}
}

// --- the DOM, as CDP gives it with pierce ---

// FromDOM reads a document tree from DOM.getDocument (depth -1, pierce):
// links, forms, resources, inline handlers, the HTML in noscript and
// comments, the doctype, and the URLs in text, in shadow roots (closed
// ones too), templates and same-process frames.
func FromDOM(root *cdp.Node, pageURL string) []Found {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var c collector
	c.node(root, base, false)
	return c.out
}

func attrs(n *cdp.Node) map[string]string {
	m := make(map[string]string, len(n.Attributes)/2)
	for i := 0; i+1 < len(n.Attributes); i += 2 {
		m[strings.ToLower(n.Attributes[i])] = n.Attributes[i+1]
	}
	return m
}

func (c *collector) node(n *cdp.Node, base *url.URL, svg bool) {
	if n == nil {
		return
	}
	switch n.NodeType {
	case 9: // a document: its own base
		ref := n.BaseURL
		if ref == "" {
			ref = n.DocumentURL
		}
		if b, err := url.Parse(ref); err == nil && b.Scheme != "" && b.Scheme != "about" {
			base = b
		}
	case 10: // <!DOCTYPE … "url">
		c.add(base, n.SystemID, Resource, false)
	case 8: // a comment: <!--[if IE]><script src=…><![endif]-->
		c.html(n.NodeValue, base)
		c.text(n.NodeValue, base)
	case 3:
		c.text(n.NodeValue, base)
	case 1:
		tag := strings.ToLower(n.LocalName)
		if tag == "" {
			tag = strings.ToLower(n.NodeName)
		}
		svg = svg || n.IsSVG || tag == "svg"
		a := attrs(n)
		switch tag {
		case "script", "style":
			// Scripts are in the store and read by jsapi; their text is
			// not the page's.
			c.element(tag, a, base, svg)
			return
		case "noscript":
			// With scripts on, its content is text: the HTML it hides.
			for _, ch := range n.Children {
				if ch.NodeType == 3 {
					c.html(ch.NodeValue, base)
				}
			}
		case "form":
			for _, f := range formURLs(n, base) {
				c.addURL(f)
			}
		}
		c.element(tag, a, base, svg)
	}
	for _, ch := range n.Children {
		c.node(ch, base, svg)
	}
	for _, sr := range n.ShadowRoots {
		c.node(sr, base, svg)
	}
	c.node(n.TemplateContent, base, svg)
	c.node(n.ContentDocument, base, false)
}

// --- HTML fragments: noscript, comments, srcdoc ---

// html reads a fragment of HTML the DOM keeps as text.
func (c *collector) html(s string, base *url.URL) {
	if !strings.Contains(s, "<") {
		return
	}
	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		return
	}
	var walk func(*html.Node, bool)
	walk = func(n *html.Node, svg bool) {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			svg = svg || tag == "svg"
			a := map[string]string{}
			for _, at := range n.Attr {
				name := strings.ToLower(at.Key)
				if at.Namespace != "" {
					name = at.Namespace + ":" + name
				}
				a[name] = at.Val
			}
			c.element(tag, a, base, svg)
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch, svg)
		}
	}
	walk(doc, false)
}

// FromHTML reads a fragment of HTML on its own (tests, srcdoc).
func FromHTML(s, pageURL string) []Found {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var c collector
	c.html(s, base)
	return c.out
}
