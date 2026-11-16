package frontier

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"golang.org/x/net/html"
)

// control is one form control, as far as building a submission goes.
type control struct {
	tag, typ, name, value  string
	checked                bool
	options                []string // a select's values, the selected one first
	formaction, formmethod string
}

// Samples are the values a crawler types into empty fields, by type.
var Samples = map[string]string{
	"email": "test@example.com", "number": "1", "range": "1", "url": "https://example.com/", "tel": "5555555555",
	"date": "2026-01-01", "datetime-local": "2026-01-01T00:00", "month": "2026-01", "week": "2026-W01", "time": "00:00",
	"color": "#000000", "search": "test", "text": "test", "password": "test", "": "test",
}

// formURLs builds the submissions of a form: one per submit button (a
// formaction or formmethod of its own, or its name and value), each with
// every field filled. GET ones are pages to visit; the others are named.
func formURLs(form *cdp.Node, base *url.URL) []Found {
	fa := attrs(form)
	method := strings.ToUpper(strings.TrimSpace(fa["method"]))
	if method == "" || method == "DIALOG" {
		method = "GET"
	}
	var controls []control
	var walk func(*cdp.Node)
	walk = func(n *cdp.Node) {
		if n == nil {
			return
		}
		if n.NodeType == 1 {
			a := attrs(n)
			tag := strings.ToLower(n.LocalName)
			if _, off := a["disabled"]; !off {
				switch tag {
				case "input":
					controls = append(controls, control{tag: tag, typ: strings.ToLower(a["type"]), name: a["name"], value: a["value"],
						checked: hasAttr(a, "checked"), formaction: a["formaction"], formmethod: a["formmethod"]})
				case "button":
					typ := strings.ToLower(a["type"])
					if typ == "" {
						typ = "submit"
					}
					controls = append(controls, control{tag: tag, typ: typ, name: a["name"], value: a["value"],
						formaction: a["formaction"], formmethod: a["formmethod"]})
				case "textarea":
					controls = append(controls, control{tag: tag, name: a["name"], value: text(n)})
				case "select":
					s := control{tag: tag, name: a["name"]}
					var first, selected string
					var options func(*cdp.Node)
					options = func(o *cdp.Node) {
						for _, ch := range o.Children {
							if ch.NodeType == 1 && strings.EqualFold(ch.LocalName, "option") {
								oa := attrs(ch)
								v, ok := oa["value"]
								if !ok {
									v = strings.TrimSpace(text(ch))
								}
								if first == "" {
									first = v
								}
								if hasAttr(oa, "selected") && selected == "" {
									selected = v
								}
							}
							options(ch)
						}
					}
					options(n)
					if selected == "" {
						selected = first
					}
					s.options = []string{selected}
					controls = append(controls, s)
					return
				}
			}
		}
		for _, ch := range n.Children {
			walk(ch)
		}
	}
	walk(form)

	fields := url.Values{}
	radios := map[string]bool{}
	anyChecked := map[string]bool{}
	for _, c := range controls {
		if c.typ == "checkbox" && c.checked {
			anyChecked[c.name] = true
		}
	}
	var submits []control
	for _, c := range controls {
		switch {
		case c.tag == "select":
			if c.name != "" && len(c.options) > 0 {
				fields.Add(c.name, c.options[0])
			}
		case c.typ == "submit" || c.typ == "image":
			submits = append(submits, c)
		case c.typ == "button" || c.typ == "reset" || c.typ == "file" || c.name == "":
		case c.typ == "radio":
			// The checked one, or the first of the group.
			if !radios[c.name] && (c.checked || !anyRadioChecked(controls, c.name)) {
				radios[c.name] = true
				fields.Add(c.name, valueOr(c.value, "on"))
			}
		case c.typ == "checkbox":
			// The checked ones, or all of a group none is checked in.
			if c.checked || !anyChecked[c.name] {
				fields.Add(c.name, valueOr(c.value, "on"))
			}
		default:
			fields.Add(c.name, valueOr(c.value, Samples[c.typ]))
		}
	}
	if len(submits) == 0 {
		submits = []control{{}}
	}
	var out []Found
	seen := map[string]bool{}
	for _, s := range submits {
		action, m := fa["action"], method
		if s.formaction != "" {
			action = s.formaction
		}
		if s.formmethod != "" {
			m = strings.ToUpper(s.formmethod)
		}
		target, err := base.Parse(strings.TrimSpace(action))
		if err != nil || (target.Scheme != "http" && target.Scheme != "https") {
			continue
		}
		v := url.Values{}
		for k, vs := range fields {
			v[k] = append([]string(nil), vs...)
		}
		switch {
		case s.typ == "image" && s.name != "":
			v.Set(s.name+".x", "1")
			v.Set(s.name+".y", "1")
		case s.typ == "image":
			v.Set("x", "1")
			v.Set("y", "1")
		case s.name != "":
			v.Set(s.name, s.value)
		}
		target.Fragment = ""
		f := Found{How: Form, Method: m}
		if m == "GET" {
			// A GET form replaces the action's query with its fields.
			target.RawQuery = v.Encode()
			f.Visit = true
		}
		f.URL = target.String()
		if !seen[f.URL+f.Method] {
			seen[f.URL+f.Method] = true
			out = append(out, f)
		}
	}
	return out
}

func anyRadioChecked(cs []control, name string) bool {
	for _, c := range cs {
		if c.typ == "radio" && c.name == name && c.checked {
			return true
		}
	}
	return false
}

func hasAttr(a map[string]string, name string) bool {
	_, ok := a[name]
	return ok
}

func valueOr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func text(n *cdp.Node) string {
	var b strings.Builder
	var walk func(*cdp.Node)
	walk = func(n *cdp.Node) {
		if n.NodeType == 3 {
			b.WriteString(n.NodeValue)
		}
		for _, ch := range n.Children {
			walk(ch)
		}
	}
	walk(n)
	return b.String()
}

// --- headers ---

var linkHeaderRe = regexp.MustCompile(`<([^>]+)>`)

// FromHeaders reads the URLs of a document's response headers: a
// redirect's Location and a Refresh are where the browser goes; Link and
// Content-Location only name URLs.
func FromHeaders(h map[string]string, pageURL string) []Found {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var c collector
	for k, v := range h {
		switch strings.ToLower(k) {
		case "location":
			c.add(base, v, Redirect, true)
		case "refresh":
			if m := refreshRe.FindStringSubmatch(v); m != nil {
				c.add(base, m[1], Redirect, true)
			}
		case "content-location":
			c.add(base, v, Header, true)
		case "link":
			for _, m := range linkHeaderRe.FindAllStringSubmatch(v, -1) {
				c.add(base, m[1], Header, true)
			}
		}
	}
	return c.out
}

// --- robots.txt and sitemaps ---

// FromRobots reads robots.txt: the paths it allows or disallows (a
// security crawl looks at both), and the sitemaps it names.
func FromRobots(body, robotsURL string) (pages []Found, sitemaps []string) {
	base, err := url.Parse(robotsURL)
	if err != nil {
		return nil, nil
	}
	var c collector
	for _, line := range strings.Split(body, "\n") {
		line, _, _ = strings.Cut(line, "#")
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "allow", "disallow":
			// A pattern is no URL: keep what comes before its first wildcard.
			if i := strings.IndexAny(v, "*$"); i >= 0 {
				v = v[:i]
			}
			if strings.HasPrefix(v, "/") && v != "/" {
				c.add(base, v, Robots, true)
			}
		case "sitemap":
			if u := resolve(base, v); u != "" {
				sitemaps = append(sitemaps, u)
			}
		}
	}
	return c.out, sitemaps
}

var locRe = regexp.MustCompile(`(?is)<loc>\s*(.*?)\s*</loc>`)

// FromSitemap reads the <loc> URLs of a sitemap (or a sitemap index).
func FromSitemap(body, sitemapURL string) []Found {
	base, err := url.Parse(sitemapURL)
	if err != nil {
		return nil
	}
	var c collector
	for _, m := range locRe.FindAllStringSubmatch(body, 50000) {
		c.add(base, html.UnescapeString(m[1]), Sitemap, true)
	}
	return c.out
}
