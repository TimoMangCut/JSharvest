package frontier

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func mustURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

func el(tag string, attrs []string, children ...*cdp.Node) *cdp.Node {
	return &cdp.Node{NodeType: 1, NodeName: strings.ToUpper(tag), LocalName: tag, Attributes: attrs, Children: children}
}

func txt(s string) *cdp.Node { return &cdp.Node{NodeType: 3, NodeValue: s} }

func doc(u string, children ...*cdp.Node) *cdp.Node {
	return &cdp.Node{NodeType: 9, DocumentURL: u, BaseURL: u, Children: children}
}

// keys lists found URLs as "how visit url".
func keys(fs []Found) []string {
	var out []string
	for _, f := range fs {
		v := "name"
		if f.Visit {
			v = "visit"
		}
		m := ""
		if f.Method != "" && f.Method != "GET" {
			m = f.Method + " "
		}
		out = append(out, f.How+" "+v+" "+m+f.URL)
	}
	slices.Sort(out)
	return out
}

func has(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in\n%s", w, strings.Join(got, "\n"))
		}
	}
}

func TestFromDOM(t *testing.T) {
	closed := &cdp.Node{NodeType: 11, ShadowRootType: cdp.ShadowRootTypeClosed, Children: []*cdp.Node{el("a", []string{"href", "/closed"})}}
	host := el("div", nil)
	host.ShadowRoots = []*cdp.Node{closed}
	tpl := el("template", nil)
	tpl.TemplateContent = &cdp.Node{NodeType: 11, Children: []*cdp.Node{el("a", []string{"href", "/in-template"})}}
	frame := el("iframe", []string{"srcdoc", "<a href=x>"})
	frame.ContentDocument = doc("about:srcdoc", el("a", []string{"href", "/in-srcdoc"}))
	svg := el("svg", nil, el("a", []string{"xlink:href", "/svg-link"}), el("image", []string{"xlink:href", "/svg.png"}))
	svg.IsSVG = true
	// CDP gives a document's base as <base href> sets it.
	root := doc("http://app.test/dir/page.html",
		&cdp.Node{NodeType: 10, SystemID: "http://app.test/doctype.dtd"},
		el("html", nil,
			el("head", []string{"profile", "/profile"},
				el("base", []string{"href", "/base/"}),
				el("meta", []string{"http-equiv", "refresh", "content", "5; url=/refreshed"}),
				el("meta", []string{"http-equiv", "Content-Security-Policy", "content", "script-src 'self'; report-uri /csp.found"}),
				el("link", []string{"rel", "alternate", "href", "/alt"}),
				el("link", []string{"rel", "stylesheet", "href", "/s.css"}),
				&cdp.Node{NodeType: 8, NodeValue: `[if IE]><script src="/ie.js"></script><![endif]`}),
			el("body", []string{"background", "/bg.png"},
				el("a", []string{"href", "rel", "ping", "/ping1 /ping2"}),
				el("a", []string{"href", "javascript:location.href='/js-href'"}),
				el("div", []string{"onclick", "window.location='/onclick'"}),
				el("map", nil, el("area", []string{"href", "/area"})),
				el("noscript", nil, txt(`<a href="/noscript">x</a>`)),
				el("blockquote", []string{"cite", "/cite"}),
				el("img", []string{"src", "/i.png", "srcset", "/i1.png 1x, /i2.png 2x", "lowsrc", "/low.png"}),
				el("applet", []string{"archive", "/a.jar,/b.jar"}),
				el("p", nil, txt("see ../text/x.found or https://other.test/y")),
				host, tpl, frame, svg)))
	root.BaseURL = "http://app.test/base/"
	got := keys(FromDOM(root, "http://app.test/dir/page.html"))
	has(t, got,
		"resource name http://app.test/doctype.dtd",
		"resource name http://app.test/base/",
		"redirect visit http://app.test/refreshed",
		"text name http://app.test/csp.found",
		"link visit http://app.test/alt",
		"resource name http://app.test/s.css",
		"resource name http://app.test/ie.js",
		"resource name http://app.test/bg.png",
		"link visit http://app.test/base/rel",
		"resource name http://app.test/ping1",
		"link visit http://app.test/js-href",
		"link visit http://app.test/onclick",
		"link visit http://app.test/area",
		"link visit http://app.test/noscript",
		"resource name http://app.test/cite",
		"resource name http://app.test/i2.png",
		"resource name http://app.test/low.png",
		"resource name http://app.test/b.jar",
		"text name http://app.test/text/x.found",
		"text name https://other.test/y",
		"link visit http://app.test/closed",
		"link visit http://app.test/in-template",
		"link visit http://app.test/in-srcdoc",
		"link visit http://app.test/svg-link",
		"resource name http://app.test/svg.png",
		"resource name http://app.test/profile",
	)
}

func TestForms(t *testing.T) {
	form := el("form", []string{"action", "/search?old=1"},
		el("input", []string{"type", "text", "name", "q"}),
		el("input", []string{"type", "email", "name", "mail"}),
		el("input", []string{"type", "hidden", "name", "csrf", "value", "abc"}),
		el("input", []string{"type", "radio", "name", "r", "value", "a"}),
		el("input", []string{"type", "radio", "name", "r", "value", "b", "checked", ""}),
		el("input", []string{"type", "checkbox", "name", "c", "value", "x"}),
		el("input", []string{"type", "checkbox", "name", "c", "value", "y"}),
		el("input", []string{"type", "text", "name", "off", "disabled", ""}),
		el("select", []string{"name", "s"}, el("option", []string{"value", "1"}), el("option", []string{"value", "2", "selected", ""})),
		el("textarea", []string{"name", "t"}, txt("hi")),
		el("button", []string{"name", "go", "value", "1"}),
		el("button", []string{"formaction", "/elsewhere"}),
		el("button", []string{"formaction", "/write", "formmethod", "post"}),
		el("input", []string{"type", "image", "name", "img", "src", "/b.png"}),
	)
	got := keys(formURLs(form, mustURL("http://app.test/p")))
	want := []string{
		"form name POST http://app.test/write",
		"form visit http://app.test/elsewhere?c=x&c=y&csrf=abc&mail=test%40example.com&q=test&r=b&s=2&t=hi",
		"form visit http://app.test/search?c=x&c=y&csrf=abc&go=1&mail=test%40example.com&q=test&r=b&s=2&t=hi",
		"form visit http://app.test/search?c=x&c=y&csrf=abc&img.x=1&img.y=1&mail=test%40example.com&q=test&r=b&s=2&t=hi",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	post := el("form", []string{"method", "post", "action", "/login"}, el("input", []string{"name", "u"}))
	if got := keys(formURLs(post, mustURL("http://app.test/"))); !slices.Equal(got, []string{"form name POST http://app.test/login"}) {
		t.Fatal(got)
	}
}

func TestHeadersRobotsSitemap(t *testing.T) {
	got := keys(FromHeaders(map[string]string{"Location": "/moved", "Refresh": "0;url=/r", "Link": `</l1>; rel=preload, </l2>; rel=next`,
		"Content-Location": "/cl"}, "http://app.test/x"))
	has(t, got, "redirect visit http://app.test/moved", "redirect visit http://app.test/r", "header visit http://app.test/l1",
		"header visit http://app.test/l2", "header visit http://app.test/cl")

	pages, maps := FromRobots("User-agent: *\nDisallow: /private/ # no\nAllow: /pub*.html\nDisallow: /\nSitemap: /sm.xml\n", "http://app.test/robots.txt")
	if got := keys(pages); !slices.Equal(got, []string{"robots visit http://app.test/private/", "robots visit http://app.test/pub"}) || !slices.Equal(maps, []string{"http://app.test/sm.xml"}) {
		t.Fatal(got, maps)
	}
	sm := keys(FromSitemap(`<urlset><url><loc> http://app.test/a?x=1&amp;y=2 </loc></url><url><loc>/b</loc></url></urlset>`, "http://app.test/sm.xml"))
	if !slices.Equal(sm, []string{"sitemap visit http://app.test/a?x=1&y=2", "sitemap visit http://app.test/b"}) {
		t.Fatal(sm)
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"HTTP://App.Test:80":                  "http://app.test/",
		"https://app.test:443/a?b=2&a=1#frag": "https://app.test/a?a=1&b=2",
		"http://app.test/#/route":             "http://app.test/#/route",
		"http://u:p@app.test/x":               "http://app.test/x",
	} {
		if got, _ := Normalize(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	if _, ok := Normalize("ftp://app.test/"); ok {
		t.Error("ftp normalised")
	}
}

func TestQueue(t *testing.T) {
	q := NewQueue(Options{InScope: func(h string) bool { return h == "app.test" }, MaxDepth: 2, MaxPages: 5,
		Destructive: func(u string) bool { return strings.Contains(u, "logout") }})
	add := func(u, how string, visit bool, method string, depth int) string {
		return q.Add(Found{URL: u, How: how, Visit: visit, Method: method}, depth, "http://app.test/")
	}
	cases := []struct {
		u, how, method string
		visit          bool
		depth          int
		want           string
	}{
		{"http://app.test/", Seed, "", true, 0, ""},
		{"http://app.test/#frag", Link, "", true, 1, seenAlready},
		{"http://other.test/", Link, "", true, 1, OutOfScope},
		{"http://app.test/login", Form, "POST", false, 1, NotGET},
		{"http://app.test/i.png", Resource, "", false, 1, OnlyNamed},
		{"http://app.test/doc.pdf", Link, "", true, 1, Asset},
		{"http://app.test/api/users", JS, "", true, 1, API},
		{"http://app.test/scooter/v1.0/admin/search", JS, "", true, 1, API},
		{"http://app.test/v2/users", Route, "", true, 1, API},
		{"http://app.test/scooters/{scooter_id}/status", JS, "", true, 1, Template},
		{"http://app.test/users/%7Bid%7D", Route, "", true, 1, Template},
		{"http://app.test/api/redirect?url=/x", Link, "", true, 1, ""},
		{"http://app.test/logout", Link, "", true, 1, Destructive},
		{"http://app.test/deep", Link, "", true, 3, TooDeep},
		{"http://app.test/js-page", JS, "", true, 1, ""},
		{"http://app.test/b", Link, "", true, 1, ""},
		{"http://app.test/c", Link, "", true, 2, ""},
		{"http://app.test/d", Link, "", true, 2, Limit},
	}
	for _, c := range cases {
		if got := add(c.u, c.how, c.visit, c.method, c.depth); got != c.want {
			t.Errorf("%s: %q, want %q", c.u, got, c.want)
		}
	}
	var order []string
	for {
		it, ok := q.Next()
		if !ok {
			break
		}
		order = append(order, it.URL)
	}
	want := []string{"http://app.test/", "http://app.test/api/redirect?url=/x", "http://app.test/b", "http://app.test/js-page", "http://app.test/c"}
	if !slices.Equal(order, want) {
		t.Fatalf("order %v", order)
	}
	if len(q.Listed) != 12 {
		t.Fatalf("listed %d: %+v", len(q.Listed), q.Listed)
	}
}

// A bundle of libraries names no page of the app (SheetJS's
// "/!DocumentSummaryInformation", SockJS's "/xhr_send").
func TestVendor(t *testing.T) {
	for u, want := range map[string]bool{
		"https://a.test/version/1/js/vendors.js": true, "/js/chunk-vendors.3f2a1b.js": true, "/static/js/vendors~main.chunk.js": true,
		"/_next/static/chunks/framework-2c79e2a64abdb08b.js": true, "/polyfills.es2015.js?v=1": true, "/js/app.js": false, "/js/vendor-admin-page.js": false,
		"/js/vendors-node_modules_lodash_js.js": true, "/_next/static/chunks/polyfills-c67a75d1b6f99dc8.js": true,
		"/js/advendors.js": false, "/js/main.vendors.js": false,
	} {
		if Vendor(u) != want {
			t.Errorf("Vendor(%s) = %v", u, !want)
		}
	}
	r := jsapi.Result{Routes: []string{"/!SummaryInformation"}, Paths: []string{"/xhr_send"},
		Endpoints: []jsapi.Endpoint{{Method: "GET", URL: "/help", Kind: "navigation"}}}
	base, _ := url.Parse("https://a.test/")
	if got := FromScript(r, base, true); len(got) != 1 || got[0].URL != "https://a.test/help" {
		t.Fatalf("vendor: %+v", got)
	}
	if got := FromScript(r, base, false); len(got) != 3 {
		t.Fatalf("app: %+v", got)
	}
}

// A real TanStack Router app (round 18): its route ids (/_authenticated/home,
// a pathless layout's) and patterns ($slug, $ splat) are no pages; the
// pages they stand for are. A library's examples (:id, **, (group), the
// node_modules id of a module) neither.
func TestRouterPatternsAreNoPages(t *testing.T) {
	r := jsapi.Result{
		Routes: []string{"/_authenticated", "/_authenticated/home", "/_authenticated/apps/$slug/$", "/apps/$slug/$", "/home",
			"/_account", "/_account/settings/account/notifications", "/settings/account/notifications", "/help/$"},
		Paths: []string{"/posts/:postId/edit", "/settings/**", "/_next/static/*", "/(ss)/g", "/cms/...",
			"/vi/ROOT/node_modules/.pnpm/next@16/node_modules/next/dist/compiled/process", "/_admin", "/_next/data/x",
			// Round 19: Next.js's and Turbopack's own names, a parser's tests, a CSP's list.
			"/_next/image", "/_next/", "/_next/static/immutable", "/_head", "/_index", "/_not-found", "/_tree", "/ROOT/",
			"/a/b", "/a/i", "https://*.example.services,https://cdn.example.biz"},
	}
	base, _ := url.Parse("https://h.test/")
	q := NewQueue(Options{InScope: func(string) bool { return true }, MaxDepth: 5})
	queued := map[string]bool{}
	for _, f := range FromScript(r, base, false) {
		if q.Add(f, 1, "") == "" {
			queued[strings.TrimPrefix(f.URL, "https://h.test")] = true
		}
	}
	// /_admin is no layout's that the script proves: kept. Where the
	// router's root id is named, a lone /_x is TanStack's layout.
	want := []string{"/home", "/settings/account/notifications", "/_admin"}
	if !templatePath("/__root__") || !routeIDs(jsapi.Result{Paths: []string{"/__root__", "/_admin"}})["/_admin"] {
		t.Fatal("__root__ is TanStack's root id")
	}
	if len(queued) != len(want) {
		t.Fatalf("queued %v, want %v", queued, want)
	}
	for _, w := range want {
		if !queued[w] {
			t.Fatalf("queued %v, want %v", queued, want)
		}
	}
}

func TestSpecPathsAndAppAPIOrigins(t *testing.T) {
	for _, p := range []string{"/v2/api-docs", "/v3/api-docs", "/swagger-resources"} {
		if !slices.Contains(SpecPaths, p) {
			t.Errorf("SpecPaths missing %q", p)
		}
		if !SpecFile(p) || !SpecFile("/api-gateway"+p) {
			t.Errorf("SpecFile(%q) = false, want true", p)
		}
	}
	if SpecFile("/swagger") || SpecFile("/swagger-ui") {
		t.Error("Swagger HTML UI path mistakenly matched SpecFile")
	}

	r := jsapi.Result{
		Bases: []string{
			"https://api.example.test/v1",
			"https://gw.partner-backend.test/api-gateway",
			"https://cdn.example.test/js",
			"https://static.partner-backend.test/assets",
			"https://fonts.googleapis.com/css2",
		},
		Endpoints: []jsapi.Endpoint{
			{Method: "POST", URL: "https://www.google-analytics.com/g/collect", Kind: "fetch"},
			{Method: "POST", URL: "https://o1.ingest.sentry.io/api/1/envelope/", Kind: "fetch"},
			{Method: "GET", URL: "https://www.googletagmanager.com/gtm.js", Kind: "fetch"},
			{Method: "GET", URL: "https://orders.partner-backend.test/v1/list", Kind: "fetch"},
		},
	}
	inScope := func(h string) bool { return h == "example.test" || strings.HasSuffix(h, ".example.test") }
	got := APIOrigins(r, inScope)
	want := []string{
		"https://api.example.test",
		"https://gw.partner-backend.test",
		"https://orders.partner-backend.test",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("APIOrigins:\n got  %v\n want %v", got, want)
	}
}
