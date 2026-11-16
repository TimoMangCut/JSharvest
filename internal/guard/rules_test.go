package guard

import (
	"regexp"
	"testing"
)

func TestDestructive(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://h/logout":                    true,
		"https://h/auth/sign-out?next=/":      true,
		"https://h/api/session?action=logoff": true,
		"https://h/account/delete":            true,
		"https://h/api/users/12/delete":       true,
		"https://h/api/deleteUser":            true,
		"https://h/api/resetFilters":          true,
		"https://h/reset":                     true,
		"https://h/reset-password-help":       true, // skipped on purpose: errs towards blocking
		"https://h/oauth/revoke2":             true,
		"https://h/?do=unsubscribe":           true,
		"https://h/static/js/main.js":         false,
		"https://h/removed-items":             false,
		"https://h/presets":                   false,
		"https://h/deleted-posts":             false,
		"https://h/api/resettable":            false,
		"https://h/blogout.html":              false,
		"https://h/catalogue":                 false,
		"https://h/":                          false,
	} {
		if got := Destructive(raw); got != want {
			t.Errorf("Destructive(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	r := Rules{}
	cases := []struct {
		name string
		req  Request
		want Decision
	}{
		{"get", Request{Method: "GET", URL: "https://h/a"}, Decision{Pass, "read"}},
		{"get logout", Request{Method: "GET", URL: "https://h/logout"}, Decision{Fake, "destructive"}},
		{"post", Request{Method: "POST", URL: "https://h/api/login"}, Decision{Fake, "write"}},
		{"put", Request{Method: "put", URL: "https://h/api/x"}, Decision{Fake, "write"}},
		{"delete method", Request{Method: "DELETE", URL: "https://h/api/item/3"}, Decision{Fake, "write"}},
		{"options", Request{Method: "OPTIONS", URL: "https://h/api/x"}, Decision{Pass, "read"}},
		{"gql query", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"query Me { me { id } }"}`}, Decision{Pass, "read"}},
		{"gql anonymous", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"{ me { id } }"}`}, Decision{Pass, "read"}},
		{"gql mutation", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"mutation Up($i:ID!){ up(id:$i){id} }"}`}, Decision{Fake, "graphql-mutation"}},
		{"gql anonymous mutation", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"mutation{ up{id} }"}`}, Decision{Fake, "graphql-mutation"}},
		{"gql subscription", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"subscription S { s }"}`}, Decision{Fake, "graphql-mutation"}},
		{"gql batch with a write", Request{Method: "POST", URL: "https://h/graphql", Body: `[{"query":"query A{a}"},{"query":"mutation B{b}"}]`}, Decision{Fake, "graphql-mutation"}},
		{"gql named query among writes", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"query A{a} mutation B{b}","operationName":"A"}`}, Decision{Pass, "read"}},
		{"gql named write", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"query A{a} mutation B{b}","operationName":"B"}`}, Decision{Fake, "graphql-mutation"}},
		{"gql persisted POST", Request{Method: "POST", URL: "https://h/graphql", Body: `{"operationName":"X","extensions":{"persistedQuery":{"version":1,"sha256Hash":"ab"}}}`}, Decision{Fake, "graphql-unknown"}},
		{"gql persisted GET reads", Request{Method: "GET", URL: "https://h/graphql?operationName=X&extensions=%7B%22persistedQuery%22%3A%7B%7D%7D"}, Decision{Pass, "read"}},
		// From the review: a JSON body with a "query" field is not GraphQL by itself.
		{"search form JSON", Request{Method: "POST", URL: "https://h/api/notes", Body: `{"query":"shoes","text":"new note"}`}, Decision{Fake, "write"}},
		{"batch with a non-GraphQL element", Request{Method: "POST", URL: "https://h/graphql", Body: `[{"query":"{a}"},{"id":"x"}]`}, Decision{Fake, "graphql-unknown"}},
		{"mutation after a BOM", Request{Method: "POST", URL: "https://h/graphql", Body: "{\"query\":\"\ufeffmutation{x}\"}"}, Decision{Fake, "graphql-mutation"}},
		{"leading commas", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":", , mutation M { x }"}`}, Decision{Fake, "graphql-mutation"}},
		{"fragment first", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"fragment F on User { id } mutation M { x { ...F } }"}`}, Decision{Fake, "graphql-mutation"}},
		{"directives and variables", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"query Q($a: Int) @cached(ttl: 5) { a(x: $a) }"}`}, Decision{Pass, "read"}},
		{"search GET ?query= is not GraphQL", Request{Method: "GET", URL: "https://h/search?query=mutation+testing+tools"}, Decision{Pass, "read"}},
		{"gql GET query", Request{Method: "GET", URL: "https://h/graphql?query=%7Bme%7Bid%7D%7D"}, Decision{Pass, "read"}},
		{"gql GET mutation", Request{Method: "GET", URL: "https://h/graphql?query=mutation%7Bx%7D"}, Decision{Fake, "graphql-mutation"}},
		{"gql comment mentions mutation", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"# no mutation here\nquery Q { a }"}`}, Decision{Pass, "read"}},
		{"gql # inside a string hides nothing", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"query A { a(x: \"#\") } mutation B { b }"}`}, Decision{Fake, "graphql-mutation"}},
		{"gql block string", Request{Method: "POST", URL: "https://h/graphql", Body: `{"query":"query A { a(d: \"\"\"# x\"\"\") }"}`}, Decision{Pass, "read"}},
		{"application/graphql", Request{Method: "POST", URL: "https://h/graphql", ContentType: "application/graphql", Body: "mutation { x }"}, Decision{Fake, "graphql-mutation"}},
		// CF-02: the CDN's own paths pass, the challenge's telemetry first.
		{"cf challenge flow", Request{Method: "POST", URL: "https://h/cdn-cgi/challenge-platform/h/b/flow/ov1/713:179:_Iz/a563/N.lD-1.2.1.1-XN"}, Decision{Pass, "cdn-infra"}},
		{"cf challenge token spells delete", Request{Method: "POST", URL: "https://h/cdn-cgi/challenge-platform/h/b/fo/x-Delete-y/managed"}, Decision{Pass, "cdn-infra"}},
		{"cf rum", Request{Method: "POST", URL: "https://h/cdn-cgi/rum?"}, Decision{Pass, "cdn-infra"}},
		{"cf access logout is not infra", Request{Method: "GET", URL: "https://h/cdn-cgi/access/logout"}, Decision{Fake, "destructive"}},
		{"cf access write is not infra", Request{Method: "POST", URL: "https://h/cdn-cgi/access/x"}, Decision{Fake, "write"}},
		{"dot-dot out of cdn-cgi", Request{Method: "POST", URL: "https://h/cdn-cgi/%2e%2e/api/x"}, Decision{Fake, "write"}},
		{"cdn-cgi below the root is the site's", Request{Method: "POST", URL: "https://h/app/cdn-cgi/x"}, Decision{Fake, "write"}},
		// From the review: a path a server may read otherwise is never infra.
		{"escaped slash into cdn-cgi", Request{Method: "GET", URL: "https://h/logout%2f..%2fcdn-cgi/x"}, Decision{Fake, "destructive"}},
		{"tomcat dot-dot-semicolon", Request{Method: "POST", URL: "https://h/cdn-cgi/..;/api/delete"}, Decision{Fake, "destructive"}},
		{"iis backslash", Request{Method: "POST", URL: "https://h/cdn-cgi/x/..%5c..%5capi/delete"}, Decision{Fake, "destructive"}},
		{"access with a parameter", Request{Method: "GET", URL: "https://h/cdn-cgi/access;x/logout"}, Decision{Fake, "destructive"}},
		{"double slash", Request{Method: "GET", URL: "https://h/cdn-cgi//access/logout"}, Decision{Fake, "destructive"}},
	}
	for _, c := range cases {
		if got := r.Classify(c.req); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestClassifyOptions(t *testing.T) {
	post := Request{Method: "POST", URL: "https://h/api/x"}
	if got := (Rules{AllowWrite: true}).Classify(post); got.Action != Pass {
		t.Errorf("AllowWrite: %+v", got)
	}
	// Writes allowed, logout still not.
	if got := (Rules{AllowWrite: true}).Classify(Request{Method: "POST", URL: "https://h/logout"}); got.Action != Fake {
		t.Errorf("AllowWrite logout: %+v", got)
	}
	allow := Rules{Allow: regexp.MustCompile(`/api/search$`)}
	if got := allow.Classify(Request{Method: "POST", URL: "https://h/api/search"}); got.Action != Pass {
		t.Errorf("allowlist: %+v", got)
	}
	deny := Rules{Deny: regexp.MustCompile(`/api/pay`)}
	if got := deny.Classify(Request{Method: "GET", URL: "https://h/api/pay/now"}); got.Action != Fake {
		t.Errorf("denylist: %+v", got)
	}
}

func TestExploreRules(t *testing.T) {
	plain := Rules{}
	ex := Rules{Explore: true}
	exw := Rules{Explore: true, AllowWrite: true}
	cases := []struct {
		r    Rules
		req  Request
		want Decision
	}{
		// With writes allowed, explore still never deletes.
		{exw, Request{Method: "DELETE", URL: "https://app.test/api/items/42"}, Decision{Fake, "destructive"}},
		{Rules{AllowWrite: true}, Request{Method: "DELETE", URL: "https://app.test/api/items/42"}, Decision{Pass, "allow-write"}},
		{exw, Request{Method: "POST", URL: "https://app.test/graphql", ContentType: "application/json",
			Body: `{"query":"mutation { deleteUser(id: 1) { id } }"}`}, Decision{Fake, "destructive"}},
		{exw, Request{Method: "POST", URL: "https://app.test/graphql", ContentType: "application/json",
			Body: `{"query":"mutation { updateUser(id: 1) { id } }"}`}, Decision{Pass, "allow-write"}},
		// A script's GET that names an action.
		{ex, Request{Method: "GET", URL: "https://app.test/api/orders/7/approve", ResourceType: "Fetch"}, Decision{Fake, "explore-verb"}},
		{ex, Request{Method: "GET", URL: "https://app.test/api/x/toggle?on=true", ResourceType: "XHR"}, Decision{Fake, "explore-verb"}},
		{ex, Request{Method: "GET", URL: "https://app.test/api/markAllRead", ResourceType: "Fetch"}, Decision{Fake, "explore-verb"}},
		{plain, Request{Method: "GET", URL: "https://app.test/api/orders/7/approve", ResourceType: "Fetch"}, Decision{Pass, "read"}},
		// Not an action: in the query, in a longer word, a page, a script.
		{ex, Request{Method: "GET", URL: "https://app.test/api/items?filter=archived", ResourceType: "Fetch"}, Decision{Pass, "read"}},
		{ex, Request{Method: "GET", URL: "https://app.test/getting-started", ResourceType: "Fetch"}, Decision{Pass, "read"}},
		{ex, Request{Method: "GET", URL: "https://app.test/api/marketing", ResourceType: "Fetch"}, Decision{Pass, "read"}},
		{ex, Request{Method: "GET", URL: "https://app.test/orders/7/approve", ResourceType: "Document"}, Decision{Pass, "read"}},
		{ex, Request{Method: "GET", URL: "https://app.test/static/cancel.js", ResourceType: "Script"}, Decision{Pass, "read"}},
		// An operation parameter that names an action (Reviewer round 3,
		// the replay review): explore's GET of /rpc?action=purge reached
		// role-app's server.
		{plain, Request{Method: "GET", URL: "https://app.test/api/rpc?action=purge", ResourceType: "Fetch"}, Decision{Fake, "destructive"}},
		{ex, Request{Method: "GET", URL: "https://app.test/api/rpc?action=approve", ResourceType: "Fetch"}, Decision{Fake, "explore-verb"}},
		{ex, Request{Method: "GET", URL: "https://app.test/api/rpc?action=list", ResourceType: "Fetch"}, Decision{Pass, "read"}},
		{exw, Request{Method: "POST", URL: "https://app.test/api/ra/graphql", ContentType: "application/json",
			Body: `{"operationName":"PurgeUsers","query":"mutation PurgeUsers { purgeUsers }"}`}, Decision{Fake, "destructive"}},
		// A DELETE that a POST carries in an override.
		{Rules{AllowWrite: true}, Request{Method: "POST", URL: "https://app.test/api/items/42", Override: "DELETE"}, Decision{Fake, "destructive"}},
		{Rules{AllowWrite: true}, Request{Method: "POST", URL: "https://app.test/api/items/42", ContentType: "application/x-www-form-urlencoded",
			Body: "_method=DELETE&x=1"}, Decision{Fake, "destructive"}},
		{Rules{AllowWrite: true}, Request{Method: "GET", URL: "https://app.test/api/items/42?_method=delete"}, Decision{Fake, "destructive"}},
		{plain, Request{Method: "GET", URL: "https://app.test/api/items/42", Override: "PATCH"}, Decision{Fake, "write"}},
		// -guard-allow still wins.
		{Rules{Explore: true, Allow: regexp.MustCompile(`/approve$`)}, Request{Method: "GET", URL: "https://app.test/api/orders/7/approve", ResourceType: "Fetch"}, Decision{Pass, "allow"}},
	}
	for _, c := range cases {
		if got := c.r.Classify(c.req); got != c.want {
			t.Errorf("%+v %s %s: got %v, want %v", c.r.Explore, c.req.Method, c.req.URL, got, c.want)
		}
	}
}

func TestDenyBeatsAllow(t *testing.T) {
	r := Rules{Allow: regexp.MustCompile(`^https://h/`), Deny: regexp.MustCompile(`/api/danger`)}
	if d := r.Classify(Request{Method: "POST", URL: "https://h/api/danger"}); d.Action != Fake {
		t.Fatalf("denied and allowed: %+v", d)
	}
	if d := r.Classify(Request{Method: "POST", URL: "https://h/api/ok"}); d != (Decision{Pass, "allow"}) {
		t.Fatalf("allowed: %+v", d)
	}
}

func TestRefreshGrant(t *testing.T) {
	const form = "application/x-www-form-urlencoded"
	cases := []struct {
		name string
		req  Request
		pass bool
	}{
		{"form", Request{Method: "POST", URL: "https://h/oauth/token", ContentType: form, Body: "grant_type=refresh_token&refresh_token=abc&client_id=x"}, true},
		{"json", Request{Method: "POST", URL: "https://h/auth/token", ContentType: "application/json", Body: `{"grant_type":"refresh_token","refresh_token":"abc"}`}, true},
		{"json charset", Request{Method: "POST", URL: "https://h/auth/token", ContentType: "application/json; charset=utf-8", Body: `{"grant_type":"refresh_token"}`}, true},
		{"query", Request{Method: "POST", URL: "https://h/oauth/token?grant_type=refresh_token", ContentType: form, Body: "refresh_token=abc"}, true},
		{"query no body", Request{Method: "POST", URL: "https://h/oauth/token?grant_type=refresh_token"}, true},
		{"get stays a read", Request{Method: "GET", URL: "https://h/oauth/token?grant_type=refresh_token"}, true},
		{"revoke path", Request{Method: "POST", URL: "https://h/oauth/revoke?grant_type=refresh_token"}, false},
		{"revocation endpoint", Request{Method: "POST", URL: "https://h/oauth2/revocation", ContentType: form, Body: "grant_type=refresh_token&token=x"}, false},
		{"introspect", Request{Method: "POST", URL: "https://h/oauth2/introspect", ContentType: form, Body: "grant_type=refresh_token&token=x"}, false},
		{"path alone", Request{Method: "POST", URL: "https://h/api-tokens/refresh", ContentType: "application/json", Body: `{}`}, false},
		{"path alone empty", Request{Method: "POST", URL: "https://h/api/auth/refresh"}, false},
		{"password grant", Request{Method: "POST", URL: "https://h/oauth/token", ContentType: form, Body: "grant_type=password&username=a&password=b"}, false},
		{"auth code grant json", Request{Method: "POST", URL: "https://h/oauth/token", ContentType: "application/json", Body: `{"grant_type":"authorization_code"}`}, false},
		{"nested json", Request{Method: "POST", URL: "https://h/api/x", ContentType: "application/json", Body: `{"x":{"grant_type":"refresh_token"}}`}, false},
		{"mixed grants", Request{Method: "POST", URL: "https://h/oauth/token", ContentType: form, Body: "grant_type=refresh_token&grant_type=password"}, false},
		{"query vs body", Request{Method: "POST", URL: "https://h/oauth/token?grant_type=refresh_token", ContentType: form, Body: "grant_type=password"}, false},
		{"delete method", Request{Method: "DELETE", URL: "https://h/oauth/token", ContentType: form, Body: "grant_type=refresh_token"}, false},
		{"disguised delete", Request{Method: "POST", URL: "https://h/oauth/token?_method=DELETE&grant_type=refresh_token"}, false},
		{"override header", Request{Method: "POST", Override: "DELETE", URL: "https://h/oauth/token", ContentType: form, Body: "grant_type=refresh_token"}, false},
		{"multipart override", Request{Method: "POST", URL: "https://h/oauth/token", ContentType: "multipart/form-data; boundary=x", Body: "--x\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nPUT\r\n--x--"}, false},
		{"multipart grant", Request{Method: "POST", URL: "https://h/oauth/token", ContentType: "multipart/form-data; boundary=x", Body: "grant_type=refresh_token"}, false},
		{"destructive word", Request{Method: "POST", URL: "https://h/account/delete", ContentType: form, Body: "grant_type=refresh_token"}, false},
		{"put", Request{Method: "PUT", URL: "https://h/oauth/token", ContentType: form, Body: "grant_type=refresh_token"}, false},
	}
	for _, rules := range []Rules{{}, {Explore: true}} {
		for _, c := range cases {
			got := rules.Classify(c.req).Action == Pass
			if got != c.pass {
				t.Errorf("explore=%v %s: pass=%v, want %v", rules.Explore, c.name, got, c.pass)
			}
		}
	}
	if d := (Rules{}).Classify(cases[0].req); d.Reason != "refresh" {
		t.Errorf("reason %q", d.Reason)
	}
	// AllowWrite off or on, a deny rule still wins over the refresh exception.
	r := Rules{Deny: regexp.MustCompile(`/oauth/token`)}
	if r.Classify(cases[0].req).Action != Fake {
		t.Error("Deny must beat the refresh exception")
	}
}

func TestAnchoredAllow(t *testing.T) {
	in := func(h string) bool { return h == "app.x.com" || h == "x.com" || h == "localhost" }
	ok := []string{
		`^https://app\.x\.com/api/auth/refresh(\?|$)`,
		`^https?://app\.x\.com/api/auth/refresh`,
		`^http://app\.x\.com/`,
		`^https://app\.x\.com:8443/api/refresh$`,
		`^https://app\.x\.com(:\d+)?/api/refresh$`,
		`^https://x\.com/(a|b)$`,
		`^http://localhost/refresh`,
	}
	bad := []string{
		``,
		`/api/auth/refresh`,
		`https://app\.x\.com/api/refresh`,
		`^/api/auth/refresh`,
		`^https://.*/refresh`,
		`^https://[^/]+/refresh`,
		`^https://app.x.com/refresh`, // unescaped dot
		`^https://app\.x\.com`,       // no path slash
		`^https://app\.x\.com\.evil\.io/refresh`,
		`^https://evil\.io/refresh`,
		`^https://app\.x\.com/refresh|.*`,
		`^https://app\.x\.com/a|^https://app\.x\.com/b`,
		`(?i)^https://app\.x\.com/refresh`,
		`^https://app\.x\.com/(`,
		`^ftp://app\.x\.com/a`,
	}
	for _, re := range ok {
		if err := AnchoredAllow(re, in); err != nil {
			t.Errorf("%q refused: %v", re, err)
		}
	}
	for _, re := range bad {
		if err := AnchoredAllow(re, in); err == nil {
			t.Errorf("%q accepted", re)
		}
	}
	if AnchoredAllow(ok[0], nil) == nil {
		t.Error("no scope must refuse")
	}
}

func TestWithAllow(t *testing.T) {
	r, err := (Rules{Allow: regexp.MustCompile(`^https://a/x`)}).WithAllow(`^https://b/y$`, `^https://c/z`)
	if err != nil {
		t.Fatal(err)
	}
	for u, want := range map[string]bool{"https://a/x1": true, "https://b/y": true, "https://c/z9": true, "https://b/y2": false, "https://d/": false} {
		if got := r.Allow.MatchString(u); got != want {
			t.Errorf("%s: %v want %v", u, got, want)
		}
	}
	if _, err := (Rules{}).WithAllow(`(`); err == nil {
		t.Error("a bad regexp must fail")
	}
	if r, _ := (Rules{}).WithAllow(); r.Allow != nil {
		t.Error("nothing to add")
	}
}
