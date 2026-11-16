package roles

import (
	"net/url"
	"slices"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
)

func TestClassify(t *testing.T) {
	A, U, C, D, R, H, X := Absent, Used, Code, Denied, Redirected, Held, Unknown
	cases := []struct {
		name   string
		states []State
		native int
		class  string
		lowest int
		also   []string
	}{
		{"used by all", []State{U, U, U}, -1, Same, 0, nil},
		{"code below", []State{C, C, U}, -1, ClientGated, 2, nil},
		{"held is used", []State{C, C, H}, -1, ClientGated, 2, nil},
		{"refused below", []State{D, D, U}, -1, DeniedBelow, 2, nil},
		{"sent away below", []State{R, U, U}, -1, DeniedBelow, 1, nil},
		// The role right below decides: the server refused user, though
		// anon has the code (Reviewer S3).
		{"code, then refused", []State{C, D, U}, -1, DeniedBelow, 2, nil},
		{"absent below", []State{A, A, U}, -1, HigherOnly, 2, nil},
		{"not looked below", []State{A, X, U}, -1, NotCovered, 2, nil},
		// An admin's endpoint a user uses with success (Reviewer M6).
		{"lower ok", []State{D, U, U}, 2, LowerOK, 1, []string{DeniedBelow}},
		{"native and lowest agree", []State{D, D, U}, 2, DeniedBelow, 2, nil},
		{"inconsistent", []State{U, D, U}, -1, Inconsistent, 0, nil},
		{"code only", []State{C, C, C}, -1, Unreached, -1, nil},
		{"nothing", []State{A, D, A}, -1, "", -1, nil},
	}
	for _, c := range cases {
		class, lowest, also := classify(c.states, c.native)
		if class != c.class || lowest != c.lowest || !slices.Equal(also, c.also) {
			t.Errorf("%s: %s %d %v, want %s %d %v", c.name, class, lowest, also, c.class, c.lowest, c.also)
		}
	}
}

func TestCallState(t *testing.T) {
	for _, c := range []struct {
		o    obs
		want State
	}{
		{obs{statuses: []int64{200, 403}}, Used},
		{obs{statuses: []int64{401}}, Denied},
		{obs{statuses: []int64{302}}, Redirected},
		{obs{held: 2}, Held},
		{obs{statuses: []int64{404}}, Denied},
		{obs{refs: []Ref{{"r", 1}}}, Unknown}, // failed, no answer: says nothing
	} {
		if got := callState(c.o); got != c.want {
			t.Errorf("%+v: %s, want %s", c.o, got, c.want)
		}
	}
	if !mixed([]int64{200, 403}) || mixed([]int64{200, 201}) {
		t.Error("mixed")
	}
}

func TestPages(t *testing.T) {
	for raw, want := range map[string]string{
		"http://app.test/items/41/":         "/items/#",
		"http://app.test/":                  "/",
		"http://app.test/#/admin/users":     "/#/admin/users",
		"http://app.test/?page=admin&x=1":   "/?page=admin",
		"http://app.test/index.php?a=1#top": "/index.php",
	} {
		if got := pageKey(raw); got != want {
			t.Errorf("%s: %s, want %s", raw, got, want)
		}
	}
	d := &roleData{login: "/account/login/"}
	for _, c := range []struct {
		p    pageLine
		want State
	}{
		{pageLine{URL: "http://app.test/admin", Visited: true, Status: 200, FinalURL: "http://app.test/admin"}, Used},
		{pageLine{URL: "http://app.test/admin", Visited: true, Status: 403}, Denied},
		{pageLine{URL: "http://app.test/admin", Visited: true, Status: 200, FinalURL: "http://app.test/account/login?next=/admin"}, Denied},
		{pageLine{URL: "http://app.test/admin", Visited: true, Status: 200, FinalURL: "http://app.test/signin"}, Denied},
		// A SPA answers 200, and its own guard sends the page home.
		{pageLine{URL: "http://app.test/admin", Visited: true, Status: 200, FinalURL: "http://app.test/"}, Redirected},
		// Not visited for want of budget: no sign (Reviewer M7).
		{pageLine{URL: "http://app.test/admin", Reason: "limit"}, Unknown},
		{pageLine{URL: "http://app.test/authors", Visited: true, Status: 200, FinalURL: "http://app.test/authors"}, Used},
	} {
		if got, _ := d.pageState(c.p); got != c.want {
			t.Errorf("%+v: %s, want %s", c.p, got, c.want)
		}
	}
	if _, ok := d.pageState(pageLine{URL: "http://app.test/api/x", Reason: "api"}); ok {
		t.Error("an API URL is no page")
	}
	if d.isLogin("http://app.test/authors") || d.isLogin("http://app.test/oauth/callback") {
		t.Error("not login pages")
	}
}

func TestParamNames(t *testing.T) {
	u, _ := url.Parse("http://app.test/api/rpc?action=purge&id=7")
	names, op := paramNames("GET", u, "", "")
	if op != "action=purge" || !slices.Equal(names, []string{"query:action", "query:id"}) {
		t.Fatalf("%v %q", names, op)
	}
	g, _ := url.Parse("http://app.test/graphql")
	names, op = paramNames("POST", g, "application/json", `{"query":"mutation DeleteUser($id: ID!) { deleteUser(id: $id) }","variables":{"id":7}}`)
	if op != "op=DeleteUser" || !slices.Contains(names, "json:variables.id") {
		t.Fatalf("%v %q", names, op)
	}
	f, _ := url.Parse("http://app.test/api/search")
	names, _ = paramNames("POST", f, "application/x-www-form-urlencoded", "q=x&include_deleted=1")
	if !slices.Equal(names, []string{"form:include_deleted", "form:q"}) {
		t.Fatalf("%v", names)
	}
}

func TestFeatureKey(t *testing.T) {
	a := flow.Flow{Kind: "click", Page: "http://app.test/", Label: `button "My orders, alice"`, Element: &flow.Element{Tag: "button", ID: "orders", Label: "My orders, alice"}}
	b := a
	b.Label, b.Element = `button "My orders, admin"`, &flow.Element{Tag: "button", ID: "orders", Label: "My orders, admin"}
	if featureKey(a) != featureKey(b) {
		t.Fatalf("%q != %q", featureKey(a), featureKey(b))
	}
	c := flow.Flow{Kind: "click", Page: "http://app.test/inbox/3", Element: &flow.Element{Tag: "a", Role: "link", Label: "Mail bob@x.test (3)"}}
	d := c
	d.Page, d.Element = "http://app.test/inbox/9", &flow.Element{Tag: "a", Role: "link", Label: "Mail eve@y.test (12)"}
	if featureKey(c) != featureKey(d) {
		t.Fatalf("%q != %q", featureKey(c), featureKey(d))
	}
}

func TestEndpointPairing(t *testing.T) {
	if !generic(endpoints.Endpoint{Path: "/api/{}"}) || generic(endpoints.Endpoint{Path: "/api/ra/me"}) ||
		generic(endpoints.Endpoint{Path: "/me", Bases: []string{"/api"}}) {
		t.Fatal("generic")
	}
	re := templateRe("/api/users/{id}/posts/{}")
	if !re.MatchString("/api/users/7/posts/abc") || re.MatchString("/api/users/7/posts") {
		t.Fatal("templateRe")
	}
	e := endpoints.Endpoint{Operations: []string{"mutation PurgeUsers"}, Static: []endpoints.Source{{Snippet: "fetch('/api/rpc?action=purge')"}}}
	if !namesOp(e, "op=PurgeUsers") || namesOp(e, "op=News") || !namesOp(e, "action=purge") || namesOp(e, "action=list") {
		t.Fatal("namesOp")
	}
	if k := staticKey(endpoints.Endpoint{Path: "/users/{id}", Bases: []string{"/api"}}, "app.test"); k != "GET app.test/api/users/{}" {
		t.Fatal(k)
	}

	// P1-3: when Endpoint.Bases mixes an absolute cross-origin base and a
	// relative base, traffic to BOTH the cross-origin host and the target's
	// own host must pair, while unrelated hosts are still rejected.
	var cmp comparer
	order := []string{"k_target", "k_api", "k_other"}
	tmpl := map[string]string{
		"k_target": "GET app.test/v1/users/7",
		"k_api":    "GET api.app.test/v1/users/7",
		"k_other":  "GET other.app.test/v1/users/7",
	}
	by := map[string][]obs{
		"k_target": {{samples: []string{"/v1/users/7"}}},
		"k_api":    {{samples: []string{"/v1/users/7"}}},
		"k_other":  {{samples: []string{"/v1/users/7"}}},
	}
	mixedEp := endpoints.Endpoint{
		Method: "GET",
		Path:   "/users/{id}",
		Bases:  []string{"https://api.app.test/v1", "/v1"},
	}
	paired := cmp.pair(mixedEp, "app.test", order, tmpl, map[string]string{}, by)
	if !slices.Equal(paired, []string{"k_target", "k_api"}) {
		t.Fatalf("mixed Bases paired = %v, want [k_target k_api]", paired)
	}
}

func TestNativeOf(t *testing.T) {
	// /api/items/featured only in admin's script, /api/items/{id} in the
	// shared bundle: both are the key, so lower roles have it as code.
	if nativeOf([]int{2, -1}) != -1 || nativeOf([]int{1, 2}) != 2 || nativeOf(nil) != -1 {
		t.Fatal("nativeOf")
	}
}

func TestOrder(t *testing.T) {
	got, err := Order([]string{"admin", "anon", "user"})
	if err != nil || !slices.Equal(got, []string{"anon", "user", "admin"}) {
		t.Fatal(got, err)
	}
	// Unknown names have no order by name (Reviewer S6).
	if _, err := Order([]string{"user", "superadmin", "manager"}); err == nil {
		t.Fatal("ordered unknown names")
	}
}

func TestMaskTokens(t *testing.T) {
	got := MaskTokens("/reset/9f8e7d6c5b4a39281706f5e4d3c2b1a0/user/bob@x.test?next=/home")
	if got != "/reset/{hash}/user/{email}?next=/home" {
		t.Fatal(got)
	}
	if MaskTokens("/api/users/42/orders") != "/api/users/42/orders" {
		t.Fatal("ids and names stay")
	}
}
