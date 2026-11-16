package replay

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestClassifyID(t *testing.T) {
	relay := EncodeRelay("VaultItem", "1001", 0)
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl"
	for _, c := range []struct {
		name string
		p    export.Param
		ctx  IDCtx
		want IDKind
	}{
		{"uuid in a path", export.Param{In: "path", Index: 4, Value: "5a1c0d0c-2e4f-4b6a-8c7d-0000a11ce001"}, IDCtx{}, IDUUID},
		{"small int in a path", export.Param{In: "path", Index: 4, Value: "1101"}, IDCtx{}, IDIntSmall},
		{"snowflake", export.Param{In: "path", Index: 4, Value: "1700000000000000001"}, IDCtx{}, IDInt64},
		{"past int64: no id", export.Param{In: "path", Index: 4, Value: "9300000000000000001"}, IDCtx{}, IDNone},
		{"int64 at the top", export.Param{In: "path", Index: 4, Value: "9223372036854775807"}, IDCtx{}, IDInt64},
		{"ulid", export.Param{In: "query", Name: "id", Value: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}, IDCtx{}, IDULID},
		{"objectid", export.Param{In: "path", Index: 3, Value: "507f1f77bcf86cd799439011"}, IDCtx{}, IDObjectID},
		{"relay in a body", export.Param{In: "json", Name: "$[0].variables.id", Value: relay}, IDCtx{}, IDRelay},
		{"slug at a placeholder", export.Param{In: "path", Index: 4, Value: "proj-aurora"}, IDCtx{Wildcard: true}, IDSlug},
		{"slug where the template is constant", export.Param{In: "path", Index: 3, Value: "orgs"}, IDCtx{}, IDNone},
		{"slug by an id-like name", export.Param{In: "query", Name: "itemId", Value: "vault-alice-01"}, IDCtx{}, IDSlug},
		{"a word in a query", export.Param{In: "query", Name: "type", Value: "user"}, IDCtx{}, IDNone},
		{"small number in a query: a flag", export.Param{In: "query", Name: "tab", Value: "3"}, IDCtx{}, IDNone},
		{"small number with an id name", export.Param{In: "query", Name: "userId", Value: "7"}, IDCtx{}, IDIntSmall},
		{"pagination", export.Param{In: "query", Name: "page", Value: "2000"}, IDCtx{}, IDNone},
		{"limit", export.Param{In: "query", Name: "limit", Value: "100"}, IDCtx{}, IDNone},
		{"alias me", export.Param{In: "path", Index: 4, Value: "me"}, IDCtx{Wildcard: true}, IDNone},
		{"a jwt", export.Param{In: "query", Name: "userId", Value: jwt}, IDCtx{}, IDNone},
		{"a signature", export.Param{In: "query", Name: "sig", Value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}, IDCtx{}, IDNone},
		{"a long hex", export.Param{In: "query", Name: "id", Value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}, IDCtx{}, IDNone},
		{"a random token", export.Param{In: "query", Name: "ref", Value: "aZ3kQ9xLmP2vB7nR4tYw8cJe5HdFg6"}, IDCtx{}, IDNone},
		{"expires", export.Param{In: "query", Name: "expires", Value: "4102444800"}, IDCtx{}, IDNone},
		{"a date", export.Param{In: "query", Name: "from", Value: "2026-01-02"}, IDCtx{}, IDNone},
		{"the graphql document", export.Param{In: "json", Name: "$[0].query", Value: "query A { a }"}, IDCtx{}, IDNone},
		{"operationName", export.Param{In: "json", Name: "$[0].operationName", Value: "GetVaultItem"}, IDCtx{}, IDNone},
		{"a credential header", export.Param{In: "header", Name: "x-api-key", Value: "7b2d9e44-1a6c-4f08-b3d5-b0b000000002"}, IDCtx{}, IDNone},
		{"a tenant header", export.Param{In: "header", Name: "x-org-id", Value: "7b2d9e44-1a6c-4f08-b3d5-b0b000000002"}, IDCtx{}, IDUUID},
		{"a nonce header", export.Param{In: "header", Name: "x-req-nonce", Value: "7b2d9e441a6c4f08b3d5b0b000000002"}, IDCtx{}, IDNone},
		{"a cookie", export.Param{In: "cookie", Name: "uid", Value: "1101"}, IDCtx{}, IDNone},
		{"zero", export.Param{In: "path", Index: 4, Value: "0"}, IDCtx{}, IDNone},
	} {
		if got := ClassifyID(c.p, c.ctx).Kind; got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDecodeRelay(t *testing.T) {
	for enc := range relayEncodings {
		v := EncodeRelay("VaultItem", "1001", enc)
		typ, inner, ik, e, ok := DecodeRelay(v)
		if !ok || typ != "VaultItem" || inner != "1001" || ik != IDIntSmall || EncodeRelay(typ, inner, e) != v {
			t.Errorf("enc %d: %q -> %s %s %s %d %v", enc, v, typ, inner, ik, e, ok)
		}
	}
	for _, v := range []string{"", "plainstring", "VmF1bHRJdGVt", EncodeRelay("lower", "1001", 0), EncodeRelay("Item", "a b", 0)} {
		if _, _, _, _, ok := DecodeRelay(v); ok {
			t.Errorf("%q read as relay", v)
		}
	}
}

func TestSeenSet(t *testing.T) {
	s := NewSeenSet()
	s.AddResponse(map[string]string{"content-type": "application/json", "x-trace": "abc123def"},
		`{"viewer":{"id":"u-1","org":"org-alpha","tier":4},"links":[{"url":"/api/files/doc-b1?sig=xyz&expires=9"}],"rel":"`+EncodeRelay("Doc", "55", 0)+`"}`)
	for _, v := range []string{"u-1", "org-alpha", "4", "doc-b1", "xyz", "abc123def", "Doc:55"} {
		if !s.Has(v) {
			t.Errorf("%q not seen", v)
		}
	}
	if s.Has("doc-a1") || s.Has("5") || s.Has("55") {
		t.Error("something never shown")
	}
	// A short value is seen by the leaf it was under only.
	if !s.HasKV("tier", "4") || s.HasKV("balance", "4") {
		t.Error("key and value")
	}
	// A Relay id is seen when its decoded form or inner id is.
	if !s.Has(EncodeRelay("Doc", "55", 2)) || s.Has(EncodeRelay("Doc", "56", 0)) {
		t.Error("relay")
	}
	// An id with its padding dropped is the same.
	s.Add("abcd==")
	if !s.Has("abcd") {
		t.Error("padding")
	}
	h := NewSeenSet()
	h.AddResponse(map[string]string{"content-type": "text/html"}, `<meta name="csrf" content="zzz-123"><a href="/docs/doc-77">x</a>`)
	if !h.Has("zzz-123") {
		t.Error("html attribute")
	}
}

func TestBogusID(t *testing.T) {
	uuid4 := "5a1c0d0c-2e4f-4b6a-8c7d-0000a11ce001"
	uuid7 := "01890a5d-ac96-774b-bcce-b302099a8057"
	cases := []ParsedID{
		{Kind: IDIntSmall, Value: "1101"},
		{Kind: IDIntSmall, Value: "2000000000"},
		{Kind: IDIntSmall, Value: "7"},
		{Kind: IDInt64, Value: "1700000000000000001"},
		{Kind: IDInt64, Value: "9223372036854775800"},
		{Kind: IDInt64, Value: "2200000000"},
		{Kind: IDUUID, Value: uuid4},
		{Kind: IDUUID, Value: uuid7},
		{Kind: IDUUID, Value: strings.ToUpper(uuid4)},
		{Kind: IDULID, Value: "01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		{Kind: IDObjectID, Value: "507f1f77bcf86cd799439011"},
		{Kind: IDSlug, Value: "proj-aurora"},
		{Kind: IDSlug, Value: "doc-a1"},
		{Kind: IDSlug, Value: "vault-alice-01"},
		{Kind: IDSlug, Value: "alpharoadmap"},
	}
	r := ParsedID{Kind: IDRelay, RelayType: "VaultItem", RelayInner: "1001", InnerKind: IDIntSmall, Value: EncodeRelay("VaultItem", "1001", 1), relayEnc: 1}
	cases = append(cases, r)
	for _, c := range cases {
		for range 200 {
			v := BogusID(c, nil)
			if v == "" || v == c.Value {
				t.Fatalf("%s %s: %q", c.Kind, c.Value, v)
			}
			switch c.Kind {
			case IDIntSmall, IDInt64:
				n, err := strconv.ParseInt(v, 10, 64)
				o, _ := strconv.ParseInt(c.Value, 10, 64)
				if err != nil || n <= 0 || n > math.MaxInt64 {
					t.Fatalf("%s: %q", c.Value, v)
				}
				if c.Kind == IDIntSmall && n > math.MaxInt32 {
					t.Fatalf("%s: %q past int32", c.Value, v)
				}
				if d := n - o; d >= -1_000_000 && d <= 1_000_000 {
					t.Fatalf("%s: %q too near", c.Value, v)
				}
				if c.Kind == IDInt64 && len(v) != len(c.Value) && c.Value != "2200000000" {
					t.Fatalf("%s: %q another length", c.Value, v)
				}
			case IDUUID:
				if len(v) != 36 || v[14] != c.Value[14] || !regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(v) {
					t.Fatalf("%s: %q", c.Value, v)
				}
				if (c.Value == strings.ToUpper(c.Value)) != (v == strings.ToUpper(v)) {
					t.Fatalf("%s: %q case", c.Value, v)
				}
			case IDULID:
				if !ulidRe.MatchString(v) || v[:10] != c.Value[:10] {
					t.Fatalf("%s: %q", c.Value, v)
				}
			case IDObjectID:
				if !objectIDRe.MatchString(v) || v[:8] != c.Value[:8] {
					t.Fatalf("%s: %q", c.Value, v)
				}
			case IDSlug:
				if !strings.HasPrefix(c.Value, "alpha") && !strings.HasPrefix(v, c.Value[:strings.IndexAny(c.Value, "-_")+1]) {
					t.Fatalf("%s: %q lost its prefix", c.Value, v)
				}
				if c.Value == "alpharoadmap" && (!strings.HasPrefix(v, "z-") || len(v) < 14) {
					t.Fatalf("%s: %q", c.Value, v)
				}
			case IDRelay:
				typ, inner, ik, enc, ok := DecodeRelay(v)
				if !ok || typ != "VaultItem" || ik != IDIntSmall || enc != 1 || inner == "1001" {
					t.Fatalf("%q: %s %s %v", v, typ, inner, ok)
				}
				if n, _ := strconv.ParseInt(inner, 10, 64); n < 1_000_000_000 || n > math.MaxInt32 {
					t.Fatalf("inner %s", inner)
				}
			}
		}
	}
	// The ids taken are avoided.
	taken := map[string]bool{}
	for range 50 {
		v := BogusID(ParsedID{Kind: IDSlug, Value: "doc-a1"}, func(s string) bool { return taken[s] })
		if taken[v] {
			t.Fatalf("%q was taken", v)
		}
		taken[v] = true
	}
	if BogusID(ParsedID{Kind: IDNone, Value: "x"}, nil) != "" {
		t.Error("a bogus for no id")
	}
	if !near("1500", "1101", IDIntSmall) || near("1900000000", "1101", IDIntSmall) || !near(EncodeRelay("Item", "1500", 0), EncodeRelay("Item", "1101", 0), IDRelay) {
		t.Error("near")
	}
}

func TestCanonKey(t *testing.T) {
	for in, want := range map[string]string{
		"GET h/api/orders/{id}":                    "GET h/api/orders/{}",
		"GET h/api/orgs/{o}/projects/{uuid}/":      "GET h/api/orgs/{}/projects/{}",
		"POST h/api/graphql op=GetVaultItem":       "POST h/api/graphql op=GetVaultItem",
		"GET h/api/keys/{param} action=regenerate": "GET h/api/keys/{} action=regenerate",
		"GET h/":                    "GET h/",
		"GET h/api/notes/{hash}/{}": "GET h/api/notes/{}/{}",
		"GET h/api/files/{a}b/{c}":  "GET h/api/files/{}b/{}",
	} {
		if got := canonEndpointKey(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	for _, n := range []string{"sig", "X-Amz-Signature", "Expires", "Key-Pair-Id", "se"} {
		if !isURLSignatureParam(n) {
			t.Errorf("%s is a signature", n)
		}
	}
	if isURLSignatureParam("access_token") || isURLSignatureParam("id") {
		t.Error("not signatures")
	}
}

func TestAlignWildcardsKeepsEndpointsApart(t *testing.T) {
	mk := func(url, tmpl string) *export.Request {
		return &export.Request{Entry: traffic.Entry{Method: "GET", URL: url}, Template: tmpl}
	}
	h := "http://h:1"
	a1 := mk(h+"/api/peer/private-notes/1101", "/api/peer/private-notes/1101")
	b1 := mk(h+"/api/peer/wallets-leaky/7", "/api/peer/wallets-leaky/7")
	a2 := mk(h+"/api/peer/signed-preview/6601", "/api/peer/signed-preview/6601")
	b2 := mk(h+"/api/peer/private-notes/1201", "/api/peer/private-notes/1201")
	pa := mk(h+"/api/peer/orgs/org-alpha/projects/p-77", "/api/peer/orgs/org-alpha/projects/p-77")
	pb := mk(h+"/api/peer/orgs/org-beta/projects/p-91", "/api/peer/orgs/org-beta/projects/p-91")
	al := alignWildcards(&export.Model{Requests: []*export.Request{a1, a2, pa}}, &export.Model{Requests: []*export.Request{b1, b2, pb}})
	key := func(r *export.Request) string { return reportKey(r, nil, al) }
	if key(a1) == key(b1) || key(a2) == key(b1) || key(a1) == key(a2) {
		t.Errorf("different endpoints share a key: %s %s %s", key(a1), key(b1), key(a2))
	}
	if key(a1) != "GET h:1/api/peer/private-notes/{}" || key(a1) != key(b2) {
		t.Errorf("same endpoint: %s %s", key(a1), key(b2))
	}
	if k := key(pa); k != "GET h:1/api/peer/orgs/org-alpha/projects/{}" {
		t.Errorf("projects: %s", k)
	}
	// Templates of the export that differ at a literal: never merged.
	x := mk(h+"/api/v/a1", "/api/v/a1")
	y := mk(h+"/api/v/b2", "/api/v/{}")
	z := mk(h+"/api/v/c3", "/api/v/c3")
	if al := alignWildcards(&export.Model{Requests: []*export.Request{x}}, &export.Model{Requests: []*export.Request{z}}); len(al[x]) == 0 {
		t.Error("literal ids that differ were not aligned")
	}
	lit1 := mk(h+"/api/v1/x7", "/api/v1/x7")
	lit2 := mk(h+"/api/v2/x7", "/api/v2/x7")
	if al := alignWildcards(&export.Model{Requests: []*export.Request{lit1}}, &export.Model{Requests: []*export.Request{lit2}}); len(al) != 0 {
		t.Errorf("v1 and v2 merged: %v", al)
	}
	_ = y
}
