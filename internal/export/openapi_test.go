package export

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func oaReq(id int, method, url, tmpl, ct, body string, status int64, extra map[string]string) *Request {
	h := map[string]string{"host": "app.test", "cookie": "sid=SECRETCOOKIEVALUE", "authorization": "Bearer SECRETBEARERTOKEN", "x-csrf-token": "CSRFSECRETVALUE"}
	if ct != "" {
		h["content-type"] = ct
	}
	for k, v := range extra {
		h[k] = v
	}
	e := traffic.Entry{Run: "R1", ID: id, Method: method, URL: url, ResourceType: "Fetch", Outcome: "ok",
		Time: time.Unix(1700000000+int64(id), 0).UTC(), Headers: h, Body: traffic.Body{Body: body}}
	if status > 0 {
		e.Response = &traffic.Response{Status: status, Headers: map[string]string{"content-type": "application/json; charset=utf-8"}}
	}
	return &Request{Entry: e, Run: "R1", Template: tmpl, File: true}
}

func oaModel(t *testing.T, eps []endpoints.Endpoint, redacted bool) *Model {
	t.Helper()
	m := &Model{Runs: []string{"R1"}, role: "anon", redacted: redacted, byRef: map[string]*Request{},
		cat: newCatalog(eps, func(string) bool { return true })}
	g1 := oaReq(1, "POST", "https://app.test/graphql", "/graphql", "application/json", `[`+elemA+`]`, 200, nil)
	g1.Op = "op=GetA"
	g2 := oaReq(2, "POST", "https://app.test/graphql", "/graphql", "application/json", `{"operationName":"GetB","query":"query GetB { b }","variables":{"email":"bob@example.com"}}`, 200, nil)
	g2.Op = "op=GetB"
	items1 := oaReq(3, "GET", "https://app.test/api/items/42?page=2&token=ABCDEFGH", "/api/items/{}", "", "", 200, map[string]string{"x-trace": "t1"})
	items2 := oaReq(4, "GET", "https://app.test/api/items/43?page=3", "/api/items/{}", "", "", 404, nil)
	prof := oaReq(5, "POST", "https://app.test/api/profile", "/api/profile", "application/json",
		`{"display_name":"Bob","age":3,"score":1.5,"tags":["a"],"nested":{"ok":true,"none":null},"password":"hunter2hunter2"}`, 200, nil)
	del := oaReq(6, "DELETE", "https://app.test/api/items/42", "/api/items/{}", "", "", 204, nil)
	held := oaReq(7, "PUT", "https://app.test/api/upload/1", "/api/upload/{}", "application/x-www-form-urlencoded", "a=1&b=x", 0, nil)
	held.Entry.Outcome = "held_back:write"
	held.Held = true
	form := oaReq(8, "POST", "https://app.test/api/edit", "/api/edit", "application/x-www-form-urlencoded", "action=save&n=3", 200, nil)
	cdn := oaReq(9, "GET", "https://cdn.other.test/a/b", "/a/b", "", "", 200, nil)
	m.Requests = []*Request{g1, g2, items1, items2, prof, del, held, form, cdn}
	return m
}

var oaCode = []endpoints.Endpoint{
	{Method: "GET", Path: "/api/legacy/{id}/info", Query: []string{"verbose"}, Headers: []string{"X-Api-Key", "Cookie"}, Host: "app.test"},
	{Method: "POST", Path: "/api/orders/create", Body: []string{"sku", "qty"}, Host: "app.test"},
	{Path: "/api/nomethod/thing", Host: "app.test"},
}

func oaDoc(t *testing.T, m *Model) (obj, []byte) {
	t.Helper()
	b, err := m.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var d obj
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d, b
}

func sub(t *testing.T, v any, keys ...string) any {
	t.Helper()
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok || m[k] == nil {
			t.Fatalf("no %s in %v", strings.Join(keys, "."), v)
		}
		v = m[k]
	}
	return v
}

func TestOpenAPIShape(t *testing.T) {
	d, b := oaDoc(t, oaModel(t, oaCode, false))
	if d["openapi"] != "3.1.0" || sub(t, d, "info", "title") == "" {
		t.Fatalf("%v", d["info"])
	}
	// Path templates: {} named by position; the traffic's statuses.
	get := sub(t, d, "paths", "/api/items/{p1}", "get").(obj)
	ps := get["parameters"].([]any)
	if p := ps[0].(obj); p["name"] != "p1" || p["in"] != "path" || p["required"] != true || sub(t, p, "schema", "type") != "integer" {
		t.Fatalf("path param: %v", p)
	}
	sub(t, get, "responses", "200")
	sub(t, get, "responses", "404")
	if sub(t, get, "x-jsharvest", "source") != "traffic" {
		t.Fatalf("%v", get["x-jsharvest"])
	}
	// Query: names, a sample of a plain one, none of a credential's.
	var names []string
	for _, p := range ps {
		pm := p.(obj)
		names = append(names, pm["in"].(string)+":"+pm["name"].(string))
		if pm["name"] == "page" && pm["example"] != "2" {
			t.Fatalf("page: %v", pm)
		}
		if pm["name"] == "token" && pm["example"] != nil {
			t.Fatalf("an example of a credential: %v", pm)
		}
		if pm["in"] == "header" && (pm["example"] != nil || pm["default"] != nil) {
			t.Fatalf("a header with a value: %v", pm)
		}
	}
	if got := strings.Join(names, ","); got != "path:p1,header:authorization,header:x-csrf-token,header:x-trace,query:page,query:token" {
		// path first, then header and query by name; a credential's header by its name
		t.Fatalf("%s", got)
	}
	// A destructive method, and a held write with no status.
	if sub(t, d, "paths", "/api/items/{p1}", "delete", "x-jsharvest", "destructive") != true {
		t.Fatal("not destructive")
	}
	put := sub(t, d, "paths", "/api/upload/{p1}", "put").(obj)
	if sub(t, put, "x-jsharvest", "held_back") != true {
		t.Fatal("not held back")
	}
	sub(t, put, "responses", "default")
	sub(t, put, "requestBody", "content", "application/x-www-form-urlencoded", "schema", "properties", "a")
	// A JSON body's schema, its secrets nowhere.
	sch := sub(t, d, "paths", "/api/profile", "post", "requestBody", "content", "application/json", "schema")
	if sub(t, sch, "properties", "age", "type") != "integer" || sub(t, sch, "properties", "score", "type") != "number" ||
		sub(t, sch, "properties", "tags", "items", "type") != "string" || sub(t, sch, "properties", "nested", "properties", "none", "type") != "null" {
		t.Fatalf("%v", sch)
	}
	// Code only: its method, its names, its default response.
	cg := sub(t, d, "paths", "/api/legacy/{id}/info", "get").(obj)
	if sub(t, cg, "x-jsharvest", "source") != "code" {
		t.Fatalf("%v", cg)
	}
	sub(t, cg, "responses", "default")
	var cn []string
	for _, p := range cg["parameters"].([]any) {
		cn = append(cn, p.(obj)["in"].(string)+":"+p.(obj)["name"].(string))
	}
	if strings.Join(cn, ",") != "path:id,header:x-api-key,query:verbose" {
		t.Fatalf("%v", cn) // Cookie is no header parameter
	}
	sub(t, d, "paths", "/api/orders/create", "post", "requestBody", "content", "application/json", "schema", "properties", "sku")
	if strings.Contains(string(b), "nomethod") || sub(t, d, "x-jsharvest", "code_endpoints_without_method") != float64(1) {
		t.Fatal("an endpoint with no method was written")
	}
	// Two origins: servers, and the operation's own.
	if len(d["servers"].([]any)) != 2 {
		t.Fatalf("%v", d["servers"])
	}
	sub(t, d, "paths", "/a/b", "get", "servers")
	// Nothing secret in the document.
	for _, s := range []string{"SECRETCOOKIEVALUE", "SECRETBEARERTOKEN", "CSRFSECRETVALUE", "hunter2hunter2", "bob@example.com", "ABCDEFGH"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("%s is in the document", s)
		}
	}
	// operationIds are unique.
	ids := map[string]bool{}
	for _, pi := range d["paths"].(obj) {
		for _, op := range pi.(obj) {
			id := op.(obj)["operationId"].(string)
			if ids[id] {
				t.Fatalf("operationId %s twice", id)
			}
			ids[id] = true
		}
	}
}

// One operation for /graphql, its operations listed and exemplified.
func TestOpenAPIGraphQLBatch(t *testing.T) {
	d, b := oaDoc(t, oaModel(t, nil, false))
	op := sub(t, d, "paths", "/graphql", "post").(obj)
	if got := op["x-graphql-operations"].([]any); len(got) != 2 || got[0] != "GetA" || got[1] != "GetB" {
		t.Fatalf("%v", got)
	}
	ex := sub(t, op, "requestBody", "content", "application/json", "examples").(obj)
	if _, ok := sub(t, ex, "GetA", "value").([]any); !ok {
		t.Fatalf("the batch's example is not an array: %v", ex["GetA"])
	}
	if _, ok := sub(t, ex, "GetB", "value").(obj); !ok {
		t.Fatalf("%v", ex["GetB"])
	}
	if !strings.Contains(string(b), "{email}") {
		t.Fatal("the email was not masked in the example")
	}
}

func TestOpenAPIRedactedHasNoExamples(t *testing.T) {
	_, b := oaDoc(t, oaModel(t, oaCode, true))
	if bytes.Contains(b, []byte(`"example`)) {
		t.Fatalf("an example in a redacted document: %s", b)
	}
}

func TestOpenAPIDeterministic(t *testing.T) {
	_, a := oaDoc(t, oaModel(t, oaCode, false))
	_, c := oaDoc(t, oaModel(t, oaCode, false))
	if !bytes.Equal(a, c) {
		t.Fatal("two runs, two documents")
	}
}

func TestOpenAPIFromLoad(t *testing.T) {
	dir := batchDir(t)
	m, err := Load(Options{Dir: dir, Role: "anon"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := oaDoc(t, m)
	op := sub(t, d, "paths", "/graphql", "post").(obj)
	if got := op["x-graphql-operations"].([]any); len(got) != 2 {
		t.Fatalf("%v", got)
	}
	// The file: 0600, and a later export may replace its directory.
	out := filepath.Join(dir, "oa")
	if err := m.WriteOpenAPI(out); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(out, "openapi.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	if _, err := Export(Options{Dir: dir, Dest: out}); err != nil {
		t.Fatalf("an openapi-only directory was not replaced: %v", err)
	}
}

func TestOpenAPICatalogOnly(t *testing.T) {
	m := CatalogModel(Options{Catalog: oaCode, Role: "anon"})
	d, _ := oaDoc(t, m)
	sub(t, d, "paths", "/api/orders/create", "post")
	if len(d["servers"].([]any)) != 1 {
		t.Fatalf("%v", d["servers"])
	}
}

func TestMergeSchema(t *testing.T) {
	a := inferSchema(map[string]any{"x": json.Number("1"), "l": []any{}}, 0)
	b := inferSchema(map[string]any{"x": json.Number("1.5"), "y": nil, "l": []any{"s"}}, 0)
	m := mergeSchema(a, b)
	if sub(t, m, "properties", "x", "type") != "number" || sub(t, m, "properties", "y", "type") != "null" ||
		sub(t, m, "properties", "l", "items", "type") != "string" {
		t.Fatalf("%v", m)
	}
}
