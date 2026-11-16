package main

import (
	"strings"
	"testing"
)

const goodOA = `{"openapi":"3.1.0","info":{"title":"t","version":"1"},"servers":[{"url":"http://h"}],
"paths":{"/api/items/{p1}":{"get":{"operationId":"get_items","parameters":[
 {"name":"p1","in":"path","required":true,"schema":{"type":"string"}},
 {"name":"authorization","in":"header","schema":{"type":"string"}}],
 "responses":{"200":{"description":"OK"}},"x-jsharvest":{"source":"traffic"}},
 "delete":{"operationId":"delete_items","parameters":[{"name":"p1","in":"path","required":true,"schema":{}}],"responses":{"default":{"description":"d"}}}},
"/api/search":{"get":{"operationId":"get_search","responses":{"200":{"description":"OK"}}}}}}`

func TestOpenAPIProblems(t *testing.T) {
	if p := openapiProblems([]byte(goodOA), []string{"GET /api/search", "GET /api/items/{id}", "DELETE /api/items/{}"}); len(p) != 0 {
		t.Fatalf("a good document: %v", p)
	}
	cases := []struct{ name, from, to, want string }{
		{"version", `"3.1.0"`, `"3.0.3"`, "want 3.1.0"},
		{"title", `"title":"t"`, `"title":""`, "info.title"},
		{"path", `"/api/search"`, `"api/search"`, "does not start with /"},
		{"unnamed path param", `"name":"p1","in":"path","required":true,"schema":{"type":"string"}`, `"name":"q","in":"path","required":true,"schema":{"type":"string"}`, "has no in: path parameter"},
		{"not required", `"required":true,"schema":{"type":"string"}`, `"schema":{"type":"string"}`, "not required"},
		{"duplicate id", `"get_search"`, `"get_items"`, "also"},
		{"no responses", `"responses":{"200":{"description":"OK"}}}}}}`, `"responses":{}}}}}`, "no responses"},
		{"credential value", `{"name":"authorization","in":"header","schema":{"type":"string"}}`, `{"name":"Authorization","in":"header","example":"Bearer x","schema":{"type":"string"}}`, "carries a value"},
		{"bad source", `"source":"traffic"`, `"source":"guess"`, "x-jsharvest.source"},
	}
	for _, c := range cases {
		doc := strings.Replace(goodOA, c.from, c.to, 1)
		if doc == goodOA {
			t.Fatalf("%s: the case changes nothing", c.name)
		}
		p := strings.Join(openapiProblems([]byte(doc), nil), "|")
		if !strings.Contains(p, c.want) {
			t.Errorf("%s: problems %q, want one with %q", c.name, p, c.want)
		}
	}
	if p := openapiProblems([]byte(goodOA), []string{"POST /api/missing"}); len(p) != 1 || !strings.Contains(p[0], "no operation for") {
		t.Fatalf("%v", p)
	}
	if p := openapiProblems([]byte("{"), nil); len(p) != 1 {
		t.Fatalf("%v", p)
	}
}
