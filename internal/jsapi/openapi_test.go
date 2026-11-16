package jsapi

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestSwaggerResources(t *testing.T) {
	body := []byte(`[
		{"name":"auth","url":"/v2/api-docs?group=auth","location":"/auth/v2/api-docs"},
		{"name":"orders","location":"/orders/v2/api-docs"},
		{"name":"dup","url":"/orders/v2/api-docs"},
		{"name":"ext","url":"https://evil.example.com/v2/api-docs"},
		{"name":"proto","url":"//evil.example.com/v2/api-docs"},
		{"name":"noslash","url":"v2/api-docs"},
		{"name":"dotdot","url":"/../etc/passwd"},
		{"name":"billing","url":"/billing/v2/api-docs"}
	]`)
	got := SwaggerResources(body)
	want := []string{
		"/v2/api-docs?group=auth",
		"/orders/v2/api-docs",
		"/billing/v2/api-docs",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("SwaggerResources:\n got  %v\n want %v", got, want)
	}

	// Cap at MaxSwaggerResources (5).
	var many []string
	for i := 0; i < 9; i++ {
		many = append(many, fmt.Sprintf(`{"name":"s%d","url":"/svc%d/v2/api-docs"}`, i, i))
	}
	capped := SwaggerResources([]byte("[" + strings.Join(many, ",") + "]"))
	if len(capped) != MaxSwaggerResources {
		t.Fatalf("expected cap %d, got %d (%v)", MaxSwaggerResources, len(capped), capped)
	}

	// Non-array or invalid JSON returns nil.
	for _, bad := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"url":"/v2/api-docs"}`),
		[]byte(`<!doctype html><html></html>`),
	} {
		if r := SwaggerResources(bad); len(r) != 0 {
			t.Errorf("expected empty for %q, got %v", bad, r)
		}
	}
}

func TestSwagger2IsOpenAPIAndExtract(t *testing.T) {
	doc := []byte(`{"swagger":"2.0","info":{"title":"Auth","version":"1.0"},"basePath":"/api-gateway/auth","paths":{"/v1/login":{"post":{"operationId":"login"}}}}`)
	if !IsOpenAPI(doc) {
		t.Fatal("expected Swagger 2.0 JSON to match IsOpenAPI")
	}
	res := ExtractOpenAPI(doc)
	if !slices.Equal(res.Bases, []string{"/api-gateway/auth"}) || len(res.Endpoints) != 1 || res.Endpoints[0].URL != "/v1/login" {
		t.Fatalf("unexpected ExtractOpenAPI result: %+v", res)
	}
}
