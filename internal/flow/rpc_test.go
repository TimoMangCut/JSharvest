package flow

import (
	"net/url"
	"slices"
	"testing"
)

func TestNextActionOperationWithHeaders(t *testing.T) {
	u, _ := url.Parse("https://app.test/dashboard/settings")

	// Standard Next.js 14/15/16 App Router header (case-insensitive header key & hex normalized).
	hex40 := "40A1B2C3D4E5F60718293A4B5C6D7E8F90123456"
	want := "next-action=40a1b2c3d4e5f60718293a4b5c6d7e8f90123456"
	got := OperationWithHeaders(u, map[string]string{"Next-Action": hex40}, "text/plain;charset=UTF-8", `["inv_1"]`)
	if got != want {
		t.Fatalf("OperationWithHeaders(Next-Action) = %q, want %q", got, want)
	}
	if ops := OperationsWithHeaders(u, map[string]string{"next-action": hex40}, "text/plain;charset=UTF-8", `["inv_1"]`); !slices.Equal(ops, []string{want}) {
		t.Fatalf("OperationsWithHeaders = %v, want [%q]", ops, want)
	}

	// Progressive-enhancement form body ($ACTION_ID_<hex>, raw and URL-encoded) and multipart field name.
	hex42 := "7f0123456789abcdef0123456789abcdef01234567"
	want42 := "next-action=" + hex42
	for _, body := range []string{
		"$ACTION_ID_" + hex42 + "=&name=alice",
		"%24ACTION_ID_" + hex42 + "=&name=alice",
		"------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"$ACTION_ID_" + hex42 + "\"\r\n\r\n\r\n------WebKitFormBoundary--",
	} {
		if got := Operation(u, "application/x-www-form-urlencoded", body); got != want42 {
			t.Fatalf("Operation(form %q) = %q, want %q", body, got, want42)
		}
	}

	// Reject malformed or non-hex Next-Action headers.
	for _, bad := range []string{"", "short1234", "not-a-hex-string-at-all-0000000000000000", "40a1b2c3d4e5f60718293a4b5c6d7e8f9012345z"} {
		if got := OperationWithHeaders(u, map[string]string{"Next-Action": bad}, "text/plain", `[]`); got != "" {
			t.Fatalf("OperationWithHeaders(bad=%q) = %q, want empty", bad, got)
		}
	}

	// Next.js protocol routing headers are plain (never credentials or kept_headers).
	for _, h := range []string{"Next-Action", "next-action", "Next-Router-State-Tree", "Next-Router-Prefetch", "Next-Url", "RSC"} {
		if !PlainHeader(h) {
			t.Fatalf("PlainHeader(%q) = false, want true", h)
		}
	}
}

func TestTRPCBatchSplitGETAndPOST(t *testing.T) {
	rawGET := `https://app.test/api/trpc/user.me,invoice.byId?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%2C%221%22%3A%7B%22json%22%3A%7B%22id%22%3A%22inv_1%22%7D%7D%7D`
	uGET, err := url.Parse(rawGET)
	if err != nil {
		t.Fatal(err)
	}
	parts := SplitBatchWithURL(uGET, "", "")
	if len(parts) != 2 {
		t.Fatalf("GET SplitBatchWithURL len = %d (%+v), want 2", len(parts), parts)
	}
	u0, _ := url.Parse(parts[0].URL)
	u1, _ := url.Parse(parts[1].URL)
	if u0.Path != "/api/trpc/user.me" || u0.Query().Get("batch") != "1" || u0.Query().Get("input") != `{"0":{"json":null}}` {
		t.Fatalf("part[0] URL = %q (input=%q)", parts[0].URL, u0.Query().Get("input"))
	}
	if u1.Path != "/api/trpc/invoice.byId" || u1.Query().Get("batch") != "1" || u1.Query().Get("input") != `{"0":{"json":{"id":"inv_1"}}}` {
		t.Fatalf("part[1] URL = %q (input=%q)", parts[1].URL, u1.Query().Get("input"))
	}

	// POST indexed object body.
	uPOST, _ := url.Parse("https://app.test/api/trpc/invoice.update,audit.log?batch=1")
	postObj := `{"0":{"json":{"id":"inv_1"}},"1":{"json":{"evt":"view"}}}`
	pPost := SplitBatchWithURL(uPOST, "application/json", postObj)
	if len(pPost) != 2 {
		t.Fatalf("POST object SplitBatchWithURL len = %d, want 2", len(pPost))
	}
	if pPost[0].URL != "https://app.test/api/trpc/invoice.update?batch=1" || pPost[0].Body != `{"0":{"json":{"id":"inv_1"}}}` {
		t.Fatalf("POST part[0] = %+v", pPost[0])
	}
	if pPost[1].URL != "https://app.test/api/trpc/audit.log?batch=1" || pPost[1].Body != `{"0":{"json":{"evt":"view"}}}` {
		t.Fatalf("POST part[1] = %+v", pPost[1])
	}

	// POST array body (tRPC v11 array batch).
	postArr := `[{"json":{"id":"inv_1"}},{"json":{"evt":"view"}}]`
	pArr := SplitBatchWithURL(uPOST, "application/json", postArr)
	if len(pArr) != 2 || pArr[1].Body != `[{"json":{"evt":"view"}}]` {
		t.Fatalf("POST array SplitBatchWithURL = %+v", pArr)
	}
}

func TestTRPCTemplatesPreserveProcedureNames(t *testing.T) {
	calls := []Call{
		{Method: "GET", URL: "https://app.test/api/trpc/user.me?batch=1", Frame: "trpc.js:12"},
		{Method: "GET", URL: "https://app.test/api/trpc/invoice.byId?batch=1", Frame: "trpc.js:12"},
		{Method: "GET", URL: "https://app.test/api/trpc/org.members.list?batch=1", Frame: "trpc.js:12"},
		{Method: "GET", URL: "https://app.test/api/trpc/billing.plan?batch=1", Frame: "trpc.js:12"},
		// Non-tRPC dotted domain parameters from one frame MUST still collapse to {param}.
		{Method: "GET", URL: "https://app.test/api/domains/alpha.com", Frame: "dom.js:5"},
		{Method: "GET", URL: "https://app.test/api/domains/bravo.org", Frame: "dom.js:5"},
		{Method: "GET", URL: "https://app.test/api/domains/charlie.net", Frame: "dom.js:5"},
	}
	got := Templates(calls)
	want := []string{
		"/api/trpc/user.me",
		"/api/trpc/invoice.byId",
		"/api/trpc/org.members.list",
		"/api/trpc/billing.plan",
		"/api/domains/{param}",
		"/api/domains/{param}",
		"/api/domains/{param}",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Templates =\n  %v\nwant:\n  %v", got, want)
	}
}

func TestConnectRPCTemplatesPreserveServiceAndMethod(t *testing.T) {
	calls := []Call{
		{Method: "POST", URL: "https://api.test/acme.v1.UserService/GetUser", Frame: "connect.js:8"},
		{Method: "POST", URL: "https://api.test/acme.v1.UserService/ListUsers", Frame: "connect.js:8"},
		{Method: "POST", URL: "https://api.test/acme.v1.UserService/GetSettings", Frame: "connect.js:8"},
		{Method: "POST", URL: "https://api.test/acme.v1.OrderService/GetRecord", Frame: "connect.js:9"},
		{Method: "POST", URL: "https://api.test/acme.v1.BillingService/GetRecord", Frame: "connect.js:9"},
		{Method: "POST", URL: "https://api.test/acme.v1.AuditService/GetRecord", Frame: "connect.js:9"},
	}
	got := Templates(calls)
	want := []string{
		"/acme.v1.UserService/GetUser",
		"/acme.v1.UserService/ListUsers",
		"/acme.v1.UserService/GetSettings",
		"/acme.v1.OrderService/GetRecord",
		"/acme.v1.BillingService/GetRecord",
		"/acme.v1.AuditService/GetRecord",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ConnectRPC Templates =\n  %v\nwant:\n  %v", got, want)
	}
}
