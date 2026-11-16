package jsapi

import (
	"slices"
	"testing"
)

// Round 25B (3.1): parameter BindingObject destructuring, body destructuring,
// mutated options variable (o.data / o.params), and ${ctx.baseUrl}${endpoint}
// template split.
func TestRound25DestructureOptionsAndBaseSplit(t *testing.T) {
	src := `
function reqParam({ method, baseURL, endpoint, data, params }) {
	const opts = { method, baseURL, url: endpoint };
	if (method === "GET") opts.params = params;
	else opts.data = data;
	return axios.request(opts);
}
function reqBody(config) {
	const { method, baseURL, endpoint, body } = config;
	return fetch(` + "`${baseURL}${endpoint}`" + `, { method, body: JSON.stringify(body) });
}
function streamReq(ctx, path, payload) {
	return fetch(` + "`${ctx.baseUrl}${path}`" + `, { method: "POST", body: JSON.stringify(payload) });
}
reqParam({ method: "GET", baseURL: ctx.baseUrl, endpoint: "/v1/items", params: { page: 1, limit: 20 } });
reqParam({ method: "POST", baseURL: ctx.baseUrl, endpoint: "/v1/items", data: { title: "a", tags: t } });
reqBody({ method: "PATCH", baseURL: ctx.baseUrl, endpoint: "/v1/items/42", body: { archived: true } });
streamReq(ctx, "/ai/chat", { prompt: p, sessionId: s });
`
	r := Extract([]byte(src))
	got := byURL(r)

	assertEP := func(key string, wantQuery, wantBody []string) {
		t.Helper()
		ep, ok := got[key]
		if !ok {
			t.Fatalf("missing %s in %v", key, eps(src))
		}
		if wantQuery != nil && !slices.Equal(ep.Query, wantQuery) {
			t.Errorf("%s: query=%v, want %v", key, ep.Query, wantQuery)
		}
		if wantBody != nil && !slices.Equal(ep.Body, wantBody) {
			t.Errorf("%s: body=%v, want %v", key, ep.Body, wantBody)
		}
	}

	assertEP("GET {}/v1/items", []string{"limit", "page"}, nil)
	assertEP("POST {}/v1/items", nil, []string{"tags", "title"})
	assertEP("PATCH {}/v1/items/42", nil, []string{"archived"})
	assertEP("POST {}/ai/chat", nil, []string{"prompt", "sessionId"})
}

// Round 25B (3.1): multi-hop argStringAt (depth <= 8), optional omitted
// ternary branch selection, and HOF wrapper instantiation.
func TestRound25MultiHopOptionalTernaryAndHOF(t *testing.T) {
	src := `
function transport(ctx, method, path, payload) {
	const o = { method, baseURL: ctx.baseUrl, url: path };
	if (method === "GET") o.params = payload;
	else o.data = payload;
	return axios.request(o);
}
function hop1(ctx, m, p, d) { return transport(ctx, m, p, d); }
function hop2(ctx, m, p, d) { return hop1(ctx, m, p, d); }
function hop3(ctx, m, p, d) { return hop2(ctx, m, p, d); }
function hop4(ctx, p, d) { return hop3(ctx, "PATCH", p, d); }

function getTestRuns(ctx, wfId, runId) {
	return transport(ctx, "GET", runId ? ` + "`/workflows/${wfId}/test-runs/${runId}`" + ` : ` + "`/workflows/${wfId}/test-runs`" + `);
}

const createTagClient = (basePath) => ({
	getAll: (ctx, filters) => transport(ctx, "GET", basePath, filters),
	create: (ctx, body) => transport(ctx, "POST", basePath, body),
	byId: (ctx, id) => transport(ctx, "DELETE", ` + "`${basePath}/${id}`" + `),
});
const tagApi = createTagClient("/annotation-tags");

const makeEndpoint = (method, endpoint) => (ctx, data) => transport(ctx, method, endpoint, data);
const savePrefs = makeEndpoint("POST", "/source-control/preferences");

hop4(c, "/v1/deep", { enabled: true });
getTestRuns(c, wId);
getTestRuns(c, wId, rId);
tagApi.getAll(c, { withUsageCount: true });
tagApi.create(c, { name: "urgent" });
tagApi.byId(c, tid);
savePrefs(c, { branchName: "main", repoUrl: u });
`
	r := Extract([]byte(src))
	got := byURL(r)

	for _, want := range []string{
		"PATCH {}/v1/deep",
		"GET {}/workflows/{}/test-runs",
		"GET {}/workflows/{}/test-runs/{}",
		"GET {}/annotation-tags",
		"POST {}/annotation-tags",
		"DELETE {}/annotation-tags/{}",
		"POST {}/source-control/preferences",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, eps(src))
		}
	}
	if b := got["PATCH {}/v1/deep"].Body; !slices.Equal(b, []string{"enabled"}) {
		t.Errorf("hop4 body = %v, want [enabled]", b)
	}
	if q := got["GET {}/annotation-tags"].Query; !slices.Equal(q, []string{"withUsageCount"}) {
		t.Errorf("tagApi.getAll query = %v, want [withUsageCount]", q)
	}
	if b := got["POST {}/source-control/preferences"].Body; !slices.Equal(b, []string{"branchName", "repoUrl"}) {
		t.Errorf("savePrefs body = %v, want [branchName repoUrl]", b)
	}
}

// Round 25B (3.2): unified Export (ParamURL, ParamMethod, Via, Local),
// ReExports (export * / named re-export), and no dynBase leak into static calls.
func TestRound25ExportViaReExportAndNoDynBaseLeak(t *testing.T) {
	// Module C: parameterized transport leaf + an unrelated static fetch in the same file.
	modC := `
export async function request(config) {
	const { method, baseURL, endpoint, data } = config;
	return fetch(` + "`${baseURL}${endpoint}`" + `, { method, body: JSON.stringify(data) });
}
fetch("/healthz");
`
	rc := Extract([]byte(modC))
	gotC := byURL(rc)
	if _, ok := gotC["GET /healthz"]; !ok {
		t.Fatalf("unrelated static fetch polluted by dynBase: %v", eps(modC))
	}
	if len(rc.Exports) != 1 {
		t.Fatalf("modC exports = %+v, want 1", rc.Exports)
	}
	exc := rc.Exports[0]
	if exc.Name != "request" || !exc.ParamURL || exc.URLProp != "endpoint" || !exc.ParamMethod || exc.MethodProp != "method" || !exc.HasDynBase {
		t.Errorf("unexpected modC Export: %+v", exc)
	}

	// Module B: imports request from "./http" and exports post() via Export.Via,
	// plus re-exports * from "./extra" and named { helper as alias } from "./sub".
	modB := `
import { request } from "./http";
export * from "./extra";
export { rawHelper as aliasHelper } from "./sub";
export async function post(baseUrl, endpoint, payload) {
	return request({ method: "POST", baseURL: baseUrl, endpoint, data: payload });
}
`
	rb := Extract([]byte(modB))
	if len(rb.ReExports) != 2 {
		t.Fatalf("modB reExports = %+v, want 2", rb.ReExports)
	}
	if rb.ReExports[0] != (ReExport{Module: "./extra", All: true}) {
		t.Errorf("reExport[0] = %+v", rb.ReExports[0])
	}
	if rb.ReExports[1] != (ReExport{Module: "./sub", Name: "aliasHelper", Target: "rawHelper"}) {
		t.Errorf("reExport[1] = %+v", rb.ReExports[1])
	}
	if len(rb.Exports) != 1 || rb.Exports[0].Via == nil {
		t.Fatalf("modB exports = %+v, want 1 Via export", rb.Exports)
	}
	via := rb.Exports[0].Via
	if via.Module != "./http" || via.Name != "request" || len(via.Args) != 1 {
		t.Fatalf("unexpected Via: %+v", via)
	}
	// Because the call to request(...) inside post() is captured as Via, it must
	// not also emit a spurious unlinked Import call site.
	if len(rb.Imports) != 0 {
		t.Errorf("modB imports = %+v, want 0 (captured in Via)", rb.Imports)
	}
}

// Round 25D: optional path-segment ternary (`runId ? "/"+runId : ""`) must NOT
// emit the empty branch when the caller explicitly supplies a non-nullish arg,
// while still emitting the omitted branch when the caller omits the arg. Also
// verifies Line >= 1, Col >= 1, and non-empty Snippet on literal-less Import
// and CallExpr call sites after multi-pass cursor resets.
func TestRound25DSuppliedOptionalTernaryAndLocations(t *testing.T) {
	src := `import { post, makeRestApiRequest } from "@app/rest-client";

const EXT_API_BASE = "https://external.vendor.example/api";
const ONBOARDING_PATH = "/accounts/onboarding";

const getTestRunsEndpoint = (workflowId, runId) =>
	` + "`/workflows/${workflowId}/test-runs${runId ? `/${runId}` : ''}`" + `;

export async function listTestRuns(ctx, workflowId) {
	return await makeRestApiRequest(ctx, "GET", getTestRunsEndpoint(workflowId));
}

export async function getTestRun(ctx, params) {
	return await makeRestApiRequest(ctx, "GET", getTestRunsEndpoint(params.workflowId, params.runId));
}

export async function deleteTestRun(ctx, params) {
	return await makeRestApiRequest(ctx, "DELETE", getTestRunsEndpoint(params.workflowId, params.runId));
}

export async function submitOnboarding(instanceId, email) {
	return await post(EXT_API_BASE, ONBOARDING_PATH, { instance_id: instanceId, email });
}
`
	r := Extract([]byte(src))
	got := byURL(r)

	for _, want := range []string{
		"GET {}/workflows/{}/test-runs",
		"GET {}/workflows/{}/test-runs/{}",
		"DELETE {}/workflows/{}/test-runs/{}",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing expected endpoint %s in %v", want, eps(src))
		}
	}
	if _, bad := got["DELETE {}/workflows/{}/test-runs"]; bad {
		t.Errorf("phantom empty ternary branch leaked for DELETE: %v", eps(src))
	}

	for _, ep := range r.Endpoints {
		if ep.Line <= 0 || ep.Col <= 0 || ep.Snippet == "" {
			t.Errorf("endpoint %s %s has invalid location: line=%d col=%d snippet=%q",
				ep.Method, ep.URL, ep.Line, ep.Col, ep.Snippet)
		}
	}
	if len(r.Imports) == 0 {
		t.Fatalf("expected cross-module Imports, got 0")
	}
	foundPost := false
	for _, im := range r.Imports {
		if im.Line <= 0 || im.Col <= 0 || im.Snippet == "" {
			t.Errorf("Import %s.%s has invalid location: line=%d col=%d snippet=%q",
				im.Module, im.Name, im.Line, im.Col, im.Snippet)
		}
		if im.Name == "post" && len(im.Args) >= 2 {
			foundPost = true
			if !slices.Equal(im.Args[0].Values, []string{"https://external.vendor.example/api"}) {
				t.Errorf("post arg[0] values = %v, want [https://external.vendor.example/api]", im.Args[0].Values)
			}
			if !slices.Equal(im.Args[1].Values, []string{"/accounts/onboarding"}) {
				t.Errorf("post arg[1] values = %v, want [/accounts/onboarding]", im.Args[1].Values)
			}
		}
	}
	if !foundPost {
		t.Errorf("missing literal-less post(EXT_API_BASE, ONBOARDING_PATH) Import in %+v", r.Imports)
	}
}

// Round 25E: tdewolff/parse v2.8.20 rejects valid ES2015 arrow parameter
// destructuring with renamed property default + object default
// (`const f = ({ a: b = 1 } = { a: 1 }) => b;`). Verify both Extract and
// ExtractSource lower arrows cleanly via esbuild with exact VLQ line mapping.
func TestRound25EArrowDestructuringDefaultParseEscapeHatch(t *testing.T) {
	jsBundle := []byte(`// line 1
const f = ({ a: b = 1 } = { a: 1 }) => b;
const send = (path, payload) => fetch("/api/v2" + path, {
	method: "POST",
	body: JSON.stringify(payload),
});
class ClientSvc {
	saveAll(items) {
		return items.map((it) => this.saveOne(it));
	}
	saveOne(item) {
		return send("/realms/users", { username: item.u, enabled: f() });
	}
}
`)
	for _, tc := range []struct {
		name string
		res  Result
	}{
		{"Extract", Extract(jsBundle)},
		{"ExtractSourceJS", ExtractSource(jsBundle, "https://app.example/assets/index-Cqtr7vCN.js")},
	} {
		r := tc.res
		if r.Error != "" {
			t.Fatalf("%s failed on valid ES2015 arrow destructuring: %s", tc.name, r.Error)
		}
		if !r.ASTLowered {
			t.Errorf("%s expected ASTLowered=true, got false", tc.name)
		}
		var found *Endpoint
		for i := range r.Endpoints {
			if r.Endpoints[i].Method == "POST" && r.Endpoints[i].URL == "/api/v2/realms/users" {
				found = &r.Endpoints[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("%s lost AST wrapper endpoint POST /api/v2/realms/users: %+v", tc.name, r.Endpoints)
		}
		if !slices.Equal(found.Body, []string{"enabled", "username"}) {
			t.Errorf("%s body = %v, want [enabled username]", tc.name, found.Body)
		}
		if found.Line != 12 {
			t.Errorf("%s VLQ line = %d, want 12 (saveOne call line)", tc.name, found.Line)
		}
	}

	tsSrc := []byte(`interface Opts { a?: number }
const f = ({ a: b = 1 }: Opts = { a: 1 }): number => b;
export const check = () => fetch("/api/ts-ok?v=" + f());
`)
	rt := ExtractSource(tsSrc, "src/check.ts")
	if rt.Error != "" || !rt.ASTLowered || len(rt.Endpoints) != 1 || rt.Endpoints[0].URL != "/api/ts-ok" || rt.Endpoints[0].Line != 3 {
		t.Fatalf("ExtractSource TS arrow destructuring failed: %+v", rt)
	}
}


