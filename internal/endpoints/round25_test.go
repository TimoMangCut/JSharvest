package endpoints

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// Round 25B (3.2 & 3.3): 3-module Via chain across SourceMap virtual paths
// (#packages/@app/http/src/...), barrel export * from, @/ alias + monorepo
// package specifier resolution, cycle guard, and empty/{} URL rejection.
func TestRound25ThreeModuleViaChainAndBarrel(t *testing.T) {
	mkSource := func(sha, vpath, code string) Script {
		return Script{
			SHA256: sha,
			URLs:   []string{"https://app.example.com/assets/index.js#" + vpath},
			Source: true,
			Result: jsapi.ExtractSource([]byte(code), vpath),
		}
	}

	// File C: low-level transport leaf in monorepo package @app/http.
	fileC := mkSource("c", "packages/@app/http/src/transport.ts", `
export interface ReqOpts {
	method: "GET" | "POST" | "PATCH" | "DELETE";
	baseURL: string;
	endpoint: string;
	data?: Record<string, unknown>;
	params?: Record<string, unknown>;
}
export async function rawRequest(config: ReqOpts) {
	const { method, baseURL, endpoint, data, params } = config;
	const o: any = { method, baseURL, url: endpoint };
	if (method === "GET") o.params = params;
	else o.data = data;
	return axios.request(o);
}
`)

	// File B1: 2-arg helpers calling rawRequest (Via hop 1).
	fileB1 := mkSource("b1", "packages/@app/http/src/helpers.ts", `
import { rawRequest } from "./transport";
export async function get<T>(baseUrl: string, endpoint: string, params?: Record<string, unknown>): Promise<T> {
	return rawRequest({ method: "GET", baseURL: baseUrl, endpoint, params }) as Promise<T>;
}
export async function post<T>(baseUrl: string, endpoint: string, data?: Record<string, unknown>): Promise<T> {
	return rawRequest({ method: "POST", baseURL: baseUrl, endpoint, data }) as Promise<T>;
}
`)

	// File B2: barrel index.ts re-exporting helpers + a domain wrapper adding a prefix (Via hop 2).
	fileB2 := mkSource("b2", "packages/@app/http/src/index.ts", `
export * from "./helpers";
import { post } from "./helpers";
export async function postAdmin(ctx: { baseUrl: string }, subPath: string, body: Record<string, unknown>) {
	return post(ctx.baseUrl, "/admin" + subPath, body);
}
`)

	// Cyclic re-export pair (cycleA <-> cycleB) to verify DFS cycle termination.
	cycleA := mkSource("ca", "src/api/cycleA.ts", `
export * from "./cycleB";
export function loopFn(x: string) { return loopOther(x); }
import { loopOther } from "./cycleB";
`)
	cycleB := mkSource("cb", "src/api/cycleB.ts", `
export * from "./cycleA";
import { loopFn } from "./cycleA";
export function loopOther(x: string) { return loopFn(x); }
`)

	// File A: caller importing from monorepo package "@app/http" and "@/api/cycleA",
	// plus an all-placeholder dynamic call get(ctx.baseUrl, dynamicVar) that must be rejected.
	fileA := mkSource("a", "src/api/users.ts", `
import { get, post, postAdmin } from "@app/http";
import { loopFn } from "@/api/cycleA";

export async function listUsers(ctx: { baseUrl: string }) {
	return await get(ctx.baseUrl, "/v1/users", { page: 1, limit: 50 });
}
export async function createUser(ctx: { baseUrl: string }, email: string, role: string) {
	return await post(ctx.baseUrl, "/v1/users", { email, role });
}
export async function resetMfa(ctx: { baseUrl: string }, userId: string) {
	return await postAdmin(ctx, ` + "`/users/${userId}/mfa-reset`" + `, { reason: "support" });
}
export async function dynamicOnly(ctx: { baseUrl: string }, target: string) {
	loopFn(target);
	return await get(ctx.baseUrl, target);
}
`)

	// Active bundle providing the concrete baseURL "/rest" and calling /v1/users via dynamic-base wrapper.
	bundle := Script{
		SHA256: "bundle",
		URLs:   []string{"https://app.example.com/assets/index.js"},
		Source: false,
		Result: jsapi.Extract([]byte(`
			axios.create({ baseURL: "/rest" });
			function req(ctx, m, p) { return axios.request({ method: m, baseURL: ctx.baseUrl, url: p }); }
			req(c, "GET", "/v1/users");
		`)),
	}

	catalog := Build([]Script{bundle, fileC, fileB1, fileB2, cycleA, cycleB, fileA}, nil, inExample)
	byKey := map[string]Endpoint{}
	for _, ep := range catalog {
		byKey[ep.Method+" "+ep.Path] = ep
	}

	if ep, ok := byKey["GET {}/v1/users"]; !ok {
		t.Fatalf("missing GET {}/v1/users in catalog: %+v", byKey)
	} else {
		if !slices.Equal(ep.Bases, []string{"/rest"}) {
			t.Errorf("GET {}/v1/users bases = %v, want [/rest]", ep.Bases)
		}
		if !slices.Equal(ep.Query, []string{"limit", "page"}) {
			t.Errorf("GET {}/v1/users query = %v, want [limit page]", ep.Query)
		}
		// Present in both active bundle and sourcemap -> SourceOnly must be false!
		if ep.SourceOnly {
			t.Errorf("GET {}/v1/users should not be SourceOnly (present in bundle)")
		}
	}

	if ep, ok := byKey["POST {}/v1/users"]; !ok {
		t.Fatalf("missing POST {}/v1/users in catalog: %+v", byKey)
	} else {
		if !slices.Equal(ep.Bases, []string{"/rest"}) {
			t.Errorf("POST {}/v1/users bases = %v, want [/rest]", ep.Bases)
		}
		if !slices.Equal(ep.Body, []string{"email", "role"}) {
			t.Errorf("POST {}/v1/users body = %v, want [email role]", ep.Body)
		}
		// Present only in sourcemap -> SourceOnly must be true!
		if !ep.SourceOnly {
			t.Errorf("POST {}/v1/users should be SourceOnly")
		}
		// Line number in users.ts: createUser calls post(...) on line 9.
		hasLine9 := false
		for _, st := range ep.Static {
			if st.Line == 9 {
				hasLine9 = true
			}
		}
		if !hasLine9 {
			t.Errorf("expected caller line 9 in Static, got %+v", ep.Static)
		}
	}

	if ep, ok := byKey["POST {}/admin/users/{}/mfa-reset"]; !ok {
		t.Fatalf("missing 3-hop POST {}/admin/users/{}/mfa-reset in catalog: %+v", byKey)
	} else if !slices.Equal(ep.Bases, []string{"/rest"}) || !slices.Equal(ep.Body, []string{"reason"}) {
		t.Errorf("mfa-reset bases=%v body=%v, want [/rest] [reason]", ep.Bases, ep.Body)
	}

	// Ensure empty / all-placeholder URLs ("", "{}", "{}/{}") were rejected.
	for k := range byKey {
		if k == "GET /rest" || k == "GET /rest/{}" || k == "GET {}" || k == "GET {}/{}" {
			t.Errorf("bogus placeholder endpoint leaked into catalog: %s", k)
		}
	}
}

// Round 25B (3.4): SourceOnly is set iff all static sources come from
// SourceMap virtual files AND there is no Observed traffic.
func TestRound25SourceOnlyClassification(t *testing.T) {
	scripts := []Script{
		{
			SHA256: "bundle",
			URLs:   []string{"https://app.example.com/app.js"},
			Source: false,
			Result: jsapi.Extract([]byte(`
				fetch("/api/active-both");
				fetch("/api/bundle-only");
			`)),
		},
		{
			SHA256: "smap",
			URLs:   []string{"https://app.example.com/app.js#src/api.ts"},
			Source: true,
			Result: jsapi.ExtractSource([]byte(`
				fetch("/api/active-both");
				fetch("/api/treeshaken-only", { method: "DELETE" });
				fetch("/api/smap-but-observed");
			`), "src/api.ts"),
		},
	}
	reqs := []Request{
		{Method: "GET", URL: "https://app.example.com/api/smap-but-observed", Status: 200},
	}

	got := map[string]Endpoint{}
	for _, ep := range Build(scripts, reqs, inExample) {
		got[ep.Method+" "+ep.Path] = ep
	}

	cases := map[string]bool{
		"GET /api/active-both":          false,
		"GET /api/bundle-only":          false,
		"GET /api/smap-but-observed":    false,
		"DELETE /api/treeshaken-only":   true,
	}
	for key, wantSourceOnly := range cases {
		ep, ok := got[key]
		if !ok {
			t.Fatalf("missing %s in %+v", key, got)
		}
		if ep.SourceOnly != wantSourceOnly {
			t.Errorf("%s: SourceOnly=%v, want %v", key, ep.SourceOnly, wantSourceOnly)
		}
	}
}

// Round 25D: provenance-scoped base resolution and module constant base URLs:
//  1. Cross-module constant out-of-scope base (`https://api.vendor.io/api` + `/accounts/onboarding`)
//     resolves to `Host: "api.vendor.io"`, `Path: "/api/accounts/onboarding"`, `ThirdParty: true`
//     (never inheriting target `/rest`).
//  2. Secondary host settings (`settingsStore.templatesHost`) and unbound wrapper
//     parameters (`testHealth(apiEndpoint)`) NEVER inherit `/rest` from `s.Bases`
//     or observed `/rest/...` traffic, while `ctx.baseUrl` endpoints DO inherit `/rest`.
//  3. All cross-module `Import` sources carry `Line >= 1`, `Col >= 1`, and non-empty `Snippet`.
func TestRound25DBaseProvenanceAndThirdPartyModuleBase(t *testing.T) {
	mkBundle := func(sha, name, code string) Script {
		return Script{
			SHA256: sha,
			URLs:   []string{"https://app.example.com/assets/" + name},
			Source: false,
			Result: jsapi.Extract([]byte(code)),
		}
	}

	transport := mkBundle("u1", "transport.js", `
async function request(config) {
	const { method, baseURL, endpoint, data } = config;
	const o = { method, url: endpoint, baseURL };
	if (method === "GET") o.params = data;
	else o.data = data;
	return axios.request(o);
}
export async function makeRestApiRequest(context, method, endpoint, data) {
	return request({ method, baseURL: context.baseUrl, endpoint, data });
}
export async function get(baseURL, endpoint, params) {
	return request({ method: "GET", baseURL, endpoint, data: params });
}
export async function post(baseURL, endpoint, data) {
	return request({ method: "POST", baseURL, endpoint, data });
}
export const defaultRestBase = { restEndpoint: "/rest" };
axios.create({ baseURL: "/rest" });
`)

	templatesMod := mkBundle("u2", "templates.js", `
import { get } from "./transport.js";
export async function testHealthEndpoint(apiEndpoint) {
	return await get(apiEndpoint, "/health");
}
export async function getCategories(apiEndpoint) {
	return await get(apiEndpoint, "/templates/categories");
}
`)

	appStore := mkBundle("u3", "store.js", `
import { makeRestApiRequest, post } from "./transport.js";
import { getCategories } from "./templates.js";

const VENDOR_API_BASE = "https://api.vendor.io/api";
const ONBOARDING_EP = "/accounts/onboarding";

export async function fetchSettings(ctx) {
	return await makeRestApiRequest(ctx, "GET", "/settings");
}
export async function fetchWorkflows(ctx) {
	return await makeRestApiRequest(ctx, "GET", "/workflows");
}
export async function loadTemplateCategories(settingsStore) {
	const apiEndpoint = settingsStore.templatesHost;
	return await getCategories(apiEndpoint);
}
export async function sendOnboarding(email) {
	return await post(VENDOR_API_BASE, ONBOARDING_EP, { email });
}
`)

	reqs := []Request{
		{Method: "GET", URL: "https://app.example.com/rest/settings", ResourceType: "XHR", Status: 200},
	}

	catalog := Build([]Script{transport, templatesMod, appStore}, reqs, inExample)
	byFullKey := map[string]Endpoint{}
	for _, ep := range catalog {
		byFullKey[ep.Method+" "+ep.Host+" "+ep.Path] = ep
		for _, st := range ep.Static {
			if st.Line <= 0 || st.Col <= 0 || st.Snippet == "" {
				t.Errorf("endpoint %s %s %s has incomplete source location: %+v",
					ep.Method, ep.Host, ep.Path, st)
			}
		}
	}

	// 1. Third-party constant base resolved to concrete out-of-scope host + ThirdParty: true.
	if ep, ok := byFullKey["POST api.vendor.io /api/accounts/onboarding"]; !ok {
		t.Fatalf("missing third-party POST api.vendor.io /api/accounts/onboarding in %+v", byFullKey)
	} else if !ep.ThirdParty {
		t.Errorf("expected POST api.vendor.io /api/accounts/onboarding to have ThirdParty=true")
	}
	if _, bad := byFullKey["POST  {}/accounts/onboarding"]; bad {
		t.Errorf("POST {}/accounts/onboarding leaked as relative target endpoint")
	}

	// 2. Primary `ctx.baseUrl` endpoint (`/workflows`) inherits `/rest`.
	if ep, ok := byFullKey["GET  {}/workflows"]; !ok {
		t.Fatalf("missing GET {}/workflows in %+v", byFullKey)
	} else if len(ep.Bases) == 0 {
		t.Errorf("GET {}/workflows should inherit /rest base, got Bases=%v Base=%q", ep.Bases, ep.Base)
	}

	// 3. `templatesHost` and unbound `apiEndpoint` endpoints MUST NOT inherit `/rest`!
	for _, k := range []string{"GET  {}/templates/categories", "GET  {}/health"} {
		ep, ok := byFullKey[k]
		if !ok {
			t.Fatalf("missing %s in %+v", k, byFullKey)
		}
		if ep.Base != "" || len(ep.Bases) != 0 {
			t.Errorf("%s falsely inherited target base: Base=%q Bases=%v", k, ep.Base, ep.Bases)
		}
	}
}

func TestRound25DViaIntermediateQueryAndBodyKeys(t *testing.T) {
	mkSmap := func(sha, vpath, code string) Script {
		u := "https://app.example.com/assets/bundle.js.map#" + vpath
		return Script{
			SHA256: sha,
			URLs:   []string{u},
			Source: true,
			Result: jsapi.ExtractSource([]byte(code), u),
		}
	}
	httpTS := mkSmap("v1", "packages/@app/client/src/http.ts", `
export interface ReqOpts { method: string; baseURL: string; endpoint: string; data?: unknown; params?: unknown }
export async function rawRequest<T>(config: ReqOpts): Promise<T> {
	const { method, baseURL, endpoint, data, params } = config;
	const init: RequestInit = { method };
	if (data !== undefined) init.body = JSON.stringify(data);
	void params;
	return (await fetch(`+"`${baseURL}${endpoint}`"+`, init)).json() as Promise<T>;
}
`)
	helpersTS := mkSmap("v2", "packages/@app/client/src/helpers.ts", `
import { rawRequest } from "./http";
export async function get<T>(baseUrl: string, endpoint: string, params?: Record<string, unknown>): Promise<T> {
	return await rawRequest<T>({ method: "GET", baseURL: baseUrl, endpoint, params });
}
export async function post<T>(baseUrl: string, endpoint: string, data?: Record<string, unknown>): Promise<T> {
	return await rawRequest<T>({ method: "POST", baseURL: baseUrl, endpoint, data });
}
`)
	indexTS := mkSmap("v3", "packages/@app/client/src/index.ts", `
export * from "./helpers";
`)
	apiTS := mkSmap("v4", "src/api/workflows.api.ts", `
import { get, post } from "@app/client";
export async function listWorkflows(ctx: { baseUrl: string }) {
	return await get(ctx.baseUrl, "/v1/workflows", { active: true, limit: 25 });
}
export async function createWorkflow(ctx: { baseUrl: string }, name: string, nodes: unknown[]) {
	return await post(ctx.baseUrl, "/v1/workflows", { name, nodes });
}
`)
	catalog := Build([]Script{httpTS, helpersTS, indexTS, apiTS}, nil, inExample)
	byMP := map[string]Endpoint{}
	for _, ep := range catalog {
		byMP[ep.Method+" "+ep.Path] = ep
	}
	if g, ok := byMP["GET {}/v1/workflows"]; !ok || !slices.Equal(g.Query, []string{"active", "limit"}) {
		t.Errorf("GET {}/v1/workflows = %+v, want query [active limit]", g)
	}
	if p, ok := byMP["POST {}/v1/workflows"]; !ok || !slices.Equal(p.Body, []string{"name", "nodes"}) {
		t.Errorf("POST {}/v1/workflows = %+v, want body [name nodes]", p)
	}
}

// Round 25E:
//  1. Call-site base expression matching without any hardcoded property allowlist:
//     - `ctx.host` (secondary analytics host) MUST NOT inherit `/rest` even when
//       `/rest` is in `s.Bases` and observed on `ctx.baseUrl`.
//     - `client.authServer` (custom-named primary API base) MUST inherit `/auth-api`
//       across sibling `client.authServer` calls when observed on `/auth-api/session`.
//  2. Corrupted/unparseable JS bundles fall back to `ExtractLoose` (never silently
//     dropped) and report `BundleParseErrors` + `FailedBundles` in `CatalogWithStats`.
func TestRound25EExpressionMatchedBaseAndBundleLooseFallback(t *testing.T) {
	mkBundle := func(sha, origin, name, code string) Script {
		return Script{
			SHA256: sha,
			URLs:   []string{origin + "/assets/" + name},
			Source: false,
			Result: jsapi.Extract([]byte(code)),
		}
	}

	// Origin 1 (`app.example.com`): `ctx.baseUrl` observed at `/rest/settings`,
	// while `ctx.host` is used for analytics — `ctx.host` must NOT get `/rest`.
	app1 := mkBundle("a1", "https://app.example.com", "main.js", `
function req(baseURL, method, endpoint) {
	return axios.request({ method, baseURL, url: endpoint });
}
export function loadSettings(ctx) { return req(ctx.baseUrl, "GET", "/settings"); }
export function loadUsers(ctx) { return req(ctx.baseUrl, "GET", "/users"); }
export function sendAnalytics(ctx) { return req(ctx.host, "POST", "/events/track"); }
`)
	// Origin 2 (`auth.example.com`): custom primary base name `client.authServer`
	// observed at `/auth-api/session` — sibling `client.authServer` call `/users`
	// MUST inherit `https://auth.example.com/auth-api`.
	app2 := mkBundle("a2", "https://auth.example.com", "auth.js", `
function callApi(serverBase, method, path) {
	return fetch(serverBase + path, { method });
}
export function checkSession(client) { return callApi(client.authServer, "GET", "/session"); }
export function createAccount(client) { return callApi(client.authServer, "POST", "/accounts"); }
export function pingTelemetry(client) { return callApi(client.telemetryServer, "POST", "/metrics"); }
`)

	reqs := []Request{
		{Method: "GET", URL: "https://app.example.com/rest/settings", ResourceType: "XHR", Status: 200},
		{Method: "GET", URL: "https://auth.example.com/auth-api/session", ResourceType: "Fetch", Status: 200},
	}

	inScope := func(h string) bool { return h == "example.com" || strings.HasSuffix(h, ".example.com") }
	got := Build([]Script{app1, app2}, reqs, inScope)
	byMP := map[string]Endpoint{}
	for _, ep := range got {
		byMP[ep.Method+" "+ep.Path] = ep
	}

	if u, ok := byMP["GET {}/users"]; !ok || !slices.Equal(u.Bases, []string{"https://app.example.com/rest"}) {
		t.Errorf("ctx.baseUrl sibling GET {}/users = %+v, want Bases [https://app.example.com/rest]", u)
	}
	if tr, ok := byMP["POST {}/events/track"]; !ok {
		t.Fatalf("missing POST {}/events/track in %+v", byMP)
	} else if tr.Base != "" || len(tr.Bases) != 0 {
		t.Errorf("ctx.host analytics endpoint falsely inherited /rest: Base=%q Bases=%v", tr.Base, tr.Bases)
	}

	if acc, ok := byMP["POST {}/accounts"]; !ok || !slices.Equal(acc.Bases, []string{"https://auth.example.com/auth-api"}) {
		t.Errorf("client.authServer sibling POST {}/accounts = %+v, want Bases [https://auth.example.com/auth-api]", acc)
	}
	if met, ok := byMP["POST {}/metrics"]; !ok {
		t.Fatalf("missing POST {}/metrics in %+v", byMP)
	} else if met.Base != "" || len(met.Bases) != 0 {
		t.Errorf("client.telemetryServer endpoint falsely inherited /auth-api: Base=%q Bases=%v", met.Base, met.Bases)
	}

	// Verify corrupted bundle falls back to ExtractLoose and reports BundleParseErrors.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "js"), 0o700); err != nil {
		t.Fatal(err)
	}
	corrupted := []byte("function broken( { return fetch('/api/v1/rescued-from-broken-bundle', { method: 'POST' }); @@@")
	sum := sha256.Sum256(corrupted)
	sha := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, "js", sha+".js"), corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	ent, _ := json.Marshal(store.Entry{
		SHA256: sha,
		URLs:   []string{"https://app.example.com/assets/broken-bundle.js"},
	})
	if err := os.WriteFile(filepath.Join(dir, "index.jsonl"), append(ent, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	eps, st, err := CatalogWithStats(dir, inScope, true)
	if err != nil {
		t.Fatalf("CatalogWithStats error: %v", err)
	}
	if st.BundleParseErrors != 1 || len(st.FailedBundles) != 1 || !strings.HasSuffix(st.FailedBundles[0], "broken-bundle.js") {
		t.Errorf("unexpected AnalyzeStats for broken bundle: %+v", st)
	}
	foundRescued := false
	for _, ep := range eps {
		if ep.Method == "POST" && ep.Path == "/api/v1/rescued-from-broken-bundle" {
			foundRescued = true
		}
	}
	if !foundRescued {
		t.Errorf("ExtractLoose fallback did not rescue POST /api/v1/rescued-from-broken-bundle: %+v", eps)
	}
}



