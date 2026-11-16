package jsapi

import (
	"slices"
	"testing"
)

func TestRound31TerserInlineConcatAssign(t *testing.T) {
	src := `
function exportOrders(cond) {
	let t = "svc/v1/orders";
	if (cond) t += "/pending";
	t = "".concat(t += "/export", "?fmt=csv");
	return axios.get(t);
}
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("parse error: %s", r.Error)
	}
	got := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		got[e.Method+" "+e.URL] = e
	}
	for _, want := range []string{
		"GET svc/v1/orders/export",
		"GET svc/v1/orders/pending/export",
	} {
		ep, ok := got[want]
		if !ok {
			t.Errorf("missing %s; got %v", want, eps(src))
			continue
		}
		if !slices.Equal(ep.Query, []string{"fmt"}) {
			t.Errorf("%s: query=%v, want [fmt]", want, ep.Query)
		}
	}
	for url := range got {
		if url == "GET svc/v1/orders/export/export" || url == "GET svc/v1/orders/pending/export/export" {
			t.Errorf("duplicate /export suffix in %s; all=%v", url, eps(src))
		}
	}
}

func TestRound31TerserStandaloneAddEqNoBackwardLeak(t *testing.T) {
	src := `
function syncItems() {
	let t = "/api/v1/items";
	fetch("".concat(t += "/archive", "?all=1"));
	t += "/purged";
	fetch(t);
}
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("parse error: %s", r.Error)
	}
	got := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		got[e.Method+" "+e.URL] = e
	}
	ep1, ok1 := got["GET /api/v1/items/archive"]
	if !ok1 {
		t.Fatalf("missing GET /api/v1/items/archive; got %v", eps(src))
	}
	if !slices.Equal(ep1.Query, []string{"all"}) {
		t.Errorf("archive query=%v, want [all]", ep1.Query)
	}
	ep2, ok2 := got["GET /api/v1/items/archive/purged"]
	if !ok2 {
		t.Fatalf("missing GET /api/v1/items/archive/purged; got %v", eps(src))
	}
	if slices.Contains(ep2.Query, "all") {
		t.Errorf("later step leaked query from first fetch: %+v", ep2)
	}
	if len(got) != 2 {
		t.Errorf("unexpected extra endpoints: %v", eps(src))
	}
}

func TestRound31TerserInlineBindOrder(t *testing.T) {
	src := `
function runSeq() {
	let t = "/v1";
	fetch("".concat(t += "/a", "/b", t));
	t += "/later";
	fetch(t);

	let u = "/stale";
	fetch("".concat(u = "/api/v2", "/check", u));
}
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("parse error: %s", r.Error)
	}
	got := map[string]bool{}
	for _, e := range r.Endpoints {
		got[e.Method+" "+e.URL] = true
	}
	for _, want := range []string{
		"GET /v1/a/b/v1/a",
		"GET /v1/a/later",
		"GET /api/v2/check/api/v2",
	} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, eps(src))
		}
	}
	if got["GET /v1/a/b/v1/a/later"] {
		t.Errorf("later += leaked into inline expression: %v", eps(src))
	}
}

func TestRound31ArrayMapForEachOneStage(t *testing.T) {
	src := `
function batchOneStage() {
	["/api/v1/alpha", "/api/v1/beta"].map(u => axios.get(u));
	["/api/v1/users", "/api/v1/roles"].map(axios.get);
	[{ url: "/api/v1/one", method: "POST", data: { title: "x" } }, { url: "/api/v1/two" }].forEach(c => axios(c));
	[{ url: "/api/v1/a", method: "POST" }, { url: "/api/v1/b", method: "GET", params: { filter: 1 } }].forEach(cfg => axios.request(cfg));
}
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("parse error: %s", r.Error)
	}
	got := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		got[e.Method+" "+e.URL] = e
	}
	for _, want := range []string{
		"GET /api/v1/alpha",
		"GET /api/v1/beta",
		"GET /api/v1/users",
		"GET /api/v1/roles",
		"POST /api/v1/one",
		"GET /api/v1/two",
		"POST /api/v1/a",
		"GET /api/v1/b",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, eps(src))
		}
	}
	if ep, ok := got["POST /api/v1/one"]; ok && !slices.Equal(ep.Body, []string{"title"}) {
		t.Errorf("POST /api/v1/one body=%v, want [title]", ep.Body)
	}
	if ep, ok := got["GET /api/v1/b"]; ok && !slices.Equal(ep.Query, []string{"filter"}) {
		t.Errorf("GET /api/v1/b query=%v, want [filter]", ep.Query)
	}
}

func TestRound31ArrayMapTwoStageConfigForwarding(t *testing.T) {
	src := `
function reqHelper(c) {
	return axios.get(c.url, { params: c.params });
}
function reqConfigHelper(c) {
	return axios.request(c);
}
class MetricsClient {
	request(c) {
		return axios.get(c.url, { params: c.params });
	}
	fetchBatch(q) {
		["svc/v1/summary", "svc/v1/metrics"]
			.map(p => ({ url: p, params: { scope: q } }))
			.map(cfg => this.request(cfg));
		["svc/v1/alerts", "svc/v1/quotas"]
			.map(p => ({ url: p, params: { active: 1 } }))
			.map(this.request);
	}
}
export function loadDashboard() {
	["/api/v1/summary", "/api/v1/stats"]
		.map(u => ({ url: u, params: { page: 1 } }))
		.map(cfg => reqHelper(cfg));
	["/api/v1/audit", "/api/v1/health"]
		.map(e => ({ url: e, params: { limit: 10 } }))
		.forEach(e => reqConfigHelper(e));
}
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("parse error: %s", r.Error)
	}
	got := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		got[e.Method+" "+e.URL] = e
	}
	wantQueries := map[string][]string{
		"GET /api/v1/summary": {"page"},
		"GET /api/v1/stats":   {"page"},
		"GET /api/v1/audit":   {"limit"},
		"GET /api/v1/health":  {"limit"},
		"GET svc/v1/summary":  {"scope"},
		"GET svc/v1/metrics":  {"scope"},
		"GET svc/v1/alerts":   {"active"},
		"GET svc/v1/quotas":   {"active"},
	}
	for want, wq := range wantQueries {
		ep, ok := got[want]
		if !ok {
			t.Errorf("missing %s; got %v", want, eps(src))
			continue
		}
		if !slices.Equal(ep.Query, wq) {
			t.Errorf("%s: query=%v, want %v", want, ep.Query, wq)
		}
	}
}

func TestRound31ArrayMapBoundsAndNoise(t *testing.T) {
	src := `
const flags = ["/api/v1/flag1", "/api/v1/flag2"].map(Boolean);
const overLimit = [
	"/api/v1/p01", "/api/v1/p02", "/api/v1/p03", "/api/v1/p04", "/api/v1/p05",
	"/api/v1/p06", "/api/v1/p07", "/api/v1/p08", "/api/v1/p09", "/api/v1/p10",
	"/api/v1/p11", "/api/v1/p12", "/api/v1/p13", "/api/v1/p14", "/api/v1/p15",
	"/api/v1/p16", "/api/v1/p17", "/api/v1/p18"
].map(u => fetch(u));
`
	r := Extract([]byte(src))
	for _, e := range r.Endpoints {
		if e.Kind == "fetch" || e.Kind == "wrapper" {
			t.Errorf("unexpected call endpoint from bounded/non-http map: %+v", e)
		}
	}
}

func TestRound31AdditionalEdgeCases(t *testing.T) {
	src := `
class BatchService {
	sendOne(cfg) {
		return axios.request(cfg);
	}
	runAll() {
		const paths = ["/api/v1/nodes", "/api/v1/pods"];
		const configs = paths.map(p => ({ url: p, params: { ns: "default" } }));
		return Promise.all(configs.map(this.sendOne.bind(this)));
	}
}
export function extraPatterns(flag) {
	let t = "/api/v1/reports";
	t = ` + "`${(t) += \"/daily\"}?tz=utc`" + `;
	fetch(t);

	let s = "/api/v1/jobs";
	if (flag) fetch(s += "/active");
	else fetch(s += "/failed");
	fetch(s + "/count");

	const obj = { url: "/api/v1" };
	fetch(obj.url += "/ping");

	["/api/v1/direct-a", "/api/v1/direct-b"].map(fetch);
}
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("parse error: %s", r.Error)
	}
	got := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		got[e.Method+" "+e.URL] = e
	}
	for _, want := range []string{
		"GET /api/v1/nodes",
		"GET /api/v1/pods",
		"GET /api/v1/reports/daily",
		"GET /api/v1/jobs/active",
		"GET /api/v1/jobs/failed",
		"GET /api/v1/jobs/active/count",
		"GET /api/v1/jobs/failed/count",
		"GET /api/v1/ping",
		"GET /api/v1/direct-a",
		"GET /api/v1/direct-b",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, eps(src))
		}
	}
	if _, dup := got["GET /api/v1/reports/daily/daily"]; dup {
		t.Errorf("duplicate /daily in %v", eps(src))
	}
	if _, bare := got["GET /api/v1/jobs/count"]; bare {
		t.Errorf("both if/else branches assigned s, unexpected bare /api/v1/jobs/count: %v", eps(src))
	}
}
