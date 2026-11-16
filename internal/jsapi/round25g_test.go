package jsapi

import (
	"slices"
	"testing"
)

func TestRound25GReactivePropBasesAndRSQLQuery(t *testing.T) {
	// 1. Vue/Pinia reactive store (`ref` + `computed` + `window.BASE_PATH`) and
	// non-isBaseName properties (`authServer`, `customGw`, `host`) populate PropBases
	// without mutating bare-string extraction (`x.used`).
	storeSrc := []byte(`
		var { VUE_APP_URL_BASE_API: envBase } = {};
		const state = ref({
			baseUrl: envBase ?? window.BASE_PATH,
			restEndpoint: getMeta("rest-endpoint") ?? "rest",
		});
		const restUrl = computed(() => ` + "`${state.value.baseUrl}${state.value.restEndpoint}`" + `);
		const restApiContext = computed(() => ({ baseUrl: restUrl.value }));
		const templatesHost = computed(() => state.value.templates?.host ?? "");
		const client = { authServer: "https://auth.app.test/v1" };
		client.customGw = "/gw-internal";
		const analytics = { host: "https://analytics.third.test" };
		const router = [{ path: "/signin", component: SigninView }];
		const unusedApi = "/api/v1/bare-preserved";
	`)
	r := Extract(storeSrc)
	if r.Error != "" {
		t.Fatalf("Extract failed: %s", r.Error)
	}
	pb := map[string][]string{}
	for _, h := range r.PropBases {
		pb[h.Name] = append(pb[h.Name], h.Value)
	}
	if !slices.Equal(pb["baseUrl"], []string{"/rest"}) {
		t.Errorf("PropBases[baseUrl] = %v, want [/rest]", pb["baseUrl"])
	}
	if !slices.Equal(pb["authServer"], []string{"https://auth.app.test/v1"}) {
		t.Errorf("PropBases[authServer] = %v, want [https://auth.app.test/v1]", pb["authServer"])
	}
	if !slices.Equal(pb["customGw"], []string{"/gw-internal"}) {
		t.Errorf("PropBases[customGw] = %v, want [/gw-internal]", pb["customGw"])
	}
	if !slices.Equal(pb["host"], []string{"https://analytics.third.test"}) {
		t.Errorf("PropBases[host] = %v, want [https://analytics.third.test]", pb["host"])
	}
	if len(pb["templatesHost"]) != 0 {
		t.Errorf("expected empty templatesHost to produce no PropBases, got %v", pb["templatesHost"])
	}
	if len(pb["path"]) != 0 {
		t.Errorf("expected router path to produce no PropBases, got %v", pb["path"])
	}
	foundBare := false
	for _, ep := range r.Endpoints {
		if ep.Kind == "string" && ep.URL == "/api/v1/bare-preserved" {
			foundBare = true
		}
	}
	if !foundBare {
		t.Errorf("expected bare string /api/v1/bare-preserved to remain unconsumed by settlePropBases, got %+v", r.Endpoints)
	}

	// 2. RSQL query string with single quotes in a call argument vs bare prose string.
	rsqlSrc := []byte(`
		function fetchReport(n, e, a, o) {
			var t = "/charge-point/v1.0/transactions/admin/report-on-day?query=";
			t = "".concat(t, "type=='TRANSACTION';createdTimestamp=ge='").concat(a, "T00:00:00Z';createdTimestamp=lt='").concat(o, "T00:00:00Z'&size=").concat(e.perPage, "&page=").concat(e.currentPage - 1);
			return n.$gateway.get(t);
		}
		var prose = "/api/v1/not-an-endpoint?why=it's a sentence";
	`)
	r2 := Extract(rsqlSrc)
	if r2.Error != "" {
		t.Fatalf("Extract rsql failed: %s", r2.Error)
	}
	var gotReport *Endpoint
	for i := range r2.Endpoints {
		ep := &r2.Endpoints[i]
		if ep.URL == "/api/v1/not-an-endpoint" {
			t.Errorf("bare prose string with quotes/spaces after '?' should be rejected, got %+v", *ep)
		}
		if ep.Method == "GET" && ep.URL == "/charge-point/v1.0/transactions/admin/report-on-day" {
			gotReport = ep
		}
	}
	if gotReport == nil {
		t.Fatalf("missed GET /charge-point/v1.0/transactions/admin/report-on-day; endpoints=%+v", r2.Endpoints)
	}
	if !slices.Equal(gotReport.Query, []string{"page", "query", "size"}) {
		t.Errorf("report-on-day query = %v, want [page query size]", gotReport.Query)
	}
}
