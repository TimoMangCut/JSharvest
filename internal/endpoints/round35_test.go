package endpoints

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func makeTestScript(sha, urlStr, code string) Script {
	res := jsapi.Extract([]byte(code))
	return Script{
		SHA256: sha,
		URLs:   []string{urlStr},
		Result: res,
	}
}

func TestCrossChunkServiceDIAndScopedStaticClassConstRef(t *testing.T) {
	// Chunk 0: shared HTTP wrapper service + static route dictionary.
	coreCode := `
var env = { BASE_URL: "https://api.portal.test" };
var Routes = class {
  static BASE_URL = env.BASE_URL;
  static LOGIN = "sso-login";
  static JOB_LIST = "jobs/published";
  static JOB_DETAIL = "jobs/detail";
  static DEACTIVATE_REMINDER = "candidate/deactivateReminder";
};
var HttpWrapper = class w {
  constructor(http) { this.http = http; }
  get(t) { return this.http.get(Routes.BASE_URL + "/" + t); }
  getByParams(t, n) { return this.http.get(Routes.BASE_URL + "/" + t, { params: n }); }
  getById(t, id) { return this.http.get(Routes.BASE_URL + "/" + t + "/" + id); }
  post(t, body) { return this.http.post(Routes.BASE_URL + "/" + t, body); }
  put(t, body) { return this.http.put(Routes.BASE_URL + "/" + t, body); }
  static \u0275fac = function(t) { return new (t || w)(injectHttp()); };
};
export { Routes as zc, HttpWrapper as Bc };
`
	// Unrelated chunk exporting the SAME minified alias `zc` with a conflicting value:
	// proves ConstRef resolution is strictly scoped to targetScripts(caller, "./chunk-core.js").
	unrelatedCode := `
var Other = class {
  static JOB_LIST = "wrong/collidedPath";
};
export { Other as zc };
`
	// Barrel chunk re-exporting zc and Bc.
	barrelCode := `export { zc, Bc } from "./chunk-core.js";`

	// Consumer chunk 1: Angular Ivy \u0275fac + constructor assignment + HttpParams .set() + template `${n.CONST}/${id}`.
	consumer1 := `
import { $b as HttpParams, y as ɵɵinject } from "./chunk-vendor.js";
import { Bc as Svc, zc as n } from "./chunk-barrel.js";
var JobController = class c {
  constructor(r) { this.httpClient = r; }
  loadJobs(filter) {
    let p = new HttpParams();
    if (filter.keyword) { p = p.set("keyword", filter.keyword); }
    p = p.append("department", filter.dept);
    return this.httpClient.getByParams(n.JOB_LIST, p);
  }
  loadOne(id) {
    return this.httpClient.getById(n.JOB_DETAIL, id);
  }
  login(creds) {
    return this.httpClient.post(n.LOGIN, creds);
  }
  deactivate(id) {
    return this.httpClient.put(` + "`${n.DEACTIVATE_REMINDER}/${id}`" + `, { reason: "expired" });
  }
  static \u0275fac = function(t) { return new (t || c)(ɵɵinject(Svc)); };
};
export { JobController as a };
`
	// Consumer chunk 2: Field initializer `api = inject(Svc)` and direct relative slug literal.
	consumer2 := `
import { inject } from "./chunk-vendor.js";
import { Bc as Svc } from "./chunk-core.js";
export class DirectFeature {
  api = inject(Svc);
  ping() {
    return this.api.get("health/check");
  }
}
`

	scripts := []Script{
		makeTestScript("sha-core", "https://app.portal.test/chunk-core.js", coreCode),
		makeTestScript("sha-other", "https://app.portal.test/chunk-unrelated.js", unrelatedCode),
		makeTestScript("sha-barrel", "https://app.portal.test/chunk-barrel.js", barrelCode),
		makeTestScript("sha-c1", "https://app.portal.test/chunk-jobs.js", consumer1),
		makeTestScript("sha-c2", "https://app.portal.test/chunk-direct.js", consumer2),
	}
	inScope := func(h string) bool {
		return h == "portal.test" || strings.HasSuffix(h, ".portal.test")
	}
	eps := Build(scripts, nil, inScope)

	got := map[string]Endpoint{}
	for _, ep := range eps {
		got[ep.Method+" "+ep.Host+" "+ep.Path] = ep
	}

	wantKeys := []string{
		"GET api.portal.test /jobs/published",
		"GET api.portal.test /jobs/detail/{}",
		"POST api.portal.test /sso-login",
		"PUT api.portal.test /candidate/deactivateReminder/{}",
		"GET api.portal.test /health/check",
	}
	for _, wk := range wantKeys {
		if _, ok := got[wk]; !ok {
			var all []string
			for k := range got {
				all = append(all, k)
			}
			slices.Sort(all)
			t.Fatalf("missing linked endpoint %q; got:\n%s", wk, strings.Join(all, "\n"))
		}
	}
	if _, collided := got["GET api.portal.test /wrong/collidedPath"]; collided {
		t.Fatal("unrelated module's minified export collided with scoped ConstRef")
	}
	jobListEP := got["GET api.portal.test /jobs/published"]
	if !slices.Contains(jobListEP.Query, "keyword") || !slices.Contains(jobListEP.Query, "department") {
		t.Fatalf("expected HttpParams .set/.append query keys on /jobs/published, got %v", jobListEP.Query)
	}
	deactEP := got["PUT api.portal.test /candidate/deactivateReminder/{}"]
	if !slices.Contains(deactEP.Body, "reason") {
		t.Fatalf("expected body key 'reason' on deactivate endpoint, got %v", deactEP.Body)
	}
}

func TestRebindDevLoopbackEndpoints(t *testing.T) {
	mainBundle := makeTestScript("sha-main", "https://app.portal.test/main.js", `
const cfg = {
  keycloakUrl: "https://sso.portal.test/realms/corp/users",
  delegationDev: "http://localhost:8027/delegations/pending"
};
fetch(cfg.delegationDev);
fetch("https://app.portal.test/delegations/pending?includeArchived=1");
`)
	ssoScript := makeTestScript("sha-sso", "https://sso.portal.test/resources/register.js", `
fetch("http://localhost:8081/realms/corp/users/change-email", { method: "PUT", body: JSON.stringify({ email: "a@b.c" }) });
`)
	thirdParty := Script{
		SHA256:     "sha-3p",
		URLs:       []string{"https://cdn.external-vendor.example/sdk.js"},
		ThirdParty: true,
		Result:     jsapi.Extract([]byte(`fetch("http://127.0.0.1:9222/json/version");`)),
	}

	publicScope := func(h string) bool {
		return h == "portal.test" || strings.HasSuffix(h, ".portal.test")
	}
	eps := Build([]Script{mainBundle, ssoScript, thirdParty}, nil, publicScope)

	byKey := map[string]Endpoint{}
	for _, ep := range eps {
		byKey[ep.Method+" "+ep.Host+" "+ep.Path] = ep
	}

	// 1. /delegations/pending rebound from localhost:8027 -> app.portal.test and merged with prod endpoint.
	delEP, ok := byKey["GET app.portal.test /delegations/pending"]
	if !ok {
		t.Fatalf("expected rebound & merged GET app.portal.test /delegations/pending, got %+v", eps)
	}
	if delEP.ThirdParty {
		t.Fatal("rebound first-party endpoint must not be marked ThirdParty")
	}
	if !slices.Contains(delEP.Query, "includeArchived") {
		t.Fatalf("canonicalMerge did not merge query params onto rebound endpoint: %+v", delEP)
	}
	if _, stillLocal := byKey["GET localhost:8027 /delegations/pending"]; stillLocal {
		t.Fatal("duplicate localhost:8027 endpoint remained after canonicalMerge")
	}

	// 2. /realms/corp/users/change-email matched longest base prefix -> sso.portal.test.
	ssoEP, ok := byKey["PUT sso.portal.test /realms/corp/users/change-email"]
	if !ok || ssoEP.ThirdParty {
		t.Fatalf("expected PUT sso.portal.test /realms/corp/users/change-email (in-scope), got %+v", byKey)
	}

	// 3. Out-of-scope third-party script's 127.0.0.1 call must NOT be rebound onto portal.test.
	if _, leaked := byKey["GET app.portal.test /json/version"]; leaked {
		t.Fatal("third-party script loopback URL must never be rebound onto first-party host")
	}

	// 4. When target scope itself is loopback (local testbeds), localhost must remain untouched.
	localScope := func(h string) bool { return h == "localhost" || h == "127.0.0.1" || publicScope(h) }
	localEps := Build([]Script{ssoScript}, nil, localScope)
	if len(localEps) != 1 || localEps[0].Host != "localhost:8081" {
		t.Fatalf("expected loopback host to stay localhost:8081 when loopback is in scope, got %+v", localEps)
	}
}
