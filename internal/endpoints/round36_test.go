package endpoints

import (
	"slices"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func TestRound36MultiHopWebpackConstResolutionZeroFanout(t *testing.T) {
	mainCode := `(self.webpackChunkportal=self.webpackChunkportal||[]).push([[792],{
		77747:(m,e,I)=>{"use strict";
			I.d(e,{c:()=>env});
			const env = {
				production: true,
				gateway: "https://gw.portal.test/api",
				sso: "https://sso.portal.test/realms/main"
			};
		},
		37554:(m,e,I)=>{"use strict";
			I.d(e,{G:()=>ApiService});
			class ApiService {
				constructor(http) { this.http = http; }
				get(u) { return this.http.get(u); }
				getWithParams(u, p) { return this.http.get(u, { params: p }); }
				post(u, b) { return this.http.post(u, b); }
			}
		},
		9000:(m,e,I)=>{"use strict";
			class Other {
				init(axios) {
					axios.create({ baseURL: "https://sso.portal.test/realms/main" });
					axios.create({ baseURL: "https://gw.portal.test/api/portal-notify-api" });
					axios.create({ baseURL: "/portal-form-api" });
					axios.create({ baseURL: "/portal-rule-api" });
				}
			}
		}
	}]);`

	routesChunk := `(self.webpackChunkportal=self.webpackChunkportal||[]).push([[824],{
		48377:(m,e,P)=>{"use strict";
			P.d(e,{P:()=>paths});
			const r = P(77747).c.gateway + "/portal-eval-api";
			const paths = {
				evalBase: r + "/review",
				filterUrl: r + "/review/filter"
			};
		}
	}]);`

	featureChunk := `(self.webpackChunkportal=self.webpackChunkportal||[]).push([[173],{
		1200:(m,e,u)=>{"use strict";
			var apiMod = u(37554);
			var routeMod = u(48377);
			let EvalSvc = (() => {
				class EvalSvc {
					constructor(api, http) {
						this.api = api;
						this.http = http;
						this.path = routeMod.P.evalBase;
					}
					listCriteria() {
						return this.api.getWithParams(this.path + "/criteria", { callId: 1 });
					}
					getDetail(id) {
						return this.api.get(this.path + "/detail/" + id);
					}
					runFilter() {
						return this.api.get(routeMod.P.filterUrl);
					}
					loadSchema() {
						return this.http.get("assets/activeSchema.json");
					}
				}
				EvalSvc.\u0275fac = function(t) { return new (t || EvalSvc)(u.ɵɵinject(apiMod.G), null); };
				return EvalSvc;
			})();
		}
	}]);`

	scripts := []Script{
		{SHA256: "main-sha", URLs: []string{"https://gw.portal.test/main.js"}, Result: jsapi.Extract([]byte(mainCode))},
		{SHA256: "routes-sha", URLs: []string{"https://gw.portal.test/824.chunk.js"}, Result: jsapi.Extract([]byte(routesChunk))},
		{SHA256: "feat-sha", URLs: []string{"https://gw.portal.test/173.chunk.js"}, Result: jsapi.Extract([]byte(featureChunk))},
	}
	inScope := func(h string) bool { return h == "gw.portal.test" || h == "sso.portal.test" }
	eps := Build(scripts, nil, inScope)

	byKey := map[string]Endpoint{}
	for _, ep := range eps {
		byKey[ep.Method+" "+ep.Host+" "+ep.Path] = ep
		if ep.Path == "{}/criteria" || ep.Path == "{}/detail/{}" || ep.Path == "{}/review/filter" {
			t.Errorf("phantom unresolved endpoint leaked into catalog: %+v", ep)
		}
	}

	for _, wantPath := range []string{
		"/api/portal-eval-api/review/criteria",
		"/api/portal-eval-api/review/detail/{}",
		"/api/portal-eval-api/review/filter",
	} {
		ep, ok := byKey["GET gw.portal.test "+wantPath]
		if !ok {
			t.Fatalf("missing resolved endpoint GET gw.portal.test %s; got catalog: %+v", wantPath, eps)
		}
		if len(ep.Bases) != 0 {
			t.Errorf("endpoint %s should have zero candidate Bases fan-out, got %v", wantPath, ep.Bases)
		}
	}

	tpl, ok := byKey["GET  /assets/activeSchema.json"]
	if !ok {
		t.Fatalf("missing /assets/activeSchema.json in %+v", eps)
	}
	if len(tpl.Bases) != 0 || tpl.Origin != "https://gw.portal.test" {
		t.Errorf("static webroot JSON = %+v, want Origin=https://gw.portal.test Bases=[]", tpl)
	}
}

func TestRound36CrossChunkWebpackBuilderAndSharedParentGateway(t *testing.T) {
	mainSrc := []byte(`(self.webpackChunkcat=self.webpackChunkcat||[]).push([[1],{
		5064(m,exports,O){"use strict";
			function buildQ(p, req=null, proj=null) {
				const clean = p.replace(/\{.*$/, "");
				if (!req) return clean;
				const q = { sort: req.s, size: req.n, page: req.p };
				return proj && (q.projection = proj), clean + "?" + Object.keys(q).join("&");
			}
			O.d(exports, { Y: () => buildQ });
		}
	}]);`)
	lazySrc := []byte(`(self.webpackChunkcat=self.webpackChunkcat||[]).push([[538],{
		538(m,exports,Q){"use strict";
			var h = Q(5064);
			class ItemService {
				constructor(http) {
					this.http = http;
					this._path = "/api/catalog/items";
				}
				search(req) {
					return this.http.get((0, h.Y)(this._path, req, "card"));
				}
			}
		}
	}]);`)

	scripts := []Script{
		{
			SHA256: "m1",
			URLs:   []string{"https://catalog.portal.test/main.js"},
			Result: jsapi.Extract(mainSrc),
			Load:   func() []byte { return mainSrc },
		},
		{
			SHA256: "c1",
			URLs:   []string{"https://catalog.portal.test/538.js"},
			Result: jsapi.Extract(lazySrc),
			Load:   func() []byte { return lazySrc },
		},
	}
	eps := Build(scripts, nil, func(string) bool { return true })
	var found *Endpoint
	for i := range eps {
		if eps[i].Path == "/api/catalog/items" {
			found = &eps[i]
		}
	}
	if found == nil {
		t.Fatalf("missing cross-chunk Webpack builder endpoint /api/catalog/items in %+v", eps)
	}
	for _, k := range []string{"page", "projection", "size", "sort"} {
		if !slices.Contains(found.Query, k) {
			t.Errorf("Query = %v, missing %q", found.Query, k)
		}
	}

	// Verify baseFor strips leading {} and infers shared parent gateway without sibling concatenation.
	bases := []string{
		"https://sso.portal.test/realms/main",
		"https://gw.portal.test/api/portal-notify-api",
		"/portal-form-api",
		"/portal-rule-api",
	}
	gotBases := baseFor(bases, "{}/portal-audit-api/logs", "client", nil)
	wantBases := []string{"https://gw.portal.test/api"}
	if !slices.Equal(gotBases, wantBases) {
		t.Fatalf("baseFor shared parent gateway = %v, want %v", gotBases, wantBases)
	}
}
