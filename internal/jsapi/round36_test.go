package jsapi

import (
	"slices"
	"strings"
	"testing"
)

func TestRound36SymbolicConstExportsAndWebrootJSON(t *testing.T) {
	chunkRoutes := `(self.webpackChunkapp=self.webpackChunkapp||[]).push([[824],{
		48377:(m,e,P)=>{"use strict";
			P.d(e,{P:()=>routes});
			const base = P(77747).c.gateway + "/svc-eval-api";
			const routes = {
				evalPath: base + "/review",
				filterUrl: base + "/review/filter"
			};
		}
	}]);`
	resRoutes := Extract([]byte(chunkRoutes))
	var foundEval, foundFilter string
	for _, cd := range resRoutes.ConstExports {
		if cd.Module == "48377" && cd.Export == "P" {
			foundEval = cd.Values["evalPath"]
			foundFilter = cd.Values["filterUrl"]
		}
	}
	if want := "$jsh_const[77747|c|gateway]/svc-eval-api/review"; foundEval != want {
		t.Fatalf("evalPath = %q, want %q (all ConstExports: %+v)", foundEval, want, resRoutes.ConstExports)
	}
	if want := "$jsh_const[77747|c|gateway]/svc-eval-api/review/filter"; foundFilter != want {
		t.Fatalf("filterUrl = %q, want %q", foundFilter, want)
	}

	chunkFeature := `(self.webpackChunkapp=self.webpackChunkapp||[]).push([[173],{
		9001:(m,e,u)=>{"use strict";
			var S = u(48377);
			class ReviewService {
				constructor(http) {
					this.http = http;
					this.path = S.P.evalPath;
				}
				getItem(id) {
					return this.http.get(this.path + "/items/" + id);
				}
				filterAll() {
					return this.http.get(S.P.filterUrl);
				}
				loadTemplate() {
					return this.http.get("assets/templates/default.json");
				}
			}
		}
	}]);`
	resFeat := Extract([]byte(chunkFeature))
	var gotItem, gotFilter, gotTpl *Endpoint
	for i := range resFeat.Endpoints {
		ep := &resFeat.Endpoints[i]
		switch {
		case ep.ConstRef != nil && ep.ConstRef.Key == "evalPath":
			gotItem = ep
		case ep.ConstRef != nil && ep.ConstRef.Key == "filterUrl":
			gotFilter = ep
		case strings.Contains(ep.URL, "assets/templates/default.json"):
			gotTpl = ep
		}
	}
	if gotItem == nil || gotItem.ConstSuffix != "/items/{}" {
		t.Fatalf("missing or wrong ConstRef on this.path + '/items/' + id: %+v (all: %+v)", gotItem, resFeat.Endpoints)
	}
	if gotFilter == nil || gotFilter.ConstSuffix != "" {
		t.Fatalf("missing bare ConstRef on S.P.filterUrl: %+v (all: %+v)", gotFilter, resFeat.Endpoints)
	}
	if gotTpl == nil || !gotTpl.NoInheritBase || gotTpl.Client {
		t.Fatalf("webroot JSON should set NoInheritBase=true Client=false, got %+v", gotTpl)
	}
}

func TestRound36IntraBundleWPURLBuilderAndSuperClassPath(t *testing.T) {
	bundle := `(self.webpackChunkcatalog=self.webpackChunkcatalog||[]).push([[8792],{
		5064(m,exports,O){"use strict";
			function buildUrl(basePath, req=null, proj=null) {
				const clean = basePath.replace(/^(http|https):\/\/[^\/]+\//, "/").replace(/\{.*$/, "");
				if (!req) return clean;
				const q = {
					sort: req.sortCol ? req.sortCol + ",asc" : void 0,
					size: req.pageSize,
					page: req.pageNumber ? req.pageNumber - 1 : void 0
				};
				return proj && (q.projection = proj), clean + "?" + Object.keys(q).map(k => k + "=" + q[k]).join("&");
			}
			O.d(exports, { Y: () => buildUrl });
		},
		2000(m,exports,O){"use strict";
			class BaseCrud {
				constructor(http, path) {
					this.http = http;
					this._path = path;
				}
				listAll() {
					return this.http.get(this._path);
				}
			}
			O.d(exports, { B: () => BaseCrud });
		},
		3000(m,exports,O){"use strict";
			var helper = O(5064);
			var baseMod = O(2000);
			class BookService extends baseMod.B {
				constructor(http) {
					super(http, "/api/books");
				}
				getByParams(p) {
					return this.http.get((0, helper.Y)(this._path, p, "summary"));
				}
				static {
					this.\u0275fac = function(t) { return new (t || BookService)(null); };
				}
			}
			class AuthorService extends baseMod.B {
				constructor(http) {
					super(http, "/api/authors");
				}
			}
		}
	}]);`
	res := Extract([]byte(bundle))
	byURL := map[string]Endpoint{}
	for _, ep := range res.Endpoints {
		byURL[ep.Method+" "+ep.URL] = ep
	}
	books, ok := byURL["GET /api/books"]
	if !ok {
		t.Fatalf("missing GET /api/books in %+v", res.Endpoints)
	}
	for _, wantQ := range []string{"page", "projection", "size", "sort"} {
		if !slices.Contains(books.Query, wantQ) {
			t.Errorf("GET /api/books Query = %v, missing %q", books.Query, wantQ)
		}
	}
	if _, ok := byURL["GET /api/authors"]; !ok {
		t.Errorf("missing inherited super() endpoint GET /api/authors in %+v", res.Endpoints)
	}
}

func TestRound36CyclicWebpackMemberClassExtendsDoesNotOverflow(t *testing.T) {
	src := `(self.webpackChunkcyc=self.webpackChunkcyc||[]).push([[1],{
		10(m,e,r){"use strict"; r.d(e,{A:()=>r(20).B}); },
		20(m,e,r){"use strict"; r.d(e,{B:()=>r(10).A}); },
		30(m,e,r){"use strict";
			var a = r(10);
			class Sub extends a.A {
				ping() { return fetch("/api/cyclic-safe"); }
			}
			new Sub().ping();
		}
	}]);`
	res := Extract([]byte(src))
	if len(res.Endpoints) == 0 || res.Endpoints[0].URL != "/api/cyclic-safe" {
		t.Fatalf("expected /api/cyclic-safe without stack overflow, got %+v", res)
	}
}

