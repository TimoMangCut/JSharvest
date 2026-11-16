package endpoints

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func TestRound25GStaticBasesWithoutTrafficOrIsBaseName(t *testing.T) {
	// Helper module: minified 2-arg `(e, t) => fetch(e + t)` and context wrapper
	// `(ctx, p) => fetch(`${ctx.baseUrl}${p}`)` — neither relies on `isBaseName` for `(e, t)`.
	helperSrc := []byte(`
		export function get(e, t) {
			return fetch(e + t);
		}
		export function restGet(ctx, p) {
			return fetch(` + "`${ctx.baseUrl}${p}`" + `);
		}
	`)
	storeSrc := []byte(`
		var { VUE_APP_URL_BASE_API: li } = {};
		const s = ref({
			baseUrl: li ?? window.BASE_PATH,
			restEndpoint: meta("rest-endpoint") ?? "rest",
		});
		const y = computed(() => ` + "`${s.value.baseUrl}${s.value.restEndpoint}`" + `);
		export const rootStore = {
			restApiContext: computed(() => ({ baseUrl: y.value })),
			templatesHost: computed(() => s.value.templates?.host ?? ""),
		};
		export const client = {
			authServer: "https://auth.app.test/v1",
			customGw: "/gw-internal",
		};
		export const analytics = {
			host: "https://analytics.third.test",
		};
	`)
	callerSrc := []byte(`
		import { get, restGet } from "./http.js";
		import { rootStore, client, analytics } from "./store.js";

		export function loadAll() {
			restGet(rootStore.restApiContext, "/workflows");
			get(rootStore.templatesHost, "/templates/search");
			get(client.authServer, "/users");
			get(client.customGw, "/orders");
			get(analytics.host, "/event");
		}
	`)

	scripts := []Script{
		{SHA256: "h1", URLs: []string{"https://app.test/assets/http.js"}, Result: jsapi.Extract(helperSrc)},
		{SHA256: "s1", URLs: []string{"https://app.test/assets/store.js"}, Result: jsapi.Extract(storeSrc)},
		{SHA256: "c1", URLs: []string{"https://app.test/assets/caller.js"}, Result: jsapi.Extract(callerSrc)},
	}
	inScope := func(h string) bool {
		return h == "app.test" || strings.HasSuffix(h, ".app.test")
	}

	// Build with ZERO network traffic (`reqs = nil`), simulating HTTP crawl / archive mode.
	eps := Build(scripts, nil, inScope)
	byPath := map[string]Endpoint{}
	for _, ep := range eps {
		byPath[ep.Method+" "+ep.Host+" "+ep.Path] = ep
	}

	// 1. Reactive store `ctx.baseUrl` resolves to `/rest` with zero traffic.
	if ep, ok := byPath["GET  {}/workflows"]; !ok || !slices.Equal(ep.Bases, []string{"/rest"}) || ep.ThirdParty {
		t.Errorf("GET {}/workflows = %+v, want Bases=[/rest] ThirdParty=false", ep)
	}
	// 2. Empty `templatesHost` remains Bases=[] (does NOT borrow /rest or /gw-internal).
	if ep, ok := byPath["GET  {}/templates/search"]; !ok || len(ep.Bases) != 0 {
		t.Errorf("GET {}/templates/search = %+v, want Bases=[]", ep)
	}
	// 3. Non-isBaseName `client.authServer` resolves statically to in-scope auth server.
	if ep, ok := byPath["GET  {}/users"]; !ok || !slices.Equal(ep.Bases, []string{"https://auth.app.test/v1"}) || ep.ThirdParty {
		t.Errorf("GET {}/users = %+v, want Bases=[https://auth.app.test/v1] ThirdParty=false", ep)
	}
	// 4. Non-isBaseName `client.customGw` resolves statically to `/gw-internal`.
	if ep, ok := byPath["GET  {}/orders"]; !ok || !slices.Equal(ep.Bases, []string{"/gw-internal"}) || ep.ThirdParty {
		t.Errorf("GET {}/orders = %+v, want Bases=[/gw-internal] ThirdParty=false", ep)
	}
	// 5. `analytics.host` resolves to third-party host and marks ThirdParty=true (never borrows /rest).
	if ep, ok := byPath["GET  {}/event"]; !ok || !slices.Equal(ep.Bases, []string{"https://analytics.third.test"}) || !ep.ThirdParty {
		t.Errorf("GET {}/event = %+v, want Bases=[https://analytics.third.test] ThirdParty=true", ep)
	}
}
