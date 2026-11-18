package endpoints

import (
	"fmt"
	"slices"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func TestCrossChunkConstExportsLinkingAndClashGuard(t *testing.T) {
	// Chunk 1 (chunk-common.js): defines Webpack harmony module "1234" and CJS module "9999".
	chunkCommon := jsapi.Extract([]byte(`
(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["chunk-common"], {
  "1234": (function(e, t, n) {
    "use strict";
    var r, o;
    n.d(t, "a", (function() { return r })),
    n.d(t, "b", (function() { return o }));
    r = Object.freeze({ READ: "read", CREATE: "create" });
    o = Object.freeze({ DASHBOARD_LOCATION: "dashboard_location", CUSTOMER: "customer" });
  }),
  "9999": (function(e) {
    e.exports = Object.freeze({ EXPORT_REPORT: "report:export" });
  })
}]);
`))

	// Chunk 2 (app.js): imports "1234" and "9999" from the other chunk; binds Vue.prototype.PERMISSION = o.a.
	chunkApp := jsapi.Extract([]byte(`
(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["app"], {
  "5678": (function(e, t, n) {
    "use strict";
    var v = n("0001"), o = n("1234"), c = n("9999"), ca = n.n(c);
    v.a.prototype.PERMISSION = o.a;
    v.a.prototype.PERMISSION_ENTITY = o.b;
    var page = {
      render: (function() {
        var e = this, h = e.$createElement;
        if (hasPermission(ca.a.EXPORT_REPORT)) {}
        return h("div", [e.$can(e.PERMISSION.CREATE, e.PERMISSION_ENTITY.CUSTOMER) ? "y" : "n"]);
      })
    };
    var routes = [
      {
        path: "/scooters/locations",
        component: page,
        meta: { permission: { action: o.a.READ, object: o.b.DASHBOARD_LOCATION } }
      }
    ];
    new VueRouter({ routes: routes });
  })
}]);
`))

	scripts := []Script{
		{SHA256: "1111", URLs: []string{"https://admin.example.test/js/chunk-common.js"}, Result: chunkCommon},
		{SHA256: "2222", URLs: []string{"https://admin.example.test/js/app.js"}, Result: chunkApp},
	}

	intel := BuildIntel(scripts, func(h string) bool { return h == "admin.example.test" })
	if len(intel.Routes) != 1 || !slices.Contains(intel.Routes[0].Permissions, "read:dashboard_location") {
		t.Fatalf("Intel.Routes = %+v, want /scooters/locations with [read:dashboard_location]", intel.Routes)
	}
	if intel.ClientAuthz == nil {
		t.Fatalf("expected non-nil Intel.ClientAuthz")
	}
	if !slices.Contains(intel.ClientAuthz.Permissions, "report:export") ||
		!slices.Contains(intel.ClientAuthz.Permissions, "read:dashboard_location") {
		t.Errorf("ClientAuthz.Permissions = %+v, want report:export and read:dashboard_location", intel.ClientAuthz.Permissions)
	}
	wantRule := jsapi.AuthzRule{Action: "create", Subject: "customer"}
	if !slices.Contains(intel.ClientAuthz.Rules, wantRule) {
		t.Errorf("ClientAuthz.Rules = %+v, want %+v", intel.ClientAuthz.Rules, wantRule)
	}
	// Cached Script struct must NOT have been mutated in place.
	if len(scripts[1].RouteEntries[0].Permissions) != 0 {
		t.Errorf("expected input Script.RouteEntries not to be mutated in-place, got %+v", scripts[1].RouteEntries[0].Permissions)
	}

	// Clash Guard: adding an older conflicting module "1234" on the SAME origin must suppress ambiguous linking,
	// whereas a conflicting module "1234" on a DIFFERENT origin must NOT interfere.
	otherOriginClash := jsapi.Extract([]byte(`
(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["other"], {
  "1234": (function(e, t, n) {
    n.d(t, "a", (function() { return { READ: "wrong_other_origin" }; }));
  })
}]);
`))
	withOtherOrigin := append(slices.Clone(scripts), Script{
		SHA256: "3333",
		URLs:   []string{"https://shop.example.test/js/chunk.js"},
		Result: otherOriginClash,
	})
	intelOther := BuildIntel(withOtherOrigin, func(string) bool { return true })
	if len(intelOther.Routes) != 1 || !slices.Contains(intelOther.Routes[0].Permissions, "read:dashboard_location") {
		t.Errorf("different-origin module ID should not clash: got %+v", intelOther.Routes)
	}

	sameOriginClash := append(slices.Clone(scripts), Script{
		SHA256: "4444",
		URLs:   []string{"https://admin.example.test/js/old-2020-chunk.js"},
		Result: otherOriginClash,
	})
	intelClashed := BuildIntel(sameOriginClash, func(string) bool { return true })
	if len(intelClashed.Routes) != 1 || len(intelClashed.Routes[0].Permissions) != 0 {
		t.Errorf("same-origin conflicting module ID must be blocked by clash guard, got %+v", intelClashed.Routes)
	}
}

func TestDualPoolMemCacheCrossShardEvictionAndBuildersBodyCache(t *testing.T) {
	SetMemCacheMB(1) // 1 MiB total -> ~665 KB resBudget, ~358 KB bodyBudget
	defer SetMemCacheMB(0)

	dir := t.TempDir()
	// Builder-only script on cache-miss with dir != "" must also populate bodyShards.
	builderSrc := []byte(`export function buildUserURL(id) { return "/api/v1/users/" + id; }`)
	res := ExtractCached(dir, builderSrc, "https://app.example.test/builders.js")
	if len(res.Builders) == 0 {
		t.Fatalf("expected exported URL builder, got %+v", res)
	}

	// Fill shard 1 ("...1") up to resBudget, then insert into empty shard 0 ("...0")
	// to verify cross-shard ring eviction frees space cleanly.
	bigRes := jsapi.Result{
		Version:   jsapi.Version,
		Endpoints: make([]jsapi.Endpoint, 200), // ~38 KB per entry
	}
	for i := 0; i < 24; i++ {
		sha := fmt.Sprintf("%063d1", i) // all land in shard 1
		memPutResult(sha, bigRes)
	}
	targetSHA := fmt.Sprintf("%063d0", 99) // lands in empty shard 0
	memPutResult(targetSHA, bigRes)
	if _, ok := memGetResult(targetSHA); !ok {
		t.Errorf("expected cross-shard ring eviction to make room for new entry in shard 0")
	}

	// Flood bodyShards and verify targetSHA in resShards is NOT evicted by raw bodies.
	chunkBody := make([]byte, 128<<10) // 128 KB each
	for i := 0; i < 12; i++ {
		bsha := fmt.Sprintf("%063d%x", i+100, i&15)
		CacheScriptBody(bsha, chunkBody)
	}
	if _, ok := memGetResult(targetSHA); !ok {
		t.Errorf("body pool eviction must never starve or evict AST Result pool")
	}
}
