package jsapi

import (
	"slices"
	"testing"
)

func TestTerserWebpackVue2IntraBundleAuthzAndRoutes(t *testing.T) {
	// Reproduces real-world Webpack 4 + Terser (wrap_func_args) + Vue 2 bundle:
	// - Parenthesized getter functions in n.d(t, "a", (function(){ return r }))
	// - Hoisted `var r, o;` initialized once via Object.freeze({...})
	// - Vue.prototype.PERMISSION = o.a, multi-component data() returning { PERMISSION: o.a },
	//   and shorthand computed: { PERMISSION_ENTITY() { return o.b } }
	// - Router meta: { permission: { action: o.a.READ, object: o.b.DASHBOARD_LOCATION } }
	// - Compiled Vue 2 render: var e = this; ... e.$can(e.PERMISSION.CREATE, e.PERMISSION_ENTITY.CUSTOMER)
	src := []byte(`
(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["app"], {
  "1234": (function(e, t, n) {
    "use strict";
    var r, o;
    n.d(t, "a", (function() { return r })),
    n.d(t, "b", (function() { return o }));
    r = Object.freeze({ READ: "read", CREATE: "create", DELETE: "delete" });
    o = Object.freeze({ DASHBOARD_LOCATION: "dashboard_location", CUSTOMER: "customer" });
  }),
  "5678": (function(e, t, n) {
    "use strict";
    var r = n("0001"), o = n("1234");
    r.a.prototype.PERMISSION = o.a;
    var compA = {
      data: (function() { return { PERMISSION: o.a }; }),
      computed: {
        PERMISSION_ENTITY() { return o.b; }
      },
      render: (function() {
        var e = this, t = e.$createElement, c = e._self._c || t;
        return c("div", [
          e.$can(e.PERMISSION.CREATE, e.PERMISSION_ENTITY.CUSTOMER) ? c("button") : e._e()
        ]);
      })
    };
    var compB = {
      data: (function() { return { PERMISSION: o.a }; }),
      render: (function(vm) {
        return vm._c("span", [vm._v(vm.$can(vm.PERMISSION.DELETE, "customer") ? "ok" : "")]);
      })
    };
    var routes = [
      {
        path: "/dashboard/locations",
        component: compA,
        meta: {
          permission: { action: o.a.READ, object: o.b.DASHBOARD_LOCATION }
        }
      }
    ];
    new VueRouter({ routes: routes });
  })
}]);
`)
	res := Extract(src)
	if res.Error != "" {
		t.Fatalf("Extract error: %s", res.Error)
	}
	if len(res.RouteEntries) != 1 {
		t.Fatalf("RouteEntries = %+v, want 1 route", res.RouteEntries)
	}
	re := res.RouteEntries[0]
	if re.Path != "/dashboard/locations" || !slices.Contains(re.Permissions, "read:dashboard_location") {
		t.Errorf("RouteEntry = %+v, want path=/dashboard/locations perms=[read:dashboard_location]", re)
	}
	if res.ClientAuthz == nil {
		t.Fatalf("expected non-nil ClientAuthz")
	}
	wantRule1 := AuthzRule{Action: "create", Subject: "customer"}
	wantRule2 := AuthzRule{Action: "delete", Subject: "customer"}
	if !slices.Contains(res.ClientAuthz.Rules, wantRule1) || !slices.Contains(res.ClientAuthz.Rules, wantRule2) {
		t.Errorf("ClientAuthz.Rules = %+v, want %+v and %+v", res.ClientAuthz.Rules, wantRule1, wantRule2)
	}
}

func TestConditionalOrClosureHoistedVarNotTreatedAsConstant(t *testing.T) {
	src := []byte(`
var condDict, closureDict;
if (window.FLAG) {
  condDict = { READ: "wrong_cond" };
}
function initLater() {
  closureDict = { READ: "wrong_closure" };
}
function check(ability) {
  ability.can(condDict.READ, "Order");
  ability.can(closureDict.READ, "Order");
}
`)
	res := Extract(src)
	if res.ClientAuthz != nil && len(res.ClientAuthz.Rules) > 0 {
		t.Errorf("expected conditional/closure hoisted vars not to resolve as constants, got %+v", res.ClientAuthz.Rules)
	}
}

func TestAuthzLowercaseDictsAndCustomBuilderHintsPreserved(t *testing.T) {
	src := []byte(`
const roles = { manager: "store_manager" };
const permissions = { exportData: "report:export" };
const authorities = { aud: "global_auditor" };
const CanComp = resolveComponent("Can");
const ability = buildAppRules((can, cannot) => {
  can("approve", "PurchaseOrder");
});
function render() {
  return _jsx(CanComp, { I: "archive", a: "Ledger" });
}
`)
	res := Extract(src)
	if res.ClientAuthz == nil {
		t.Fatalf("expected non-nil ClientAuthz for lowercase dicts and custom CASL builder")
	}
	if !slices.Contains(res.ClientAuthz.Roles, "store_manager") {
		t.Errorf("missing lowercase roles dict value: %+v", res.ClientAuthz.Roles)
	}
	if !slices.Contains(res.ClientAuthz.Permissions, "report:export") || !slices.Contains(res.ClientAuthz.Permissions, "global_auditor") {
		t.Errorf("missing lowercase permissions/authorities values: %+v", res.ClientAuthz.Permissions)
	}
	if !slices.Contains(res.ClientAuthz.Rules, AuthzRule{Action: "approve", Subject: "PurchaseOrder"}) ||
		!slices.Contains(res.ClientAuthz.Rules, AuthzRule{Action: "archive", Subject: "Ledger"}) {
		t.Errorf("missing custom builder or resolveComponent(Can) rule: %+v", res.ClientAuthz.Rules)
	}
}
