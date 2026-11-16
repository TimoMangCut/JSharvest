package jsapi

import (
	"slices"
	"testing"
)

func TestHierarchicalVueRouterAST(t *testing.T) {
	src := `
const ecuChildren = [
	{ path: "", component: EcuIndex },
	{ path: ":id/edit", component: EcuEdit, meta: { authRequired: !0, permissions: ["ecu:write", "ecu:read"] } },
];
const extraOta = [
	{ path: "campaigns", component: Campaigns, meta: { role: "ROLE_MANAGER" } },
];
const otaChildren = [
	{ path: "release-package", component: ReleasePkg, meta: { requiresAuth: true, roles: ["ROLE_ADMIN", "ROLE_AUDITOR"], permission: "ota:read" } },
	{ path: "ecu", component: EcuShell, children: ecuChildren },
	{ path: "/standalone-ota", component: StandaloneOta },
].concat(extraOta);

const publicRoutes = [
	{ path: "/login", component: LoginView, meta: { authRequired: !1 } },
];

const router = new VueRouter({
	mode: "history",
	routes: [
		...publicRoutes,
		{
			path: "/",
			component: MainLayout,
			redirect: "/dashboard",
			children: [
				{ path: "dashboard", component: DashboardView },
				{ path: "ota", redirect: "/ota/release-package", children: otaChildren },
			],
		},
		{ path: "*", redirect: "/login" },
	],
});
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}

	wantRoutes := []string{
		"/dashboard",
		"/login",
		"/ota",
		"/ota/campaigns",
		"/ota/ecu",
		"/ota/ecu/:id/edit",
		"/ota/release-package",
		"/standalone-ota",
	}
	for _, wr := range wantRoutes {
		if !slices.Contains(r.Routes, wr) {
			t.Errorf("missing route %q in Result.Routes=%v", wr, r.Routes)
		}
	}

	byPath := map[string]RouteEntry{}
	for _, re := range r.RouteEntries {
		byPath[re.Path] = re
	}

	if login, ok := byPath["/login"]; !ok || login.AuthRequired == nil || *login.AuthRequired != false || login.Line == 0 {
		t.Errorf("/login entry = %+v, want AuthRequired=false and Line>0", login)
	}
	if ota, ok := byPath["/ota"]; !ok || ota.Redirect != "/ota/release-package" {
		t.Errorf("/ota entry = %+v, want Redirect=/ota/release-package", ota)
	}
	if rp, ok := byPath["/ota/release-package"]; !ok {
		t.Errorf("missing /ota/release-package in RouteEntries=%+v", r.RouteEntries)
	} else {
		if rp.AuthRequired == nil || !*rp.AuthRequired {
			t.Errorf("/ota/release-package AuthRequired = %v, want true", rp.AuthRequired)
		}
		if !slices.Equal(rp.Roles, []string{"ROLE_ADMIN", "ROLE_AUDITOR"}) {
			t.Errorf("/ota/release-package Roles = %v", rp.Roles)
		}
		if !slices.Equal(rp.Permissions, []string{"ota:read"}) {
			t.Errorf("/ota/release-package Permissions = %v", rp.Permissions)
		}
	}
	if edit, ok := byPath["/ota/ecu/:id/edit"]; !ok || edit.AuthRequired == nil || !*edit.AuthRequired || !slices.Equal(edit.Permissions, []string{"ecu:read", "ecu:write"}) {
		t.Errorf("/ota/ecu/:id/edit entry = %+v", edit)
	}
	if camp, ok := byPath["/ota/campaigns"]; !ok || !slices.Equal(camp.Roles, []string{"ROLE_MANAGER"}) {
		t.Errorf("/ota/campaigns entry = %+v", camp)
	}
}

func TestReactAndAngularRoutersAndCycleSafety(t *testing.T) {
	src := `
const router = createBrowserRouter([
	{
		path: "/",
		element: RootLayout,
		children: [
			{ index: true, element: Home },
			{
				element: RequireAuthLayout,
				children: [
					{ path: "settings", element: Settings, children: [{ path: "security", element: Security }] },
					{ path: "users/:userId", element: UserDetail },
				],
			},
		],
	},
]);

const ngMod = RouterModule.forChild([
	{
		path: "devices",
		canActivate: [AuthGuard],
		data: { roles: ["OPERATOR"] },
		children: [
			{ path: "", redirectTo: "inventory" },
			{ path: "inventory", loadComponent: () => import("./inv") },
		],
	},
]);

$routeProvider.when("/legacy/audit", { templateUrl: "audit.html" });
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}
	for _, want := range []string{"/settings", "/settings/security", "/users/:userId", "/devices", "/devices/inventory", "/legacy/audit"} {
		if !slices.Contains(r.Routes, want) {
			t.Errorf("missing %q in Routes=%v", want, r.Routes)
		}
	}
	byPath := map[string]RouteEntry{}
	for _, re := range r.RouteEntries {
		byPath[re.Path] = re
	}
	if dev, ok := byPath["/devices"]; !ok || dev.AuthRequired == nil || !*dev.AuthRequired || !slices.Equal(dev.Roles, []string{"OPERATOR"}) {
		t.Errorf("/devices = %+v, want AuthRequired=true Roles=[OPERATOR]", dev)
	}

	// Non-router objects with `path` property AND cyclic `children` must produce 0 FP and terminate cleanly.
	noiseAndCycle := `
const icon = { path: "M10 10 L20 20 Z", fill: "none" };
const fieldSchema = { path: "user.profile.name", type: "string" };
const relObj = { path: "not/a/router" };
Cookies.set("sid", tok, { path: "/", secure: true });
const cyc = { path: "/cycle", component: C, children: [] };
const cyc2 = { path: "/loop", component: L, children: [cyc2] };
`
	r2 := Extract([]byte(noiseAndCycle))
	if r2.Error != "" {
		t.Fatalf("cycle/noise error: %s", r2.Error)
	}
	if !slices.Equal(r2.Routes, []string{"/cycle", "/loop"}) {
		t.Fatalf("unexpected routes from noise/cycle snippet: %v", r2.Routes)
	}
}

func TestVueRouterMetaPermissionObjectsAndLocalEnums(t *testing.T) {
	src := `
var ActEnum;
(function(e) {
	e.READ = "read";
	e.WRITE = "write";
})(ActEnum || (ActEnum = {}));
const EntityConst = Object.freeze({ INVOICES: "INVOICES", DASHBOARD: "DASHBOARD_OVERVIEW" });
const RolesConst = Object.freeze({ AUDITOR: "AUDITOR" });
const basePerm = { object: EntityConst.INVOICES };

const router = new VueRouter({
	mode: "history",
	routes: [
		{
			path: "/dashboard/overview",
			component: DashView,
			meta: { label: "nav.dashboard", permission: { action: "read", object: "DASHBOARD_OVERVIEW" } },
		},
		{
			path: "/billing/invoices/edit",
			component: InvoiceEdit,
			meta: { permission: { action: ActEnum.WRITE, subject: EntityConst.INVOICES }, role: RolesConst.AUDITOR },
		},
		{
			path: "/reports/export",
			component: ReportView,
			meta: { permissions: [{ action: ["read", "export"], resource: "REPORT" }, "system:audit"] },
		},
		{
			path: "/billing/invoices/delete",
			component: InvoiceDelete,
			meta: { permission: { ...basePerm, action: "delete" } },
		},
		{
			path: "/noise",
			component: NoiseView,
			meta: { title: "Plain Page", permission: { label: "Plain Label" } },
		},
	],
});
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}
	byPath := map[string]RouteEntry{}
	for _, re := range r.RouteEntries {
		byPath[re.Path] = re
	}

	if d, ok := byPath["/dashboard/overview"]; !ok || !slices.Equal(d.Permissions, []string{"read:DASHBOARD_OVERVIEW"}) {
		t.Errorf("/dashboard/overview = %+v, want Permissions=[read:DASHBOARD_OVERVIEW]", d)
	}
	if inv, ok := byPath["/billing/invoices/edit"]; !ok || !slices.Equal(inv.Permissions, []string{"write:INVOICES"}) || !slices.Equal(inv.Roles, []string{"AUDITOR"}) {
		t.Errorf("/billing/invoices/edit = %+v, want Permissions=[write:INVOICES] Roles=[AUDITOR]", inv)
	}
	if rep, ok := byPath["/reports/export"]; !ok || !slices.Equal(rep.Permissions, []string{"export:REPORT", "read:REPORT", "system:audit"}) {
		t.Errorf("/reports/export = %+v, want Permissions=[export:REPORT read:REPORT system:audit]", rep)
	}
	if del, ok := byPath["/billing/invoices/delete"]; !ok || !slices.Equal(del.Permissions, []string{"delete:INVOICES"}) {
		t.Errorf("/billing/invoices/delete = %+v, want Permissions=[delete:INVOICES]", del)
	}
	if noise, ok := byPath["/noise"]; !ok || len(noise.Permissions) != 0 || len(noise.Roles) != 0 {
		t.Errorf("/noise unexpected authz = %+v", noise)
	}
}
