package jsapi

import (
	"slices"
	"testing"
)

func TestClientAuthzCASLMethods(t *testing.T) {
	src := []byte(`
		const ACT_PUBLISH = "publish";
		var SubjectEnum;
		(function (SubjectEnum) {
			SubjectEnum["Firmware"] = "Firmware";
		})(SubjectEnum || (SubjectEnum = {}));
		const ACTIONS = Object.freeze({ APPROVE: "approve" });

		function render(vm, userAbility, checker, item) {
			if (this.$can("update", "Device")) {}
			if (vm._vm.$can("read", "Report")) {}
			if (this.$cannot("delete", "AuditLog")) {}
			if (this.$can("ota:rollback")) {}
			if (this.ability?.can("manage", "Tenant")) {}
			if (userAbility.can(ACTIONS.APPROVE, "Invoice")) {}
			if (checker.cannot("export", "Customer")) {}
			if (ability.can("ota:deploy")) {}
			if (this.acl.can("billing.manage")) {}
			if (ability.can(ACT_PUBLISH, SubjectEnum.Firmware)) {}
			if (ability.can("update", subject("Order", item))) {}
		}
	`)
	r := Extract(src)
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}
	if r.ClientAuthz == nil {
		t.Fatalf("expected non-nil ClientAuthz")
	}
	want := []AuthzRule{
		{Action: "approve", Subject: "Invoice"},
		{Action: "billing.manage"},
		{Action: "delete", Subject: "AuditLog"},
		{Action: "export", Subject: "Customer"},
		{Action: "manage", Subject: "Tenant"},
		{Action: "ota:deploy"},
		{Action: "ota:rollback"},
		{Action: "publish", Subject: "Firmware"},
		{Action: "read", Subject: "Report"},
		{Action: "update", Subject: "Device"},
		{Action: "update", Subject: "Order"},
	}
	if !slices.Equal(r.ClientAuthz.Rules, want) {
		t.Fatalf("Rules =\n  %+v\nwant\n  %+v", r.ClientAuthz.Rules, want)
	}
}

func TestClientAuthzCASLDefineAbilityAndUseAbility(t *testing.T) {
	src := []byte(`
		import { defineAbility, AbilityBuilder, createMongoAbility } from "@casl/ability";

		export const a1 = defineAbility((can, cannot) => {
			can("manage", "all");
			cannot("delete", "User");
		});

		export const a2 = (0, r.defineAbility)((e, t) => {
			e("read", "Dashboard");
			t("update", "SystemConfig");
		});

		export const a3 = buildHelper((can, cannot) => {
			can(["read", "export"], "Telemetry");
		});

		export function setupComp() {
			const { can: e, cannot: t } = (0, o.useAbility)();
			e("reboot", "Gateway");
			t("wipe", "Gateway");
			const { can } = new AbilityBuilder(createMongoAbility);
			can("impersonate", "Account");
		}
	`)
	r := Extract(src)
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}
	if r.ClientAuthz == nil {
		t.Fatalf("expected non-nil ClientAuthz")
	}
	want := []AuthzRule{
		{Action: "delete", Subject: "User"},
		{Action: "export", Subject: "Telemetry"},
		{Action: "impersonate", Subject: "Account"},
		{Action: "manage", Subject: "all"},
		{Action: "read", Subject: "Dashboard"},
		{Action: "read", Subject: "Telemetry"},
		{Action: "reboot", Subject: "Gateway"},
		{Action: "update", Subject: "SystemConfig"},
		{Action: "wipe", Subject: "Gateway"},
	}
	if !slices.Equal(r.ClientAuthz.Rules, want) {
		t.Fatalf("Rules =\n  %+v\nwant\n  %+v", r.ClientAuthz.Rules, want)
	}
}

func TestClientAuthzCASLCanComponent(t *testing.T) {
	src := []byte(`
		const ContextualCan = (0, caslReact.createContextualCan)(AbilityCtx.Consumer);
		function renderVue2(_c, createElement) {
			return [
				_c("Can", { attrs: { I: "update", a: "Order" } }),
				createElement("Can", { props: { do: "delete", on: "Invoice" } }),
			];
		}
		function renderVue3() {
			const _component_Can = _resolveComponent("Can");
			return _createVNode(_component_Can, { I: "approve", a: "Release" });
		}
		function renderReact() {
			return [
				_jsx(Can, { I: "read", a: "Analytics" }),
				_jsxs(ContextualCan, { I: "export", a: "Report", children: [] }),
				(0, jsxRuntime.jsx)( minifiedComp.Z, { I: "manage", a: "Webhook" } ),
			];
		}
	`)
	r := Extract(src)
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}
	if r.ClientAuthz == nil {
		t.Fatalf("expected non-nil ClientAuthz")
	}
	want := []AuthzRule{
		{Action: "approve", Subject: "Release"},
		{Action: "delete", Subject: "Invoice"},
		{Action: "export", Subject: "Report"},
		{Action: "manage", Subject: "Webhook"},
		{Action: "read", Subject: "Analytics"},
		{Action: "update", Subject: "Order"},
	}
	if !slices.Equal(r.ClientAuthz.Rules, want) {
		t.Fatalf("Rules =\n  %+v\nwant\n  %+v", r.ClientAuthz.Rules, want)
	}

	tsx := []byte(`
		import React from "react";
		import { Can } from "./ability";
		export function Btn() {
			return <Can I="archive" a="Project"><button>Archive</button></Can>;
		}
	`)
	rTSX := ExtractSource(tsx, "https://admin.example.com/src/Btn.tsx")
	if rTSX.Error != "" {
		t.Fatalf("ExtractSource TSX error: %s", rTSX.Error)
	}
	if rTSX.ClientAuthz == nil || !slices.Equal(rTSX.ClientAuthz.Rules, []AuthzRule{{Action: "archive", Subject: "Project"}}) {
		t.Fatalf("TSX ClientAuthz = %+v, want [{archive Project}]", rTSX.ClientAuthz)
	}
}

func TestClientAuthzGuardHelpers(t *testing.T) {
	src := []byte(`
		function checkGuards(auth, user) {
			hasPermission("user:write");
			(0, auth.checkAuthority)("ota.publish");
			Object(auth.requireScope)("devices:read");
			auth.hasAnyPermissions(["audit:read", "audit:export"]);
			auth.hasPrivilege("cluster.admin");

			hasRole("ADMIN");
			this.hasAnyRole(["ADMIN", "AUDITOR"]);
			user.isRole("OPERATOR");
			auth.requireAllRoles(["SUPER_ADMIN", "SECURITY_OFFICER"]);
		}
	`)
	r := Extract(src)
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}
	if r.ClientAuthz == nil {
		t.Fatalf("expected non-nil ClientAuthz")
	}
	wantRoles := []string{"ADMIN", "AUDITOR", "OPERATOR", "SECURITY_OFFICER", "SUPER_ADMIN"}
	wantPerms := []string{"audit:export", "audit:read", "cluster.admin", "devices:read", "ota.publish", "user:write"}
	if !slices.Equal(r.ClientAuthz.Roles, wantRoles) {
		t.Fatalf("Roles = %v, want %v", r.ClientAuthz.Roles, wantRoles)
	}
	if !slices.Equal(r.ClientAuthz.Permissions, wantPerms) {
		t.Fatalf("Permissions = %v, want %v", r.ClientAuthz.Permissions, wantPerms)
	}
}

func TestClientAuthzConstantDictionariesAndEnums(t *testing.T) {
	src := []byte(`
		const ROLES = {
			ADMIN: "SUPER_ADMIN",
			VIEWER: "READ_ONLY",
		};
		const USER_ROLES = Object.freeze({
			OPERATOR: "ROLE_OPERATOR",
		});
		var Role;
		(function (Role) {
			Role["Admin"] = "admin";
			Role["Guest"] = "guest";
		})(Role || (Role = {}));

		var r;
		!function (e) {
			e.Auditor = "AUDITOR";
		}(r = exports.UserRole || (exports.UserRole = {}));

		const APP_PERMISSIONS = {
			OTA_PUBLISH: "ota.publish",
			USERS: {
				CREATE: "user:create",
				DELETE: "user:delete",
			},
		};
		exports.AUTHORITIES = {
			BILLING: "billing:admin",
		};
	`)
	r := Extract(src)
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}
	if r.ClientAuthz == nil {
		t.Fatalf("expected non-nil ClientAuthz")
	}
	wantRoles := []string{"AUDITOR", "READ_ONLY", "ROLE_OPERATOR", "SUPER_ADMIN", "admin", "guest"}
	wantPerms := []string{"billing:admin", "ota.publish", "user:create", "user:delete"}
	if !slices.Equal(r.ClientAuthz.Roles, wantRoles) {
		t.Fatalf("Roles = %v, want %v", r.ClientAuthz.Roles, wantRoles)
	}
	if !slices.Equal(r.ClientAuthz.Permissions, wantPerms) {
		t.Fatalf("Permissions = %v, want %v", r.ClientAuthz.Permissions, wantPerms)
	}
}

func TestClientAuthzNegativeZeroFalsePositives(t *testing.T) {
	src := []byte(`
		function domAndFrameworkNoise(video, audio, payment, fsm, guard, el, dynA, dynB) {
			video.canPlayType("video/mp4");
			audio.canPlayType("audio/ogg; codecs=vorbis");
			payment.canMakePayment();
			navigator.canShare({ title: "Doc", url: "https://admin.example.com/doc" });
			URL.canParse("https://admin.example.com/v1", "https://admin.example.com");
			guard.canActivate("admin", "dashboard");

			// 1-arg non-ability state machine .can() must not match
			fsm.can("submit");

			// Invalid CASL tokens: slashes, spaces, URLs, 1-char, numeric, dynamic
			ability.can("video/mp4", "Player");
			ability.can("read all records", "Order");
			ability.can("https://admin.example.com/api", "GET");
			ability.can("x", "y");
			ability.can(123, 456);
			ability.can(dynA, dynB);

			// ARIA attributes and plain variables
			el.role = "button";
			const role = "dialog";
			_jsx("div", { role: "tabpanel", id: "main", a: "link" });

			// Vue prop descriptors and JSON Schema properties named role/permissions
			const VueComp = {
				props: {
					role: { type: "string", default: "user" },
					permissions: { type: "array", required: true },
				},
			};
			const jsonSchema = {
				properties: {
					role: { type: "string", format: "varchar", title: "User Role" },
				},
			};
			return [VueComp, jsonSchema, role];
		}
	`)
	r := Extract(src)
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}
	if r.ClientAuthz != nil {
		t.Fatalf("expected nil ClientAuthz on negative noise cases, got %+v", r.ClientAuthz)
	}
}
