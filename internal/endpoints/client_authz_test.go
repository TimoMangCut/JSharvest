package endpoints

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func TestMergeClientAuthzDedupSortAndTrackerSkip(t *testing.T) {
	scripts := []Script{
		{
			SHA256: "1111",
			URLs:   []string{"https://admin.example.com/static/js/app.js"},
			Result: jsapi.Result{
				Version: jsapi.Version,
				ClientAuthz: &jsapi.ClientAuthz{
					Roles:       []string{"VIEWER", "ADMIN"},
					Permissions: []string{"user:write", "ota.publish"},
					Rules: []jsapi.AuthzRule{
						{Action: "update", Subject: "Device"},
						{Action: "read", Subject: "Report"},
					},
				},
			},
		},
		{
			// App bundle hosted on a dedicated CloudFront distribution (ThirdParty=true,
			// but NOT a tracker domain -> must be included per App-Referenced Scope).
			SHA256:     "2222",
			URLs:       []string{"https://d111111abcdef8.cloudfront.net/assets/vendor-admin.js"},
			ThirdParty: true,
			Result: jsapi.Result{
				Version: jsapi.Version,
				ClientAuthz: &jsapi.ClientAuthz{
					Roles:       []string{"ADMIN", "AUDITOR"},
					Permissions: []string{"ota.publish", "audit:read"},
					Rules: []jsapi.AuthzRule{
						{Action: "update", Subject: "Device"},
						{Action: "manage", Subject: "Tenant"},
					},
				},
			},
		},
		{
			// Analytics / tag manager tracker scripts -> must be skipped!
			SHA256:     "3333",
			URLs:       []string{"https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"},
			ThirdParty: true,
			Result: jsapi.Result{
				Version: jsapi.Version,
				ClientAuthz: &jsapi.ClientAuthz{
					Roles:       []string{"GTM_FAKE_ROLE"},
					Permissions: []string{"gtm:fake"},
					Rules:       []jsapi.AuthzRule{{Action: "track", Subject: "Pixel"}},
				},
			},
		},
		{
			SHA256:     "4444",
			URLs:       []string{"https://static.hotjar.com/c/hotjar-12345.js"},
			ThirdParty: true,
			Result: jsapi.Result{
				Version: jsapi.Version,
				ClientAuthz: &jsapi.ClientAuthz{
					Roles: []string{"HOTJAR_ROLE"},
				},
			},
		},
		{
			// Synthetic un-URLed ThirdParty script -> must be skipped!
			SHA256:     "5555",
			ThirdParty: true,
			Result: jsapi.Result{
				Version: jsapi.Version,
				ClientAuthz: &jsapi.ClientAuthz{
					Roles: []string{"UNURLED_3P_ROLE"},
				},
			},
		},
	}

	in := BuildIntel(scripts, func(h string) bool { return h == "admin.example.com" })
	if in.ClientAuthz == nil {
		t.Fatalf("expected non-nil Intel.ClientAuthz")
	}
	wantRoles := []string{"ADMIN", "AUDITOR", "VIEWER"}
	wantPerms := []string{"audit:read", "ota.publish", "user:write"}
	wantRules := []jsapi.AuthzRule{
		{Action: "manage", Subject: "Tenant"},
		{Action: "read", Subject: "Report"},
		{Action: "update", Subject: "Device"},
	}
	if !slices.Equal(in.ClientAuthz.Roles, wantRoles) {
		t.Fatalf("Roles = %v, want %v", in.ClientAuthz.Roles, wantRoles)
	}
	if !slices.Equal(in.ClientAuthz.Permissions, wantPerms) {
		t.Fatalf("Permissions = %v, want %v", in.ClientAuthz.Permissions, wantPerms)
	}
	if !slices.Equal(in.ClientAuthz.Rules, wantRules) {
		t.Fatalf("Rules = %+v, want %+v", in.ClientAuthz.Rules, wantRules)
	}
}

func TestSaveIntelWritesClientAuthzOnly(t *testing.T) {
	dir := t.TempDir()
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.MkdirAll(filepath.Join(dir, CacheDir), 0o700); err != nil {
		t.Fatal(err)
	}
	idxLine := fmt.Sprintf(`{"sha256":%q,"urls":["https://admin.example.com/app.js"]}`+"\n", sha)
	if err := os.WriteFile(filepath.Join(dir, "index.jsonl"), []byte(idxLine), 0o600); err != nil {
		t.Fatal(err)
	}
	cached, err := json.Marshal(jsapi.Result{
		Version: jsapi.Version,
		ClientAuthz: &jsapi.ClientAuthz{
			Roles:       []string{"SUPER_ADMIN"},
			Permissions: []string{"firmware:sign"},
			Rules:       []jsapi.AuthzRule{{Action: "sign", Subject: "Firmware"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CacheDir, sha+".json"), cached, 0o600); err != nil {
		t.Fatal(err)
	}

	in, err := SaveIntel(dir, func(h string) bool { return h == "admin.example.com" }, nil)
	if err != nil {
		t.Fatalf("SaveIntel: %v", err)
	}
	if in.ClientAuthz == nil || !slices.Equal(in.ClientAuthz.Roles, []string{"SUPER_ADMIN"}) {
		t.Fatalf("SaveIntel returned unexpected ClientAuthz: %+v", in.ClientAuthz)
	}
	raw, err := os.ReadFile(filepath.Join(dir, IntelFile))
	if err != nil {
		t.Fatalf("expected %s to be written when ClientAuthz is non-empty: %v", IntelFile, err)
	}
	var disk Intel
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatalf("unmarshal intel.json: %v", err)
	}
	if disk.ClientAuthz == nil || len(disk.ClientAuthz.Rules) != 1 || disk.ClientAuthz.Rules[0].Subject != "Firmware" {
		t.Fatalf("disk intel.json ClientAuthz = %+v", disk.ClientAuthz)
	}
}

func TestMergeClientAuthzCapLimit(t *testing.T) {
	var roles, perms []string
	var rules []jsapi.AuthzRule
	for i := 0; i < 620; i++ {
		roles = append(roles, fmt.Sprintf("ROLE_%04d", 620-i))
		perms = append(perms, fmt.Sprintf("perm:%04d", 620-i))
		rules = append(rules, jsapi.AuthzRule{Action: "read", Subject: fmt.Sprintf("Res%04d", 620-i)})
	}
	ca := MergeClientAuthz([]Script{{
		SHA256: "cap",
		URLs:   []string{"https://admin.example.com/app.js"},
		Result: jsapi.Result{
			Version:     jsapi.Version,
			ClientAuthz: &jsapi.ClientAuthz{Roles: roles, Permissions: perms, Rules: rules},
		},
	}})
	if ca == nil {
		t.Fatalf("expected non-nil ClientAuthz")
	}
	if len(ca.Roles) != maxAuthzItems || ca.Roles[0] != "ROLE_0001" || ca.Roles[maxAuthzItems-1] != "ROLE_0500" {
		t.Fatalf("Roles len=%d first=%q last=%q", len(ca.Roles), ca.Roles[0], ca.Roles[len(ca.Roles)-1])
	}
	if len(ca.Permissions) != maxAuthzItems || ca.Permissions[0] != "perm:0001" {
		t.Fatalf("Permissions len=%d first=%q", len(ca.Permissions), ca.Permissions[0])
	}
	if len(ca.Rules) != maxAuthzItems || ca.Rules[0].Subject != "Res0001" {
		t.Fatalf("Rules len=%d first=%+v", len(ca.Rules), ca.Rules[0])
	}
}

func TestClientAuthzRouteMetaAggregation(t *testing.T) {
	f, tr := false, true
	var b ClientAuthzBuilder
	b.AddRoute("/login", &f, nil, nil)
	b.AddRoute("/forgot-password", &f, nil, nil)
	b.AddRoute("/ota/releases", &tr, []string{"ADMIN"}, []string{"ota.publish"})
	b.AddRoute("/ota/releases", nil, []string{"AUDITOR", "ADMIN"}, []string{"ota.read"})
	ca := b.Build()
	if ca == nil {
		t.Fatalf("expected non-nil ClientAuthz")
	}
	if !slices.Equal(ca.PublicRoutes, []string{"/forgot-password", "/login"}) {
		t.Fatalf("PublicRoutes = %v", ca.PublicRoutes)
	}
	if len(ca.GuardedRoutes) != 1 {
		t.Fatalf("GuardedRoutes = %+v", ca.GuardedRoutes)
	}
	gr := ca.GuardedRoutes[0]
	if gr.Path != "/ota/releases" || gr.AuthRequired == nil || !*gr.AuthRequired ||
		!slices.Equal(gr.Roles, []string{"ADMIN", "AUDITOR"}) ||
		!slices.Equal(gr.Permissions, []string{"ota.publish", "ota.read"}) {
		t.Fatalf("GuardedRoute = %+v", gr)
	}
	if !slices.Equal(ca.Roles, []string{"ADMIN", "AUDITOR"}) || !slices.Equal(ca.Permissions, []string{"ota.publish", "ota.read"}) {
		t.Fatalf("route roles/perms should propagate into ClientAuthz: roles=%v perms=%v", ca.Roles, ca.Permissions)
	}
}
