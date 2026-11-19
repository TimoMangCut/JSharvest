package jsapi

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestStaticClassConstExportsAndServiceExports(t *testing.T) {
	src := []byte(`
var cfg = {
  ENVIRONMENT: "PROD",
  BASE_URL: "https://api.portal.test",
  ENCRIPTION_KEY: "krxYt78-d*5kYaxT",
  ENCRIPTION_LOGIN_KEY: "t3x/ztr*d*5kY2xT",
  APP_PORTAL_ENCRYPTION_KEY: "m2p_aes256_998877",
  encryptionSessionKey: "99aabbccddeeff00",
  privateApiKey: "priv_9876543210",
  CURRENT_USER_TOKEN_KEY: "currentUser",
  AUTH_TOKEN_HEADER_KEY: "auth-token",
  sortKey: "createdAt",
  rowKey: "row_identifier",
  primaryKey: "record_id",
  storageKey: "local_pref_v2"
};
var Routes = class {
  static BASE_URL = cfg.BASE_URL;
  static LOGIN = "edevlet-login";
  static LIST_ITEMS = "catalog/publishedItems";
  static ARCHIVE_ITEM = "catalog/archiveItem";
  static AUTH = { VERIFY_OTP: "sso/verifyOtp" };
  static \u0275fac = function(t) { return new (t || Routes)(); };
};
var ApiService = class s {
  constructor(http) { this.http = http; }
  get(p) { return this.http.get(Routes.BASE_URL + "/" + p); }
  getByParams(p, q) { return this.http.get(Routes.BASE_URL + "/" + p, { params: q }); }
  getById(p, id) { return this.http.get(Routes.BASE_URL + "/" + p + ` + "`/${id}`" + `); }
  post = (p, body) => this.http.post(Routes.BASE_URL + "/" + p, body);
  static \u0275fac = function(t) { return new (t || s)(injectHttp()); };
};
export { Routes as zc, ApiService as Bc };
`)
	res := Extract(src)
	if res.Error != "" {
		t.Fatalf("unexpected parse error: %s", res.Error)
	}

	var routeDict *ConstDict
	for i := range res.ConstExports {
		if res.ConstExports[i].Export == "zc" {
			routeDict = &res.ConstExports[i]
			break
		}
	}
	if routeDict == nil {
		t.Fatalf("missing ConstDict for exported static class zc; got %+v", res.ConstExports)
	}
	if routeDict.Values["LIST_ITEMS"] != "catalog/publishedItems" || routeDict.Values["LOGIN"] != "edevlet-login" || routeDict.Values["AUTH.VERIFY_OTP"] != "sso/verifyOtp" {
		t.Fatalf("unexpected static class ConstDict values: %+v", routeDict.Values)
	}
	for k := range routeDict.Values {
		if strings.Contains(k, "fac") {
			t.Fatalf("framework metadata leaked into ConstDict: %s", k)
		}
	}

	expByName := map[string]Export{}
	for _, ex := range res.Exports {
		expByName[ex.Name] = ex
	}
	for _, wantName := range []string{"Bc.get", "Bc.getByParams", "Bc.getById", "Bc.post"} {
		if _, ok := expByName[wantName]; !ok {
			t.Fatalf("missing exported class method %q in %+v", wantName, res.Exports)
		}
	}
	if g := expByName["Bc.getById"]; !g.ParamURL || g.URLArg != 0 || g.URLPrefix != "https://api.portal.test" || g.URLSuffix != "/{}" {
		t.Fatalf("unexpected Bc.getById export metadata: %+v", g)
	}
	if p := expByName["Bc.post"]; !p.ParamURL || p.Method != "POST" || p.BodyArg != 1 || p.URLPrefix != "https://api.portal.test" {
		t.Fatalf("unexpected Bc.post export metadata: %+v", p)
	}

	var gotKeyNames []string
	for _, k := range res.Keys {
		gotKeyNames = append(gotKeyNames, k.Name)
	}
	for _, wantKey := range []string{"ENCRIPTION_KEY", "ENCRIPTION_LOGIN_KEY", "APP_PORTAL_ENCRYPTION_KEY", "encryptionSessionKey", "privateApiKey"} {
		if !slices.Contains(gotKeyNames, wantKey) {
			t.Errorf("missing expected crypto/auth key %q in %v", wantKey, gotKeyNames)
		}
	}
	for _, noiseKey := range []string{"CURRENT_USER_TOKEN_KEY", "AUTH_TOKEN_HEADER_KEY", "sortKey", "rowKey", "primaryKey", "storageKey"} {
		if slices.Contains(gotKeyNames, noiseKey) {
			t.Errorf("false-positive UI/header/storage key %q extracted in %v", noiseKey, gotKeyNames)
		}
	}
}

func TestKeysStepBudgetAndCycleGuard(t *testing.T) {
	var sb strings.Builder
	// 1. 3-level nested ternary over cyclic vars + 24-level shared diamond DAG.
	sb.WriteString("var cycA = cond ? cycB : { k0: 1 };\n")
	sb.WriteString("var cycB = cond ? cycA : { k1: 2 };\n")
	sb.WriteString("var n0 = { leaf: 1 };\n")
	for i := 1; i <= 24; i++ {
		fmt.Fprintf(&sb, "const d%d = cond ? { ...d%d, ...d%d } : (flag ? Object.assign({}, d%d, d%d) : { v%d: 1 });\n",
			i, i-1, i-1, i-1, i-1, i)
	}
	sb.WriteString("function makeA(x) { return makeB(x); }\n")
	sb.WriteString("function makeB(x) { return cond ? makeA(x) : { ok: 1 }; }\n")
	sb.WriteString("fetch('/api/stress-dag', { method: 'POST', body: JSON.stringify({ ...cycA, ...d24, ...makeA(1) }) });\n")

	src := strings.ReplaceAll(sb.String(), "d0", "n0")
	start := time.Now()
	res := Extract([]byte(src))
	elapsed := time.Since(start)
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("extractor.keys() took too long on adversarial DAG/cycles: %v", elapsed)
	}
	if len(res.Endpoints) != 1 || res.Endpoints[0].URL != "/api/stress-dag" {
		t.Fatalf("unexpected endpoints: %+v", res.Endpoints)
	}
}
