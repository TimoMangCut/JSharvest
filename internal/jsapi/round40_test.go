package jsapi

import (
	"slices"
	"strings"
	"testing"
)

func TestRound40ViteEnvObjectLiteralDestructuring(t *testing.T) {
	const hexA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const hexB = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	src := `
const {
  VITE_BASE_API_DOMAIN,
  VITE_MEDIA_API_URL,
  VITE_BASE_SAP_DECRYPT_PUBLIC_KEY,
  VITE_BASE_SAP_DECRYPT_PUBLIC_KEY_LAO,
  API_KEY_VN,
  API_KEY_LAO,
  TOKEN_TYPE,
  public_key_id,
  api_key_name
} = {
  VITE_BASE_API_DOMAIN: "https://api.staging.example.test",
  VITE_MEDIA_API_URL: "https://media-static.staging.example.test",
  VITE_BASE_SAP_DECRYPT_PUBLIC_KEY: "` + hexA + `",
  VITE_BASE_SAP_DECRYPT_PUBLIC_KEY_LAO: "` + hexB + `",
  API_KEY_VN: "AbCdEf0123456789GhIjKl",
  API_KEY_LAO: "enabled",
  TOKEN_TYPE: "Bearer",
  public_key_id: "0123456789abcdef0123456789abcdef",
  api_key_name: "0123456789abcdef0123456789abcdef",
  BASE_URL: "/",
  MODE: "production"
};
const { VITE_PAREN_API_DOMAIN } = ({ VITE_PAREN_API_DOMAIN: "https://paren.staging.example.test" });
const { VITE_FROZEN_API_DOMAIN } = Object.freeze({ VITE_FROZEN_API_DOMAIN: "https://frozen.staging.example.test" });

const ACCOUNT_API_URL = ` + "`${VITE_BASE_API_DOMAIN}/account/v1/public`" + `;
fetch(` + "`${ACCOUNT_API_URL}/supplier/profile`" + `);
fetch(` + "`${VITE_PAREN_API_DOMAIN}/v1/paren`" + `);
fetch(` + "`${VITE_FROZEN_API_DOMAIN}/v1/frozen`" + `);
`
	res := Extract([]byte(src))
	if res.Error != "" {
		t.Fatalf("Extract error: %s", res.Error)
	}

	var urls []string
	for _, ep := range res.Endpoints {
		urls = append(urls, ep.URL)
	}
	for _, want := range []string{
		"https://api.staging.example.test/account/v1/public/supplier/profile",
		"https://paren.staging.example.test/v1/paren",
		"https://frozen.staging.example.test/v1/frozen",
	} {
		if !slices.Contains(urls, want) {
			t.Fatalf("missing resolved endpoint %q; got %v", want, urls)
		}
	}

	if !slices.Contains(res.Bases, "https://api.staging.example.test") {
		t.Fatalf("expected https://api.staging.example.test in Result.Bases, got %v", res.Bases)
	}
	if slices.Contains(res.Bases, "https://media-static.staging.example.test") {
		t.Fatalf("media URL should stay excluded from Result.Bases, got %v", res.Bases)
	}

	gotKeys := map[string]string{}
	for _, k := range res.Keys {
		gotKeys[k.Name] = k.Value
	}
	if gotKeys["VITE_BASE_SAP_DECRYPT_PUBLIC_KEY"] != hexA {
		t.Fatalf("missing primary key, got %v", gotKeys)
	}
	if gotKeys["VITE_BASE_SAP_DECRYPT_PUBLIC_KEY_LAO"] != hexB {
		t.Fatalf("missing locale-suffixed hex key, got %v", gotKeys)
	}
	if gotKeys["API_KEY_VN"] != "AbCdEf0123456789GhIjKl" {
		t.Fatalf("missing locale-suffixed base64 key, got %v", gotKeys)
	}
	for _, bad := range []string{"API_KEY_LAO", "TOKEN_TYPE", "public_key_id", "api_key_name"} {
		if _, exists := gotKeys[bad]; exists {
			t.Fatalf("false-positive key %q captured in %v", bad, gotKeys)
		}
	}
}

func TestRound40DestructureDefaultIsFallbackOnly(t *testing.T) {
	// (a) object has property -> object value wins over default
	srcA := `
const { API_URL = "https://fallback.example.test" } = { API_URL: "https://api.example.test" };
fetch(` + "`${API_URL}/v1/items`" + `);
`
	resA := Extract([]byte(srcA))
	var urlsA []string
	for _, ep := range resA.Endpoints {
		urlsA = append(urlsA, ep.URL)
	}
	if !slices.Contains(urlsA, "https://api.example.test/v1/items") {
		t.Fatalf("case (a): want https://api.example.test/v1/items, got %v", urlsA)
	}
	if slices.Contains(urlsA, "https://fallback.example.test/v1/items") {
		t.Fatalf("case (a): default should not override present property, got %v", urlsA)
	}

	// (b) object lacks property -> default is used as fallback
	srcB := `
const { API_URL = "https://fallback.example.test" } = { MODE: "prod" };
fetch(` + "`${API_URL}/v1/items`" + `);
`
	resB := Extract([]byte(srcB))
	var urlsB []string
	for _, ep := range resB.Endpoints {
		urlsB = append(urlsB, ep.URL)
	}
	if !slices.Contains(urlsB, "https://fallback.example.test/v1/items") {
		t.Fatalf("case (b): want fallback URL when property missing, got %v", urlsB)
	}

	// (c) function param destructured with default -> caller-supplied value wins via fromCallersOf
	srcC := `
function load(e) {
  const { apiBase = "/fallback" } = e;
  return fetch(apiBase + "/orders");
}
load({ apiBase: "/real" });
`
	resC := Extract([]byte(srcC))
	var urlsC []string
	for _, ep := range resC.Endpoints {
		urlsC = append(urlsC, ep.URL)
	}
	if !slices.Contains(urlsC, "/real/orders") {
		t.Fatalf("case (c): caller value should win via fromCallersOf, got %v", urlsC)
	}
	if slices.Contains(urlsC, "/fallback/orders") {
		t.Fatalf("case (c): default should not override caller value, got %v", urlsC)
	}
}

func TestRound40AxiosClientMethodPerRequestBaseURL(t *testing.T) {
	src := `
const { VITE_BASE_API_DOMAIN } = { VITE_BASE_API_DOMAIN: "https://api.staging.example.test" };
const ACCOUNT_API_URL = ` + "`${VITE_BASE_API_DOMAIN}/account/v1/public`" + `;
const MISSION_API_URL = ` + "`${VITE_BASE_API_DOMAIN}/mission/v1/private`" + `;

const apiClient = axios.create({ baseURL: "https://default.example.test/legacy", timeout: 5000 });

apiClient.get("/supplier/profile", { baseURL: ACCOUNT_API_URL, params: { expand: "roles" } });
apiClient.post("/orders", { amount: 1 }, { baseURL: MISSION_API_URL });
apiClient.get("/dyn-path", { baseURL: window.RUNTIME_GW });
apiClient.get("/root-override", { baseURL: "/" });
apiClient.get("/default-path");
`
	res := Extract([]byte(src))
	if res.Error != "" {
		t.Fatalf("Extract error: %s", res.Error)
	}

	byURL := map[string]Endpoint{}
	for _, ep := range res.Endpoints {
		byURL[ep.Method+" "+ep.URL] = ep
	}

	// 1. GET with per-request ACCOUNT_API_URL
	getAcc, ok := byURL["GET https://api.staging.example.test/account/v1/public/supplier/profile"]
	if !ok {
		t.Fatalf("missing GET with ACCOUNT_API_URL; endpoints=%+v", res.Endpoints)
	}
	if !getAcc.Client {
		t.Fatalf("expected getAcc.Client=true")
	}
	for _, bk := range getAcc.BaseKeys {
		if strings.HasPrefix(bk, "client:") {
			t.Fatalf("per-request baseURL leaked instance BaseKey %q in %v", bk, getAcc.BaseKeys)
		}
	}

	// 2. POST with per-request MISSION_API_URL
	postMis, ok := byURL["POST https://api.staging.example.test/mission/v1/private/orders"]
	if !ok {
		t.Fatalf("missing POST with MISSION_API_URL; endpoints=%+v", res.Endpoints)
	}
	if !postMis.Client {
		t.Fatalf("expected postMis.Client=true")
	}
	for _, bk := range postMis.BaseKeys {
		if strings.HasPrefix(bk, "client:") {
			t.Fatalf("per-request baseURL leaked instance BaseKey %q in %v", bk, postMis.BaseKeys)
		}
	}

	// 3. Dynamic per-request baseURL: must NOT inherit default.example.test/legacy or client:apiClient
	dynEp, ok := byURL["GET {}/dyn-path"]
	if !ok {
		t.Fatalf("expected GET {}/dyn-path for dynamic per-request baseURL; endpoints=%+v", res.Endpoints)
	}
	if !dynEp.Client {
		t.Fatalf("expected dynEp.Client=true")
	}
	for _, bk := range dynEp.BaseKeys {
		if strings.HasPrefix(bk, "client:") {
			t.Fatalf("dynamic per-request baseURL leaked instance BaseKey %q in %v", bk, dynEp.BaseKeys)
		}
	}

	// 4. Root override { baseURL: "/" }: must stay /root-override without default.example.test/legacy or client:apiClient
	rootEp, ok := byURL["GET /root-override"]
	if !ok {
		t.Fatalf("expected GET /root-override for baseURL:\"/\"; endpoints=%+v", res.Endpoints)
	}
	for _, bk := range rootEp.BaseKeys {
		if strings.HasPrefix(bk, "client:") {
			t.Fatalf("baseURL:\"/\" leaked instance BaseKey %q in %v", bk, rootEp.BaseKeys)
		}
	}

	// 5. Call without per-request baseURL still inherits instance baseURL
	if _, ok := byURL["GET https://default.example.test/legacy/default-path"]; !ok {
		t.Fatalf("call without per-request baseURL lost instance prefix; endpoints=%+v", res.Endpoints)
	}
}
