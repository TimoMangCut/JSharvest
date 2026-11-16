package jsapi

import (
	"encoding/base64"
	"testing"
)

func TestTier2SecretSignatures(t *testing.T) {
	const (
		gmapsKey  = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
		stripeKey = "pk_live_51N1A2B3C4D5E6F7G8H9I0J1K"
		// Split synthetic prefix in source to avoid false positives from repo secret scanners.
		sgKey     = "SG" + ".a1B2c3D4e5F6g7H8i9J0k1." + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V"
		mapboxKey = "pk.eyJ1IjoiZGVtb3VzZXIiLCJhIjoiY2x4MTIzNDUifQ.a1B2c3D4e5F6g7H8i9J0k1"
		sentryDSN = "https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o450123.ingest.sentry.io/450999"
		dummyGKey = "AIzaSyDUMMY0000000000000000000000000000"
	)
	b64Cfg := base64.StdEncoding.EncodeToString([]byte(`{"maps":"` + mapboxKey + `"}`))
	src := `const uiCols = [{ key: "id" }, { key: "status" }];
const loader = new Loader({ key: "` + gmapsKey + `", version: "weekly" });
const stripe = loadStripe("` + stripeKey + `");
const sg = ` + "`" + sgKey + "`" + `;
const boot = "` + b64Cfg + `";
Sentry.init("` + sentryDSN + `");
const example = { key: "` + dummyGKey + `", aws: "AKIAIOSFODNN7EXAMPLE" };
const tier1 = { clientSecret: "plain_non_prefixed_secret_99" };
`
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("Extract error: %s", r.Error)
	}

	byNameVal := map[string]Header{}
	for _, k := range r.Keys {
		byNameVal[k.Name+"="+k.Value] = k
	}

	want := []struct {
		name string
		val  string
		line int
	}{
		{"key", gmapsKey, 2},
		{"stripe_key", stripeKey, 3},
		{"sendgrid_key", sgKey, 4},
		{"maps", mapboxKey, 5},
		{"sentry_dsn", sentryDSN, 6},
		{"clientSecret", "plain_non_prefixed_secret_99", 8},
	}
	for _, w := range want {
		got, ok := byNameVal[w.name+"="+w.val]
		if !ok {
			t.Errorf("missing key %s=%s; got Keys=%+v", w.name, w.val, r.Keys)
			continue
		}
		if got.Line != w.line {
			t.Errorf("key %s line = %d, want %d", w.name, got.Line, w.line)
		}
	}

	for _, k := range r.Keys {
		if k.Value == "id" || k.Value == "status" {
			t.Errorf("UI table key leaked into Keys: %+v", k)
		}
		if k.Value == dummyGKey || k.Value == "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("documentation placeholder leaked into Keys: %+v", k)
		}
	}
}
