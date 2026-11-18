package endpoints

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

func TestOversizeMonolithBundleUsesExtractLooseFallback(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Construct a ~17 MiB (> 16 MiB maxScript, <= 64 MiB maxLooseScript) monolith bundle.
	var buf bytes.Buffer
	buf.Grow(17 << 20)
	buf.WriteString("// monolith header\n")
	pad := strings.Repeat("/* padding_block_0123456789abcdef_0123456789abcdef */\n", 320000)
	buf.WriteString(pad)
	buf.WriteString(`function syncOrders(){ return fetch("/api/v2/monolith/orders", {method: "POST"}); }` + "\n")

	if buf.Len() <= maxScript {
		t.Fatalf("expected test bundle > maxScript (%d), got %d", maxScript, buf.Len())
	}
	if _, err := st.Add(store.Record{
		Body:   buf.Bytes(),
		URL:    "https://app.example.test/monolith.bundle.js",
		Kind:   "file",
		Via:    "network",
		Source: "live",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}

	eps, stats, err := CatalogWithStats(dir, func(h string) bool { return h == "app.example.test" }, true)
	if err != nil {
		t.Fatalf("CatalogWithStats failed: %v", err)
	}
	if stats.OversizeLooseFallback != 1 || stats.OversizeSkipped != 0 || stats.BundleParseErrors != 0 {
		t.Fatalf("unexpected AnalyzeStats for 17 MiB monolith: %+v", stats)
	}
	found := false
	for _, ep := range eps {
		if ep.Path == "/api/v2/monolith/orders" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected /api/v2/monolith/orders recovered via ExtractLoose on >16 MiB monolith, got %+v", eps)
	}
}

func TestEstimateResultBytesReflectsLargePayloads(t *testing.T) {
	bigQuery := strings.Repeat("query Big { field }\n", 110000) // ~2.2 MB
	r := jsapi.Result{
		Version:     jsapi.Version,
		GraphQLDocs: []jsapi.GraphQLDoc{{Name: "Big", Kind: "query", Query: bigQuery}},
		ConstExports: []jsapi.ConstDict{{
			Module: "1",
			Export: "a",
			Values: map[string]string{"HUGE": strings.Repeat("x", 512<<10)},
		}},
	}
	cost := estimateResultBytes(r)
	if cost < int64(len(bigQuery)+(512<<10)) {
		t.Fatalf("estimateResultBytes(%d) undercounted real string payload (%d)", cost, len(bigQuery)+(512<<10))
	}
}

func TestP3CJSNestedAndCASLCanVarsAndJSXCanCrossChunk(t *testing.T) {
	// Chunk 1: CJS module exporting nested constant objects via module.exports.
	cjsConsts := []byte(`
		(window.webpackJsonp = window.webpackJsonp || []).push([[1], {
			"9999": function(e, t) {
				e.exports = {
					PERMISSION: { READ: "invoice:read", WRITE: "invoice:write", EXPORT: "invoice:export" },
					ENTITY: { INVOICE: "Invoice" }
				};
			}
		}]);
	`)
	// Chunk 2: Direct CJS require (`var c = n("9999")`) WITHOUT `n.n`, using:
	// - destructured `const { can } = useAbility(); can(c.PERMISSION.READ, c.ENTITY.INVOICE)`
	// - JSX `_jsx(Can, { I: c.PERMISSION.WRITE, a: c.ENTITY.INVOICE })`
	// - arrow without parens `defineAbility(can => { can(c.PERMISSION.EXPORT, c.ENTITY.INVOICE) })`
	appChunk := []byte(`
		(window.webpackJsonp = window.webpackJsonp || []).push([[2], {
			"2001": function(e, t, n) {
				var c = n("9999");
				const { can } = useAbility();
				if (can(c.PERMISSION.READ, c.ENTITY.INVOICE)) {
					fetch("/api/v1/invoices");
				}
				const view = _jsx(Can, { I: c.PERMISSION.WRITE, a: c.ENTITY.INVOICE });
				defineAbility(can => {
					can(c.PERMISSION.EXPORT, c.ENTITY.INVOICE);
				});
			}
		}]);
	`)

	r1 := jsapi.Extract(cjsConsts)
	r2 := jsapi.Extract(appChunk)
	scripts := []Script{
		{Result: r1, SHA256: "sha9999", URLs: []string{"https://portal.example.test/consts.js"}},
		{Result: r2, SHA256: "sha2001", URLs: []string{"https://portal.example.test/app.js"}},
	}
	in := BuildIntel(scripts, func(h string) bool { return h == "portal.example.test" })
	if in.ClientAuthz == nil {
		t.Fatalf("expected ClientAuthz to be populated")
	}
	for _, wantAction := range []string{"invoice:read", "invoice:write", "invoice:export"} {
		want := jsapi.AuthzRule{Action: wantAction, Subject: "Invoice"}
		if !slices.Contains(in.ClientAuthz.Rules, want) {
			t.Errorf("missing cross-chunk CASL rule %+v in %+v", want, in.ClientAuthz.Rules)
		}
	}
}

func TestJSAPIDropsCRLFAndInvalidHeaderTokens(t *testing.T) {
	code := []byte(`
		const h = new Headers();
		h.set("X-Valid-Client", "web-portal");
		h.set("X-Injected", "ok\r\nX-Admin: true");
		h.set("Bad Name\r\n", "123");
		fetch("/api/v1/profile", { headers: h });
	`)
	res := jsapi.Extract(code)
	if len(res.ClientHeaders) != 1 || res.ClientHeaders[0].Name != "X-Valid-Client" || res.ClientHeaders[0].Value != "web-portal" {
		t.Fatalf("expected only X-Valid-Client to survive CRLF/token sanitization, got %+v", res.ClientHeaders)
	}
}
