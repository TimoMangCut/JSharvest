package jsapi_test

import (
	"slices"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/verify"
)

func TestExtractNextServerActions(t *testing.T) {
	src := []byte(`
		const a1 = (0, r.createServerReference)("40a1b2c3d4e5f60718293a4b5c6d7e8f90123456", r.callServer, void 0, r.findSourceMapURL, "updateProfile");
		const a2 = Object(s.registerServerReference)(fn, "40FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "deleteWorkspace");
		const ignoreBad = createServerReference("not-hex", r.callServer);
	`)
	res := jsapi.Extract(src)
	if res.Error != "" {
		t.Fatalf("Extract error: %s", res.Error)
	}
	var rpcEps []jsapi.Endpoint
	for _, ep := range res.Endpoints {
		if ep.Kind == "rpc" {
			rpcEps = append(rpcEps, ep)
		}
	}
	if len(rpcEps) != 1 {
		t.Fatalf("got %d rpc endpoints (%+v), want 1 merged POST / with 2 Next-Action operations", len(rpcEps), rpcEps)
	}
	ep := rpcEps[0]
	if ep.Method != "POST" || ep.URL != "/" || !ep.NoInheritBase {
		t.Fatalf("unexpected endpoint shape: %+v", ep)
	}
	wantOps := []string{
		"next-action=40a1b2c3d4e5f60718293a4b5c6d7e8f90123456",
		"next-action=40ffffffffffffffffffffffffffffffffffffff",
	}
	if !slices.Equal(ep.Operations, wantOps) {
		t.Fatalf("Operations = %v, want %v", ep.Operations, wantOps)
	}
	if !slices.Contains(ep.Headers, "Next-Action") {
		t.Fatalf("Headers = %v, want Next-Action", ep.Headers)
	}

	// Verify catalog -> verify.Drafts produces two distinct drafts, each carrying its own Next-Action header.
	cat := endpoints.Build([]endpoints.Script{{
		Result: res,
		SHA256: "deadbeef",
		URLs:   []string{"https://app.example.com/_next/static/chunks/app/settings/page.js"},
	}}, nil, func(h string) bool { return h == "app.example.com" })
	ds := verify.Drafts(verify.Inputs{
		Catalog: cat,
		InScope: func(h string) bool { return h == "app.example.com" },
	})
	if len(ds) != 2 {
		t.Fatalf("verify.Drafts count = %d (%+v), want 2", len(ds), ds)
	}
	for i, wantHex := range []string{
		"40a1b2c3d4e5f60718293a4b5c6d7e8f90123456",
		"40ffffffffffffffffffffffffffffffffffffff",
	} {
		if ds[i].Operation != "next-action="+wantHex {
			t.Fatalf("draft[%d].Operation = %q, want next-action=%s", i, ds[i].Operation, wantHex)
		}
		gotHdr := ""
		for _, h := range ds[i].Headers {
			if h[0] == "Next-Action" {
				gotHdr = h[1]
			}
		}
		if gotHdr != wantHex {
			t.Fatalf("draft[%d] Next-Action header = %q, want %q (headers=%v)", i, gotHdr, wantHex, ds[i].Headers)
		}
	}
}
