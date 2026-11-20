package endpoints

import (
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func TestRound41SummarizeScriptsCountsLooseTruncated(t *testing.T) {
	scripts := []Script{
		{
			SHA256: "1111111111111111",
			Result: jsapi.Result{Version: jsapi.Version, LooseFallback: true, LooseTruncated: true, ParseError: "oversize_ast_bypass: 20000000 bytes"},
		},
		{
			SHA256: "2222222222222222",
			Source: true,
			Result: jsapi.Result{Version: jsapi.Version, LooseFallback: true, LooseTruncated: true, ParseError: "parse: syntax error"},
		},
		{
			SHA256: "3333333333333333",
			Result: jsapi.Result{Version: jsapi.Version, LooseFallback: true, LooseTruncated: true, ParseError: "parse: syntax error"},
		},
		{
			SHA256: "4444444444444444",
			Result: jsapi.Result{Version: jsapi.Version, Error: "not analysed: 70000000 bytes", LooseTruncated: true},
		},
	}
	st := SummarizeScripts(scripts)
	if st.OversizeLooseFallback != 1 || st.SourceParseFallback != 1 || st.BundleParseErrors != 1 || st.OversizeSkipped != 1 {
		t.Fatalf("unexpected fallback stats: %+v", st)
	}
	if st.LooseTruncated != 3 {
		t.Fatalf("LooseTruncated=%d, want 3 (oversize + source + bundle)", st.LooseTruncated)
	}
}
