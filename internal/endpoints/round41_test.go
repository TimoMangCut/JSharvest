package endpoints

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

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

func TestRound41ParseWatchdogWarnsWithoutChangingResult(t *testing.T) {
	t.Setenv("JSHARVEST_PARSE_WATCHDOG", "10ms")
	var logBuf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prev)

	// Build an input slow enough (>10ms) without exceeding limits.
	slow := bytes.Repeat([]byte("fetch(\"/api/v1/items\");\n"), 8000)
	stop := startParseWatchdog(slow, "slow.js")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(logBuf.String(), "JSHARVEST_PARSE_WATCHDOG") {
		time.Sleep(5 * time.Millisecond)
	}
	stop()

	res := extractJS([]byte(`fetch("/api/v1/ok")`), "ok.js", nil)
	if len(res.Endpoints) != 1 || res.Endpoints[0].URL != "/api/v1/ok" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !strings.Contains(logBuf.String(), "JSHARVEST_PARSE_WATCHDOG") {
		t.Fatalf("expected watchdog warning in log, got %q", logBuf.String())
	}
}
