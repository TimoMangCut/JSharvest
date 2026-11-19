package endpoints

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// B2 (round 38): 8 goroutines calling ExtractCached concurrently on the same
// SHA-256 parse the AST once (singleflight) and write static/<sha>.json cleanly,
// and concurrent heavy bundles (>= heavyScriptBytes) obey extractHeavySem's cap.
func TestRound38ExtractCachedSingleflight(t *testing.T) {
	ClearResultMemCache()
	ClearMemCache()

	var parses atomic.Int64
	hook := func() {
		parses.Add(1)
		time.Sleep(40 * time.Millisecond)
	}
	testExtractHook.Store(&hook)
	defer testExtractHook.Store(nil)

	dirA := t.TempDir()
	dirB := t.TempDir()
	body := []byte(`export function loadUsers() { return fetch("/api/v2/users"); }`)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			targetDir := dirA
			if idx%2 == 1 {
				targetDir = dirB
			}
			res := ExtractCached(targetDir, body, "https://app.example.test/main.js")
			if len(res.Endpoints) == 0 {
				t.Errorf("goroutine %d got 0 endpoints", idx)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := parses.Load(); got != 1 {
		t.Fatalf("ExtractCached parsed same SHA %d times across 8 goroutines, want 1", got)
	}
	for _, d := range []string{dirA, dirB} {
		entries, err := os.ReadDir(filepath.Join(d, CacheDir))
		if err != nil || len(entries) != 1 {
			t.Fatalf("expected 1 static cache file in %s, got %v (%v)", d, entries, err)
		}
	}

	// Also verify extractHeavySem bounds concurrent parses of distinct heavy scripts.
	ClearResultMemCache()
	var inflight, peak atomic.Int32
	semHook := func() {
		cur := inflight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		inflight.Add(-1)
	}
	testExtractHook.Store(&semHook)

	pad := strings.Repeat("// padding comment to exceed heavyScriptBytes\n", (heavyScriptBytes/44)+16)
	var hwg sync.WaitGroup
	for i := range 8 {
		hwg.Add(1)
		src := []byte(fmt.Sprintf("%s\nfetch('/api/heavy/%d');\n", pad, i))
		go func(b []byte) {
			defer hwg.Done()
			_ = ExtractCached("", b, "https://app.example.test/heavy.js")
		}(src)
	}
	hwg.Wait()

	maxAllowed := int32(cap(extractHeavySem))
	if gotPeak := peak.Load(); gotPeak > maxAllowed || gotPeak < 1 {
		t.Fatalf("concurrent heavy ExtractCached peak = %d, want 1..%d", gotPeak, maxAllowed)
	}
}
