package archive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

type historyBenchResult struct {
	ColdLog     string
	ColdDur     time.Duration
	WarmDiskLog string
	WarmDiskDur time.Duration
	WarmMemLog  string
	WarmMemDur  time.Duration
	Endpoints   []byte
	Historical  []byte
}

func copyFileRO(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, cerr := io.Copy(out, in)
	if err := out.Close(); cerr == nil {
		cerr = err
	}
	return cerr
}

func linkOrCopyDirRO(srcDir, dstDir string) error {
	if err := os.Symlink(srcDir, dstDir); err == nil {
		return nil
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if err := copyFileRO(filepath.Join(srcDir, ent.Name()), filepath.Join(dstDir, ent.Name())); err != nil {
			return err
		}
	}
	return nil
}

func runHistoryBenchCopy(t *testing.T, srcArchiveDir, srcRootDir, host string) historyBenchResult {
	t.Helper()
	inScope, err := scope.New(host, "rdn")
	if err != nil {
		inScope = func(string) bool { return true }
	}

	tmpRoot := t.TempDir()
	workHostDir := filepath.Join(tmpRoot, host)
	workArchiveDir := filepath.Join(workHostDir, "archive")
	if err := os.MkdirAll(workArchiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyFileRO(filepath.Join(srcArchiveDir, "index.jsonl"), filepath.Join(workArchiveDir, "index.jsonl")); err != nil {
		t.Fatalf("copy index.jsonl: %v", err)
	}
	if _, err := os.Stat(filepath.Join(srcArchiveDir, "requests.jsonl")); err == nil {
		_ = copyFileRO(filepath.Join(srcArchiveDir, "requests.jsonl"), filepath.Join(workArchiveDir, "requests.jsonl"))
	}
	if _, err := os.Stat(filepath.Join(srcArchiveDir, "js")); err == nil {
		if err := linkOrCopyDirRO(filepath.Join(srcArchiveDir, "js"), filepath.Join(workArchiveDir, "js")); err != nil {
			t.Fatalf("prepare js/: %v", err)
		}
	}

	// Link sibling crawl role dirs read-only if available so classifyCtx runs
	// against the exact current crawl catalogs without modifying source data.
	if srcRootDir != "" {
		if hostDirs, err := os.ReadDir(srcRootDir); err == nil {
			for _, hd := range hostDirs {
				if !hd.IsDir() || !inScope(hostOnly(hd.Name())) {
					continue
				}
				roles, _ := os.ReadDir(filepath.Join(srcRootDir, hd.Name()))
				for _, rd := range roles {
					if !rd.IsDir() || rd.Name() == "archive" {
						continue
					}
					srcRole := filepath.Join(srcRootDir, hd.Name(), rd.Name())
					dstParent := filepath.Join(tmpRoot, hd.Name())
					_ = os.MkdirAll(dstParent, 0o700)
					dstRole := filepath.Join(dstParent, rd.Name())
					if _, err := os.Lstat(dstRole); err != nil {
						_ = os.Symlink(srcRole, dstRole)
					}
				}
			}
		}
	}

	st, err := store.Open(workArchiveDir, store.Options{MaxBody: 32 << 20})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	cur := loadCurrent(tmpRoot, inScope)

	runOnce := func() (string, time.Duration, []byte, []byte) {
		var lastLog string
		r := &runner{
			o: Options{
				Dir:     workArchiveDir,
				Root:    tmpRoot,
				Host:    host,
				InScope: inScope,
				Log: func(format string, args ...any) {
					msg := fmt.Sprintf(format, args...)
					if strings.HasPrefix(msg, "history timings:") {
						lastLog = msg
					}
				},
			},
			store: st,
			cur:   cur,
		}
		r.st.Summary.Historical = map[string]int{}
		t0 := time.Now()
		if err := r.history(context.Background()); err != nil {
			t.Fatalf("history(): %v", err)
		}
		dur := time.Since(t0)
		epBytes, err := os.ReadFile(filepath.Join(workArchiveDir, endpoints.File))
		if err != nil {
			t.Fatalf("read endpoints.jsonl: %v", err)
		}
		histBytes, err := os.ReadFile(filepath.Join(workArchiveDir, "historical.jsonl"))
		if err != nil {
			t.Fatalf("read historical.jsonl: %v", err)
		}
		return lastLog, dur, epBytes, histBytes
	}

	// Pass 1: Cold (no static/ directory, empty memory caches).
	_ = os.RemoveAll(filepath.Join(workArchiveDir, endpoints.CacheDir))
	endpoints.ClearResultMemCache()
	endpoints.ClearMemCache()
	coldLog, coldDur, coldEp, coldHist := runOnce()

	// Pass 2a: Warm disk static/*.json, cold memory caches.
	endpoints.ClearResultMemCache()
	endpoints.ClearMemCache()
	warmDiskLog, warmDiskDur, warmDiskEp, warmDiskHist := runOnce()

	// Pass 2b: Warm disk static/*.json + warm memory caches (same-process post-fetch).
	warmMemLog, warmMemDur, warmMemEp, warmMemHist := runOnce()

	if !bytes.Equal(coldEp, warmDiskEp) || !bytes.Equal(coldEp, warmMemEp) {
		t.Fatalf("endpoints.jsonl drifted between cold and warm runs")
	}
	if !bytes.Equal(coldHist, warmDiskHist) || !bytes.Equal(coldHist, warmMemHist) {
		t.Fatalf("historical.jsonl drifted between cold and warm runs")
	}

	return historyBenchResult{
		ColdLog:     coldLog,
		ColdDur:     coldDur,
		WarmDiskLog: warmDiskLog,
		WarmDiskDur: warmDiskDur,
		WarmMemLog:  warmMemLog,
		WarmMemDur:  warmMemDur,
		Endpoints:   coldEp,
		Historical:  coldHist,
	}
}

// B1 (round 38): synthetic unit test ensuring the offline history timing
// harness compiles, logs all 4 stages, touches zero network, and preserves
// byte-identical outputs across cold and pre-warmed passes.
func TestRound38HistoryTimingHarnessSynthetic(t *testing.T) {
	srcRoot := t.TempDir()
	host := "portal.example.test"
	liveAnon := filepath.Join(srcRoot, host, "anon")
	srcArch := filepath.Join(srcRoot, host, "archive")
	if err := os.MkdirAll(liveAnon, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(srcArch, 0o700); err != nil {
		t.Fatal(err)
	}

	liveStore, err := store.Open(liveAnon, store.Options{MaxBody: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := liveStore.Add(store.Record{
		Body:   []byte(`fetch("https://portal.example.test/api/v2/current");`),
		URL:    "https://portal.example.test/app.js",
		Kind:   "file",
		Source: "live",
	}); err != nil {
		t.Fatal(err)
	}
	if err := liveStore.Flush(); err != nil {
		t.Fatal(err)
	}
	inScope, _ := scope.New(host, "rdn")
	liveScripts, err := endpoints.AnalyzeSlim(liveAnon, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoints.Write(liveAnon, endpoints.Assemble(liveAnon, liveScripts, nil, inScope)); err != nil {
		t.Fatal(err)
	}

	archStore, err := store.Open(srcArch, store.Options{MaxBody: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := archStore.Add(store.Record{
		Body:   []byte(`axios.post("/api/v1/legacy-export", { format: "csv" });`),
		URL:    "https://portal.example.test/legacy.js",
		Kind:   "file",
		Via:    "archive",
		Source: "wayback",
		Tags:   []string{"archive"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := archStore.Add(store.Record{
		Body:   []byte(`export async function loadAudit(id: string) { return fetch("/api/v1/audit/" + id); }`),
		URL:    "https://portal.example.test/legacy.js.map#src/audit.ts",
		Kind:   "source",
		Via:    "archive-sourcemap",
		Source: "wayback",
		Tags:   []string{"archive", "sourcemap", "source:src/audit.ts"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := archStore.Flush(); err != nil {
		t.Fatal(err)
	}

	res := runHistoryBenchCopy(t, srcArch, srcRoot, host)
	for _, lg := range []string{res.ColdLog, res.WarmDiskLog, res.WarmMemLog} {
		for _, field := range []string{"history timings:", "scripts=2", "analyze=", "assemble=", "intel=", "classify="} {
			if !strings.Contains(lg, field) {
				t.Fatalf("missing %q in log %q", field, lg)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(srcArch, endpoints.CacheDir)); !os.IsNotExist(err) {
		t.Fatalf("source archive dir was modified (static/ created in source)")
	}
	if !bytes.Contains(res.Historical, []byte("/api/v1/legacy-export")) || !bytes.Contains(res.Historical, []byte("/api/v1/audit/")) {
		t.Fatalf("expected historical endpoints from both JS and TS map source, got:\n%s", res.Historical)
	}
}

// TestHistoryOfflineBench runs offline timing against an existing archive
// directory when JSH_HISTORY_BENCH=<path/to/<host>/archive> is set.
func TestHistoryOfflineBench(t *testing.T) {
	srcArch := strings.TrimSpace(os.Getenv("JSH_HISTORY_BENCH"))
	if srcArch == "" {
		t.Skip("set JSH_HISTORY_BENCH=<archive-dir> to run offline history benchmark")
	}
	srcArch = filepath.Clean(srcArch)
	hostDir := filepath.Dir(srcArch)
	host := hostOnly(filepath.Base(hostDir))
	srcRoot := filepath.Dir(hostDir)
	if filepath.Base(srcArch) != "archive" || host == "" {
		host = "example.test"
		srcRoot = ""
	}
	res := runHistoryBenchCopy(t, srcArch, srcRoot, host)
	t.Logf("COLD      (%s): %s", res.ColdDur.Round(time.Millisecond), res.ColdLog)
	t.Logf("WARM-DISK (%s): %s", res.WarmDiskDur.Round(time.Millisecond), res.WarmDiskLog)
	t.Logf("WARM-MEM  (%s): %s", res.WarmMemDur.Round(time.Millisecond), res.WarmMemLog)
}
