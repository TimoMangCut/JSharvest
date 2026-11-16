package jsapi

import (
	"fmt"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// JSAPI_DUMP=glob go test -run TestDump -v ./internal/jsapi prints what
// Extract finds in files, for looking at real bundles.
func TestDump(t *testing.T) {
	g := os.Getenv("JSAPI_DUMP")
	if g == "" {
		t.Skip("JSAPI_DUMP not set")
	}
	files, _ := filepath.Glob(g)
	for _, f := range files {
		src, _ := os.ReadFile(f)
		start := time.Now()
		r := Extract(src)
		fmt.Printf("== %s: %d bytes, %d endpoints, %s %s\n", f, len(src), len(r.Endpoints), time.Since(start), r.Error)
		for _, e := range r.Endpoints {
			fmt.Printf("  %-7s %-45s %-10s client=%v q=%v b=%v h=%v ops=%v @%d:%d\n", e.Method, e.URL, e.Kind, e.Client, e.Query, e.Body, e.Headers, e.Operations, e.Line, e.Col)
		}
		if os.Getenv("JSAPI_DUMP_ALL") != "" || len(files) < 4 {
			fmt.Println("  routes:", strings.Join(r.Routes, " "), "bases:", r.Bases, "ops:", r.Operations)
		}
	}
}

// JSAPI_STATS=listfile go test -run TestStats -v ./internal/jsapi reads
// the files listed (one per line) and prints totals, parse errors, and
// every endpoint found, for judging noise on code that is not an app's.
func TestStats(t *testing.T) {
	list := os.Getenv("JSAPI_STATS")
	if list == "" {
		t.Skip("JSAPI_STATS not set")
	}
	b, _ := os.ReadFile(list)
	var files, bytes, errs int
	var took time.Duration
	kinds := map[string]int{}
	for _, f := range strings.Fields(string(b)) {
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		files++
		bytes += len(src)
		start := time.Now()
		r := Extract(src)
		took += time.Since(start)
		if r.Error != "" {
			errs++
			fmt.Printf("ERR %s: %s\n", f, r.Error)
		}
		for _, e := range r.Endpoints {
			kinds[e.Kind]++
			fmt.Printf("EP %-7s %-60.60s %-10s %s\n", e.Method, e.URL, e.Kind, f)
		}
	}
	fmt.Printf("files %d, %.1f MB, %s (%.1f MB/s), parse errors %d, endpoints by kind %v\n",
		files, float64(bytes)/1e6, took, float64(bytes)/1e6/took.Seconds(), errs, kinds)
}

func TestParseSpeed(t *testing.T) {
	list := os.Getenv("JSAPI_STATS")
	if list == "" {
		t.Skip("JSAPI_STATS not set")
	}
	b, _ := os.ReadFile(list)
	var parseT, allT time.Duration
	var n int
	for _, f := range strings.Fields(string(b)) {
		src, _ := os.ReadFile(f)
		n += len(src)
		s := time.Now()
		js.Parse(parse.NewInputBytes(src), js.Options{})
		parseT += time.Since(s)
		s = time.Now()
		Extract(src)
		allT += time.Since(s)
	}
	fmt.Printf("%.1f MB: parse %s (%.1f MB/s), extract %s (%.1f MB/s)\n", float64(n)/1e6, parseT, float64(n)/1e6/parseT.Seconds(), allT, float64(n)/1e6/allT.Seconds())
}
