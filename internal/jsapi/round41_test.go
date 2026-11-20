package jsapi

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func isRaceBuild() bool {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "-race" && s.Value == "true" {
				return true
			}
		}
	}
	return false
}

func TestRound41LooseLineColUnchanged(t *testing.T) {
	// Include line 1, empty lines, indented calls, paths, and a final line with no trailing newline.
	src := []byte("fetch(\"/api/v1/first\");\n" +
		"\n" +
		"  axios.post('/api/v1/third?x=1');\n" +
		"// comment\n" +
		"// comment\n" +
		"// comment\n" +
		"    const p = \"/api/v1/seventh\";\n" +
		"const tail = `/api/v1/last`")

	oldLineCol := func(off int) (int, int) {
		before := src[:off]
		line := bytes.Count(before, []byte("\n")) + 1
		col := off - (bytes.LastIndexByte(before, '\n') + 1)
		return line, col
	}
	nl := lineStarts(src)
	for off := 0; off <= len(src); off++ {
		wantLine, wantCol := oldLineCol(off)
		idx := 0
		for idx+1 < len(nl) && nl[idx+1] <= off {
			idx++
		}
		gotLine, gotCol := idx+1, off-nl[idx]
		if gotLine != wantLine || gotCol != wantCol {
			t.Fatalf("off=%d: got (%d,%d), want (%d,%d)", off, gotLine, gotCol, wantLine, wantCol)
		}
	}

	res := ExtractLoose(src)
	if res.LooseTruncated {
		t.Fatalf("unexpected LooseTruncated on small input")
	}
	type pos struct {
		method, url string
		line, col   int
	}
	want := []pos{
		{"GET", "/api/v1/first", 1, 0},
		{"POST", "/api/v1/third", 3, 2},
		{"", "/api/v1/seventh", 7, 14},
		{"", "/api/v1/last", 8, 13},
	}
	if len(res.Endpoints) != len(want) {
		t.Fatalf("got %d endpoints (%+v), want %d", len(res.Endpoints), res.Endpoints, len(want))
	}
	for i, w := range want {
		e := res.Endpoints[i]
		if e.Method != w.method || e.URL != w.url || e.Line != w.line || e.Col != w.col {
			t.Errorf("endpoint[%d] = (%s %s @ %d:%d), want (%s %s @ %d:%d)",
				i, e.Method, e.URL, e.Line, e.Col, w.method, w.url, w.line, w.col)
		}
	}
}

func TestRound41LooseLinearTime(t *testing.T) {
	var b bytes.Buffer
	b.Grow(4 << 20)
	for i := 0; b.Len() < 4<<20; i++ {
		fmt.Fprintf(&b, "\"/a/b%d\",\n", i)
	}
	src := b.Bytes()

	start := time.Now()
	res := ExtractLoose(src)
	took := time.Since(start)
	limit := 2 * time.Second
	if isRaceBuild() {
		// Go's race detector instruments regexp's NFA queue ~18x slower; old O(N^2)
		// code took >1,300s without -race (~0.75s now, ~14s under -race).
		limit = 30 * time.Second
	}
	if took > limit {
		t.Fatalf("ExtractLoose on 4 MiB hostile input took %s, want <= %s", took, limit)
	}
	if !res.LooseTruncated {
		t.Fatalf("expected LooseTruncated=true on 4 MiB hostile input")
	}
	if len(res.Endpoints) != maxLooseEndpoints {
		t.Fatalf("len(Endpoints)=%d, want %d", len(res.Endpoints), maxLooseEndpoints)
	}
}

func TestRound41LooseTruncatedFlags(t *testing.T) {
	t.Run("small", func(t *testing.T) {
		var b strings.Builder
		for i := range 100 {
			fmt.Fprintf(&b, "\"/api/item%d\",\n", i)
		}
		res := ExtractLoose([]byte(b.String()))
		if res.LooseTruncated || len(res.Endpoints) != 100 {
			t.Fatalf("small: truncated=%v len=%d", res.LooseTruncated, len(res.Endpoints))
		}
	})

	t.Run("match_cap_stops_second_regex", func(t *testing.T) {
		// 55,000 identical fetch calls: hits maxLooseMatches (50,000) in loop 1
		// with only 1 unique endpoint, and rem == 0 prevents loop 2 from running
		// or passing a negative count to FindAllSubmatchIndex.
		var b strings.Builder
		b.Grow(55_000 * 24)
		for range 55_000 {
			b.WriteString("fetch(\"/api/same\");\n")
		}
		b.WriteString("\"/api/after_cap\"\n")
		res := ExtractLoose([]byte(b.String()))
		if !res.LooseTruncated {
			t.Fatalf("expected LooseTruncated=true when matches exceed %d", maxLooseMatches)
		}
		if len(res.Endpoints) != 1 || res.Endpoints[0].URL != "/api/same" {
			t.Fatalf("unexpected endpoints after match cap: %+v", res.Endpoints)
		}
	})

	t.Run("endpoint_cap_under_match_cap", func(t *testing.T) {
		// 25,000 unique paths (< maxLooseMatches=50,000, > maxLooseEndpoints=20,000),
		// plus an upgrade on an already-seen endpoint at capacity.
		var b strings.Builder
		b.Grow(25_005 * 24)
		b.WriteString("client(\"/api/u0\");\n") // Kind="string", Method=""
		for i := 1; i < 25_000; i++ {
			fmt.Fprintf(&b, "\"/api/u%d\",\n", i)
		}
		res := ExtractLoose([]byte(b.String()))
		if !res.LooseTruncated {
			t.Fatalf("expected LooseTruncated=true when unique endpoints exceed %d", maxLooseEndpoints)
		}
		if len(res.Endpoints) != maxLooseEndpoints {
			t.Fatalf("len(Endpoints)=%d, want %d", len(res.Endpoints), maxLooseEndpoints)
		}
	})
}

func TestRound41MaxNestingLexer(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"strings_and_comments", `const s = "((((([[[{{"; /* [[[[ */ // ((((`, 0},
		{"regex_and_char_class", `const r = /\(\[\{[/([{]/g; const y = (1 + 2) / 3;`, 1},
		{"keyword_regex", `function f() { return /((((/.test("x"); }`, 2},
		{"template_interp", "const t = `(((( ${a + `${b + (1)}`} ]]]]`;", 3},
		{"nested_arrays", `[[[1]]]`, 3},
	}
	for _, tc := range cases {
		got, over := maxNesting([]byte(tc.src), 100)
		if over || got != tc.want {
			t.Errorf("%s: maxNesting=%d over=%v, want %d false", tc.name, got, over, tc.want)
		}
	}
	if _, over := maxNesting([]byte(strings.Repeat("[", 401)+strings.Repeat("]", 401)), maxEsbuildNesting); !over {
		t.Fatal("expected over=true at 401 levels")
	}
}

func TestRound41DeepNestingSkipsEsbuild(t *testing.T) {
	if os.Getenv("JSHARVEST_TEST_DEEP_SUBPROC") == "1" {
		deep := strings.Repeat("[", 1_000_000) + strings.Repeat("]", 1_000_000)
		for _, tc := range []struct {
			hint string
			body string
		}{
			{"app.js", deep},
			{"app.ts", "const x: any = " + deep},
			{"App.vue", "<script lang=\"ts\">\nconst x: any = " + deep + "\n</script>"},
			{"Two.vue", "<script lang=\"ts\">\nconst a = 1;\n</script>\n<script setup lang=\"ts\">\nconst x: any = " + deep + "\n</script>"},
		} {
			r := ExtractSource([]byte(tc.body), tc.hint)
			if !strings.Contains(r.Error, "esbuild skipped") {
				t.Fatalf("%s: got Error=%q, want esbuild skipped", tc.hint, r.Error)
			}
		}
		if r := Extract([]byte(deep)); !strings.Contains(r.Error, "esbuild skipped") {
			t.Fatalf("Extract: got Error=%q, want esbuild skipped", r.Error)
		}
		if x, ast := prepared([]byte("const f = ({a: b = 1} = {}) => " + deep)); x != nil || ast != nil {
			t.Fatalf("prepared: expected nil on 1M-nested input")
		}
		return
	}

	// Fast in-process check at 200k levels across .js, .ts, and .vue.
	med := strings.Repeat("[", 200_000) + strings.Repeat("]", 200_000)
	start := time.Now()
	for _, hint := range []string{"bundle.js", "mod.ts"} {
		r := ExtractSource([]byte(med), hint)
		if !strings.Contains(r.Error, "esbuild skipped") {
			t.Fatalf("%s: Error=%q, want esbuild skipped", hint, r.Error)
		}
	}
	rVue := ExtractSource([]byte("<script lang=\"ts\">"+med+"</script>"), "Comp.vue")
	if !strings.Contains(rVue.Error, "esbuild skipped") {
		t.Fatalf("Comp.vue: Error=%q, want esbuild skipped", rVue.Error)
	}
	limit := 2 * time.Second
	if isRaceBuild() {
		limit = 10 * time.Second
	}
	if took := time.Since(start); took > limit {
		t.Fatalf("200k nesting took %s, want <= %s", took, limit)
	}

	// Subprocess check at 1,000,000 levels (unrecoverable stack overflow in esbuild if unguarded).
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestRound41DeepNestingSkipsEsbuild$")
	cmd.Env = append(os.Environ(), "JSHARVEST_TEST_DEEP_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("1M nesting subprocess crashed: %v\n%s", err, out)
	}
}

func TestRound41NestingThresholdCorpus(t *testing.T) {
	list := os.Getenv("JSAPI_SNAPSHOT")
	if list == "" {
		t.Skip("JSAPI_SNAPSHOT not set")
	}
	b, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	var depths []int
	overCount := 0
	for _, f := range strings.Fields(string(b)) {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		d, over := maxNesting(src, maxEsbuildNesting)
		depths = append(depths, d)
		if over {
			overCount++
		}
	}
	sort.Ints(depths)
	if len(depths) > 0 {
		p99 := depths[len(depths)*99/100]
		t.Logf("corpus files=%d p99=%d max=%d over(%d)=%d", len(depths), p99, depths[len(depths)-1], maxEsbuildNesting, overCount)
	}
	if overCount > 0 {
		t.Fatalf("%d corpus script(s) exceeded maxEsbuildNesting=%d", overCount, maxEsbuildNesting)
	}
}

func TestRound41FallbackBudgetBySize(t *testing.T) {
	var calls atomic.Int32
	hook := func() { calls.Add(1) }
	testTransformHook.Store(&hook)
	defer testTransformHook.Store(nil)

	// 1. 5 MiB broken .js: fallbackBudget == 1, so api.Transform runs exactly once.
	bigBrokenJS := append(bytes.Repeat([]byte("// pad\n"), (5<<20)/7), []byte("function ??? invalid")...)
	calls.Store(0)
	_ = ExtractSource(bigBrokenJS, "bundle.js")
	if got := calls.Load(); got != 1 {
		t.Fatalf("5 MiB broken .js: api.Transform called %d times, want 1", got)
	}

	// 2. 500 KiB broken .js: at most 6 calls (1 JSLower + 4 TS = 5 <= 6).
	medBrokenJS := append(bytes.Repeat([]byte("// pad\n"), (500<<10)/7), []byte("function ??? invalid")...)
	calls.Store(0)
	_ = ExtractSource(medBrokenJS, "bundle.js")
	if got := calls.Load(); got < 1 || got > 6 {
		t.Fatalf("500 KiB broken .js: api.Transform called %d times, want 1..6", got)
	}

	// 3. Broken .ts does NOT fall through and run transformTS a second time (5 calls, not 9).
	calls.Store(0)
	_ = ExtractSource([]byte("const x: number = ??? invalid;"), "mod.ts")
	if got := calls.Load(); got != 5 {
		t.Fatalf("broken .ts: api.Transform called %d times, want 5 (4 TS + 1 JSLower, no duplicate TS)", got)
	}

	// 4. Dual-<script lang="ts"> .vue over 1 MiB with duplicate imports still extracts both blocks.
	pad := strings.Repeat("// pad line\n", (1200<<10)/12)
	vue := `<template><div/></template>` + "\n" + pad + `
<script lang="ts">
import { ep } from "./shared.js";
const a: string = "/api/v1/from_first";
fetch(a);
</script>
<script setup lang="ts">
import { ep } from "./shared.js";
const b: string = "/api/v1/from_second";
fetch(b);
</script>`
	rVue := ExtractSource([]byte(vue), "https://example.test/Two.vue")
	if rVue.Error != "" || len(rVue.Endpoints) != 2 {
		t.Fatalf("1.2 MiB dual-script .vue failed: err=%q endpoints=%+v", rVue.Error, rVue.Endpoints)
	}

	// 5. Hostile .vue with 20 broken <script lang="ts"> blocks is bounded by maxSFCSpans.
	var sfc strings.Builder
	sfc.WriteString("<template><div/></template>\n")
	for i := range 20 {
		fmt.Fprintf(&sfc, "<script lang=\"ts\">const s%d: number = ???;</script>\n", i)
	}
	calls.Store(0)
	_ = ExtractSource([]byte(sfc.String()), "Hostile.vue")
	maxAllowed := int32(6 + maxSFCSpans*4)
	if got := calls.Load(); got > maxAllowed {
		t.Fatalf("20-span hostile .vue: api.Transform called %d times, want <= %d", got, maxAllowed)
	}
}

func TestRound41NestedFunctionsBounded(t *testing.T) {
	// Previously N=1001 nested functions bypassed tdewolff (>1000) and ran esbuild
	// multiple times (>20s CPU). Now M7 + M13 bound it deterministically.
	const n = 1001
	src := []byte(strings.Repeat("function f(){", n) + "fetch('/api/deep');" + strings.Repeat("}", n))
	start := time.Now()
	r := ExtractSource(src, "nested.js")
	took := time.Since(start)
	limit := 2 * time.Second
	if isRaceBuild() {
		limit = 5 * time.Second
	}
	if took > limit {
		t.Fatalf("1001 nested functions took %s, want <= %s", took, limit)
	}
	if !strings.Contains(r.Error, "esbuild skipped") {
		t.Fatalf("expected esbuild skipped error, got %q", r.Error)
	}
}
