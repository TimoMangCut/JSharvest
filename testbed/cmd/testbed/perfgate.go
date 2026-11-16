package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// perfgate enforces Architectural Invariant #9 on a deterministic 2,000-script
// corpus (1,600 JS bundles/modules, 300 TypeScript sourcemap files with
// decorators/generics/enums/Via chains, and 100 Vue SFC files):
//   - wall-clock analysis + module linking <= 15s
//   - peak process RSS (rusage.Maxrss / VmHWM) <= 500 MB
func perfgate(args []string) error {
	fs := flag.NewFlagSet("perfgate", flag.ExitOnError)
	binPath := fs.String("bin", "./bin/jsharvest", "path to jsharvest binary")
	workDir := fs.String("work", "", "temporary working directory")
	totalScripts := fs.Int("n", 2000, "number of scripts to generate and analyse")
	maxSec := fs.Float64("max-sec", 15.0, "hard wall-clock ceiling in seconds")
	maxRSSMB := fs.Float64("max-rss-mb", 500.0, "hard peak RSS ceiling in MB")
	fs.Parse(args)

	var cleanup func()
	root := *workDir
	if root == "" {
		tmp, err := os.MkdirTemp("", "jsh-perfgate-*")
		if err != nil {
			return err
		}
		root = tmp
		cleanup = func() { os.RemoveAll(tmp) }
	} else {
		os.RemoveAll(root)
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
	}
	if cleanup != nil {
		defer cleanup()
	}

	roleDir := filepath.Join(root, "perf.jsh.test", "anon")
	jsDir := filepath.Join(roleDir, "js")
	if err := os.MkdirAll(jsDir, 0o700); err != nil {
		return err
	}

	type idxEntry struct {
		SHA256 string   `json:"sha256"`
		URLs   []string `json:"urls"`
		Tags   []string `json:"tags,omitempty"`
	}

	var totalBytes int64
	var indexBuf bytes.Buffer
	writeScript := func(code string, url string, tags []string) error {
		sum := sha256.Sum256([]byte(code))
		sha := hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(jsDir, sha+".js"), []byte(code), 0o600); err != nil {
			return err
		}
		totalBytes += int64(len(code))
		b, err := json.Marshal(idxEntry{SHA256: sha, URLs: []string{url}, Tags: tags})
		if err != nil {
			return err
		}
		indexBuf.Write(b)
		indexBuf.WriteByte('\n')
		return nil
	}

	nTotal := max(*totalScripts, 20)
	nVue := nTotal / 20        // 5% (100 of 2000) .vue SFCs
	nTS := (nTotal * 3) / 20   // 15% (300 of 2000) .ts SourceMap modules
	nJS := nTotal - nTS - nVue // 80% (1600 of 2000) .js bundles/modules

	// Shared TS transport + barrel modules for the TS corpus (3-module Via chain).
	if nTS >= 2 {
		if err := writeScript(`
export interface TransportConfig {
	method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
	baseURL: string;
	endpoint: string;
	data?: Record<string, unknown>;
	params?: Record<string, unknown>;
}
export async function rawTransport<T>(cfg: TransportConfig): Promise<T> {
	const { method, baseURL, endpoint, data, params } = cfg;
	const o: any = { method, baseURL, url: endpoint };
	if (method === "GET") o.params = params;
	else o.data = data;
	return axios.request(o) as Promise<T>;
}
`, "https://perf.jsh.test/assets/app.js.map#packages/@perf/http/src/http.ts", []string{"sourcemap", "source:packages/@perf/http/src/http.ts"}); err != nil {
			return err
		}
		if err := writeScript(`
import { rawTransport } from "./http";
export async function get<T>(baseUrl: string, endpoint: string, params?: Record<string, unknown>): Promise<T> {
	return rawTransport<T>({ method: "GET", baseURL: baseUrl, endpoint, params });
}
export async function post<T>(baseUrl: string, endpoint: string, data?: Record<string, unknown>): Promise<T> {
	return rawTransport<T>({ method: "POST", baseURL: baseUrl, endpoint, data });
}
`, "https://perf.jsh.test/assets/app.js.map#packages/@perf/http/src/index.ts", []string{"sourcemap", "source:packages/@perf/http/src/index.ts"}); err != nil {
			return err
		}
		nTS -= 2
	}

	// Realistic ~48 MB mixed corpus (matching enterprise SPAs like n8n 2.12):
	//   - 8 multi-MB minified-style bundles (~1.5 MB each)
	//   - 24 medium bundles (~250 KB each)
	//   - remaining JS route chunks (~16 KB each)
	//   - 300 TypeScript sourcemap modules (~12 KB each)
	//   - 100 Vue SFC modules (~12 KB each)
	buildDenseJS := func(blocks int) string {
		var sb strings.Builder
		for k := 0; k < blocks; k++ {
			fmt.Fprintf(&sb, "const _m%d=(a,b)=>{const s={id:a,label:'node_%d',items:[1,2,3,%d],meta:{enabled:true,retries:%d}};return b?s.items.map(x=>x+%d):s;};\n", k, k, k+3, k%5, k+1)
		}
		return sb.String()
	}
	heavyFiller := buildDenseJS(10500) // ~1.45 MB AST-dense bundle body
	medFiller := buildDenseJS(1800)    // ~250 KB bundle body
	chunkFiller := buildDenseJS(110)   // ~15 KB chunk body
	tsFiller := buildDenseJS(75)       // ~10.5 KB TS module body
	vueStyleFiller := strings.Repeat(".panel-grid-row { display: flex; align-items: center; padding: 4px 8px; }\n", 110)

	nHeavy := min(8, nJS/4)
	nMed := min(24, (nJS-nHeavy)/4)
	for i := 0; i < nJS; i++ {
		body := chunkFiller
		name := fmt.Sprintf("chunk-%04d.js", i)
		switch {
		case i < nHeavy:
			body = heavyFiller
			name = fmt.Sprintf("vendor-bundle-%02d.js", i)
		case i < nHeavy+nMed:
			body = medFiller
			name = fmt.Sprintf("store-bundle-%02d.js", i)
		}
		code := fmt.Sprintf(`// %s (%d)
const apiClient_%d = axios.create({ baseURL: "/api/v1" });
function hopA_%d(m, p, d) { return apiClient_%d.request({ method: m, url: p, data: d }); }
function hopB_%d(p, d) { return hopA_%d("POST", p, d); }
export async function runChunk_%d(id, filter) {
	await fetch("/api/v1/js-item-%d/" + encodeURIComponent(id) + "?filter=" + encodeURIComponent(filter));
	return hopB_%d("/js-submit-%d", { itemId: id, active: true });
}
%s`, name, i, i, i, i, i, i, i, i, i, i, body)
		if err := writeScript(code, "https://perf.jsh.test/assets/"+name, nil); err != nil {
			return err
		}
	}

	for i := 0; i < nTS; i++ {
		vpath := fmt.Sprintf("src/api/feature_%04d.ts", i)
		code := fmt.Sprintf(`import { get, post } from "@perf/http";
function Injectable(): ClassDecorator { return (t) => t; }
enum FeatureRoute_%d { Root = "/ts-feature-%d" }
export interface FeaturePayload_%d { name: string; count: number; tags?: string[] }
@Injectable()
export class FeatureService_%d {
	async list(ctx: { baseUrl: string }, page: number) {
		return await get<FeaturePayload_%d[]>(ctx.baseUrl, FeatureRoute_%d.Root, { page, limit: 20 });
	}
	async create(ctx: { baseUrl: string }, body: FeaturePayload_%d) {
		return await post<FeaturePayload_%d>(ctx.baseUrl, FeatureRoute_%d.Root, { name: body.name, count: body.count });
	}
}
%s`, i, i, i, i, i, i, i, i, i, tsFiller)
		if err := writeScript(code, "https://perf.jsh.test/assets/app.js.map#"+vpath, []string{"sourcemap", "source:" + vpath}); err != nil {
			return err
		}
	}

	for i := 0; i < nVue; i++ {
		vpath := fmt.Sprintf("src/views/Panel_%04d.vue", i)
		code := fmt.Sprintf(`<template>
  <section class="panel-%d">
    <div class="panel-grid-row"><span>Panel %d</span></div>
  </section>
</template>
<script lang="ts">
interface PanelProps_%d { slug: string }
export function loadPanel_%d(p: PanelProps_%d) {
  return fetch("/api/v1/vue-panel-%d/" + encodeURIComponent(p.slug));
}
</script>
<style scoped>
.panel-%d { display: block; }
%s</style>
`, i, i, i, i, i, i, i, vueStyleFiller)
		if err := writeScript(code, "https://perf.jsh.test/assets/app.js.map#"+vpath, []string{"sourcemap", "source:" + vpath}); err != nil {
			return err
		}
	}

	if err := os.WriteFile(filepath.Join(roleDir, "index.jsonl"), indexBuf.Bytes(), 0o600); err != nil {
		return err
	}

	start := time.Now()
	cmd := exec.Command(*binPath, "endpoints", "-target", "perf.jsh.test", "-o", root)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	err := cmd.Run()
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("perfgate: jsharvest endpoints failed (%v): %s", err, strings.TrimSpace(stderr.String()))
	}

	var peakRSSMB float64
	if cmd.ProcessState != nil {
		if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			// On Linux ru.Maxrss is in KiB; on Darwin/macOS it is in bytes.
			peakRSSMB = float64(ru.Maxrss) / 1024.0
			if runtime.GOOS == "darwin" {
				peakRSSMB /= 1024.0
			}
		}
	}

	epFile := filepath.Join(roleDir, "endpoints.jsonl")
	f, err := os.Open(epFile)
	if err != nil {
		return fmt.Errorf("perfgate: missing endpoints.jsonl: %w", err)
	}
	defer f.Close()
	epCount := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			epCount++
		}
	}

	corpusMB := float64(totalBytes) / (1024.0 * 1024.0)
	fmt.Printf("perfgate: %d scripts (%.1f MB: %d .js incl. %d multi-MB bundles, %d .ts, %d .vue) -> %d endpoints in %.2fs, peak RSS %.1f MB (limits: <= %.1fs, <= %.1f MB)\n",
		nTotal, corpusMB, nJS, nHeavy, *totalScripts-nJS-nVue, nVue, epCount, elapsed.Seconds(), peakRSSMB, *maxSec, *maxRSSMB)

	var errs []string
	if nTotal >= 2000 && corpusMB < 40.0 {
		errs = append(errs, fmt.Sprintf("corpus %.1f MB smaller than 40.0 MB realistic floor", corpusMB))
	}
	if epCount < nTotal {
		errs = append(errs, fmt.Sprintf("extracted only %d endpoints for %d scripts", epCount, nTotal))
	}
	if elapsed.Seconds() > *maxSec {
		errs = append(errs, fmt.Sprintf("wall-clock %.2fs exceeds %.1fs limit", elapsed.Seconds(), *maxSec))
	}
	if peakRSSMB <= 0 {
		errs = append(errs, "unable to read child process Maxrss")
	} else if peakRSSMB > *maxRSSMB {
		errs = append(errs, fmt.Sprintf("peak RSS %.1f MB exceeds %.1f MB limit", peakRSSMB, *maxRSSMB))
	}
	if len(errs) > 0 {
		return errors.New("perfgate FAILED: " + strings.Join(errs, "; "))
	}
	return nil
}
