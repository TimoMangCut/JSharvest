package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// archivecheck checks jsharvest archive's output against archive.truth.json:
//
//   - historical.jsonl and the old scripts' catalog (endpoints.jsonl), as
//     sets of whole lines (class, method, path, bases, query, body, the
//     scripts that call it): precision and recall, both must be 1;
//
//   - the store's entries, the summary (and the in_current_code count), the
//     files' modes, no secret of the archived URLs in any file;
//
//   - live-checks.jsonl: each old script's path asked once, as GET;
//
//   - given the server's log of the run: the same live checks, never the URL
//     with a token, the archive's troubles met (the offline page as a 200, a
//     502, a 503, a 429), OTX asked under the section its host is filed in.
//
//     testbed archivecheck -dir <out>/<host>/archive -truth archive.truth.json [-log server.log] [-no-live]
func archivecheck(args []string) error {
	fset := flag.NewFlagSet("archivecheck", flag.ExitOnError)
	dir := fset.String("dir", "", "the archive directory")
	truthPath := fset.String("truth", "", "archive.truth.json")
	logPath := fset.String("log", "", "the server's log of the run")
	noLive := fset.Bool("no-live", false, "the run had -live=false")
	fset.Parse(args)
	var truth struct {
		// LiveOnly: found only through the live check (a script an old page
		// names, alive today, never archived): not there with -live=false.
		Historical []archLine `json:"historical"`
		Catalog    []archLine `json:"catalog"`
		Scripts    []struct {
			LiveOnly bool   `json:"live_only"`
			Path     string `json:"path"`
			Source   string `json:"source"`
			Alive    *bool  `json:"alive"`
			LiveSame bool   `json:"live_same"`
			Captures int    `json:"captures"`
			NotTag   string `json:"not_tag"`
		} `json:"scripts"`
		Summary    map[string]int `json:"summary"`
		Skipped    map[string]int `json:"skipped"`
		InCode     int            `json:"in_current_code"`
		LiveChecks []string       `json:"live_checks"`
		OTXSection string         `json:"otx_section"`
		Secret     string         `json:"secret"`
	}
	if err := readJSON(*truthPath, &truth); err != nil {
		return err
	}
	var errs []string
	fail := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	// The store: its entries by the paths of their URLs.
	entries := map[string]map[string]any{}
	b, _ := os.ReadFile(filepath.Join(*dir, "index.jsonl"))
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e map[string]any
		if json.Unmarshal(l, &e) != nil {
			continue
		}
		for _, u := range e["urls"].([]any) {
			if p, err := url.Parse(u.(string)); err == nil {
				entries[p.Path] = e
			}
		}
	}
	// A script is its content: the same bytes archived at two URLs are one
	// script, whichever URL a line names.
	content := func(path string) string {
		if e := entries[path]; e != nil {
			if sha, _ := e["sha256"].(string); sha != "" {
				return sha
			}
		}
		return "no script " + path
	}

	// historical.jsonl and the old scripts' catalog, line for line.
	nHist := measure("historical.jsonl", filepath.Join(*dir, "historical.jsonl"), truth.Historical, *noLive, content, fail)
	measure("endpoints.jsonl", filepath.Join(*dir, "endpoints.jsonl"), truth.Catalog, *noLive, nil, fail)

	for _, s := range truth.Scripts {
		if s.LiveOnly && *noLive {
			continue
		}
		e := entries[s.Path]
		if e == nil {
			fail("no script %s in the store", s.Path)
			continue
		}
		alive, _ := e["alive"].(bool)
		same, _ := e["live_same"].(bool)
		tags := fmt.Sprint(e["tags"])
		captures := 0
		if a, ok := e["archive"].(map[string]any); ok {
			captures = int(a["captures"].(float64))
		}
		wantSource := s.Source
		if *noLive && wantSource == "both" {
			wantSource = "wayback" // the live copy is what makes both
		}
		switch {
		case e["source"] != wantSource:
			fail("%s: source %v, want %s", s.Path, e["source"], wantSource)
		case !*noLive && s.Alive != nil && alive != *s.Alive:
			fail("%s: alive %v, want %v", s.Path, alive, *s.Alive)
		case *noLive && e["alive"] != nil:
			fail("%s: alive %v without a live check", s.Path, e["alive"])
		case !*noLive && same != s.LiveSame:
			fail("%s: live_same %v", s.Path, same)
		case s.Captures > 0 && captures != s.Captures:
			fail("%s: %d captures, want %d", s.Path, captures, s.Captures)
		case s.NotTag != "" && strings.Contains(tags, s.NotTag):
			fail("%s: tagged %s", s.Path, s.NotTag)
		}
	}

	// The summary.
	var st struct {
		Summary map[string]any `json:"summary"`
	}
	if err := readJSON(filepath.Join(*dir, "archive.json"), &st); err != nil {
		return err
	}
	for k, v := range truth.Summary {
		if *noLive && (k == "fetched" || k == "resolved" || k == "not_archived") {
			continue
		}
		var n int
		switch x := st.Summary[k].(type) {
		case float64:
			n = int(x)
		case []any:
			n = len(x)
		}
		if n != v {
			fail("summary %s: %d, want %d", k, n, v)
		}
	}
	skipped, _ := st.Summary["skipped"].(map[string]any)
	for k, v := range truth.Skipped {
		if n, _ := skipped[k].(float64); int(n) != v {
			fail("skipped %q: %v, want %d", k, skipped[k], v)
		}
	}
	hist, _ := st.Summary["historical"].(map[string]any)
	if n, _ := hist["in_current_code"].(float64); int(n) != truth.InCode {
		fail("historical in_current_code: %v, want %d (today's code writes those paths out)", hist["in_current_code"], truth.InCode)
	}

	// Files: their modes, and no secret.
	filepath.WalkDir(*dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, _ := d.Info()
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			fail("%s: mode %o", p, info.Mode().Perm())
		}
		if !d.IsDir() && truth.Secret != "" {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(truth.Secret)) {
				fail("%s holds the archived URL's secret", p)
			}
		}
		return nil
	})

	wantLive := truth.LiveChecks
	if *noLive {
		wantLive = nil
	}
	// live-checks.jsonl: what jsharvest says it sent, in this run (a run
	// starts the file anew): checked with the server's log of one run.
	sent := map[string]int{}
	b, _ = os.ReadFile(filepath.Join(*dir, "live-checks.jsonl"))
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var s struct {
			Purpose string `json:"purpose"`
			Request string `json:"request"`
		}
		if json.Unmarshal(l, &s) != nil {
			continue
		}
		method, rest, _ := strings.Cut(s.Request, " ")
		target, _, _ := strings.Cut(rest, " ")
		if s.Purpose != "live-check" || method != "GET" {
			fail("live-checks.jsonl: %s %s %s", s.Purpose, method, target)
		}
		sent[target]++
	}
	if *logPath != "" {
		checkLive("live-checks.jsonl", sent, wantLive, fail)
	}

	// The server's log of the run.
	if *logPath != "" {
		b, _ := os.ReadFile(*logPath)
		lines := strings.Split(string(b), "\n")
		lineRe := regexp.MustCompile(`^\S+ \S+ (\d+) (\S+) (\S+)`)
		live := map[string]int{}
		var trouble []string
		firstCDX, otx := 0, map[string]bool{}
		for _, l := range lines {
			m := lineRe.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			status, method, uri := m[1], m[2], m[3]
			if strings.Contains(uri, truth.Secret) && !strings.HasPrefix(uri, "/fake/") {
				fail("the URL with a token was sent to the target: %s", uri)
			}
			if strings.HasPrefix(uri, "/fake/") {
				if status == "503" || status == "429" || status == "502" || status == "504" {
					trouble = append(trouble, status)
				}
				if strings.HasPrefix(uri, "/fake/wayback/cdx/") && !strings.Contains(uri, "resumeKey=") {
					firstCDX++
				}
				if rest, ok := strings.CutPrefix(uri, "/fake/otx/api/v1/indicators/"); ok {
					section, _, _ := strings.Cut(rest, "/")
					otx[section] = true
				}
				continue
			}
			if method != "GET" {
				fail("a live check sent %s %s", method, uri)
			}
			live[uri]++
		}
		checkLive("the server's log", live, wantLive, fail)
		for _, s := range []string{"503", "429", "502", "504"} {
			if !slices.Contains(trouble, s) {
				fail("the fake archive's %s was not met (%v)", s, trouble)
			}
		}
		if firstCDX < 2 {
			fail("the CDX server's offline page (a 200) was not asked again: %d first queries", firstCDX)
		}
		if truth.OTXSection != "" && (len(otx) != 1 || !otx[truth.OTXSection]) {
			fail("OTX asked under %v, want %s only", otx, truth.OTXSection)
		}
	}
	for _, e := range errs {
		fmt.Println("FAIL", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("archivecheck: %d failure(s)", len(errs))
	}
	fmt.Printf("archivecheck: ok (%d historical, %d scripts)\n", nHist, len(entries))
	return nil
}

// archLine is a line of historical.jsonl or of the catalog, as the truth
// gives it; key is what it is compared by.
type archLine struct {
	Class    string   `json:"class"`
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	Bases    []string `json:"bases"`
	Query    []string `json:"query"`
	Body     []string `json:"body"`
	Scripts  []string `json:"scripts"` // the paths of the scripts that call it (in the output: their sha256)
	LiveOnly bool     `json:"live_only"`
}

func (l archLine) key(scripts []string) string {
	k := fmt.Sprintf("%s %s %s bases=%s query=%s body=%s", l.Class, l.Method, l.Path, sortedJoin(l.Bases), sortedJoin(l.Query), sortedJoin(l.Body))
	if scripts != nil {
		k += " scripts=" + sortedJoin(scripts)
	}
	return strings.TrimSpace(k)
}

func sortedJoin(xs []string) string {
	xs = slices.Clone(xs)
	sort.Strings(xs)
	return strings.Join(xs, ",")
}

// measure compares a JSONL file's lines with the truth's, by their whole
// key: precision (no line the truth lacks) and recall (every line the truth
// has). With content, a line's scripts count too, by their content (the
// truth names them by path). The catalog's third-party lines are no
// history's.
func measure(name, path string, want []archLine, noLive bool, content func(path string) string, fail func(string, ...any)) int {
	var got []string
	b, _ := os.ReadFile(path)
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var x struct {
			Class, Method, Path string
			Bases, Query, Body  []string
			ThirdParty          bool `json:"third_party"`
			Scripts             []struct {
				SHA256 string `json:"sha256"`
			}
		}
		if json.Unmarshal(l, &x) != nil || x.ThirdParty {
			continue
		}
		a := archLine{Class: x.Class, Method: x.Method, Path: x.Path, Bases: x.Bases, Query: x.Query, Body: x.Body}
		var scripts []string
		if content != nil {
			scripts = []string{}
			for _, s := range x.Scripts {
				scripts = append(scripts, s.SHA256)
			}
		}
		got = append(got, a.key(scripts))
	}
	var w []string
	for _, l := range want {
		if l.LiveOnly && noLive {
			continue
		}
		var scripts []string
		if content != nil {
			scripts = []string{}
			for _, p := range l.Scripts {
				scripts = append(scripts, content(p))
			}
		}
		w = append(w, l.key(scripts))
	}
	sort.Strings(got)
	sort.Strings(w)
	tp := 0
	var extra, missing []string
	for _, g := range got {
		if slices.Contains(w, g) {
			tp++
		} else {
			extra = append(extra, g)
		}
	}
	for _, x := range w {
		if !slices.Contains(got, x) {
			missing = append(missing, x)
		}
	}
	ratio := func(n, d int) float64 {
		if d == 0 {
			return 1
		}
		return float64(n) / float64(d)
	}
	fmt.Printf("%s: precision %.3f (%d/%d), recall %.3f (%d/%d)\n", name, ratio(tp, len(got)), tp, len(got), ratio(tp, len(w)), tp, len(w))
	for _, x := range extra {
		fail("%s: a line the truth lacks: %s", name, x)
	}
	for _, x := range missing {
		fail("%s: missing: %s", name, x)
	}
	return len(got)
}

func checkLive(where string, got map[string]int, want []string, fail func(string, ...any)) {
	var paths []string
	for p, n := range got {
		paths = append(paths, p)
		if n > 1 {
			fail("%s: live check of %s sent %d times", where, p, n)
		}
	}
	sort.Strings(paths)
	if !slices.Equal(paths, want) && !(len(paths) == 0 && len(want) == 0) {
		fail("%s: live checks %v, want %v", where, paths, want)
	}
}
