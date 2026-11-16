package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
)

// explorescore scores what crawl -explore found on its own, with no step
// order to go by:
//
//   - each case must be one action of explore (a flow that is neither a
//     page load nor background) holding all of the case's requests, and of
//     the case's kind when the truth names one;
//
//   - precision: of the requests put under explore's actions, how many are
//     some case's;
//
//   - forbidden requests never reach the server, nor does any write;
//     server_max bounds how often one does; urls are named in pages.jsonl
//     as found by explore.
//
// The truth is an explore.truth.json, or a flows.truth.json (each step with
// requests is a case, and a query matches by its names only: explore types
// its own values).
//
//	testbed explorescore -truth T -out <output>/<host>/<role> [-log bin/testbed.log -from N] [-min 0.95]
func explorescore(args []string) error {
	fset := flag.NewFlagSet("explorescore", flag.ExitOnError)
	truthPath := fset.String("truth", "", "explore.truth.json or flows.truth.json")
	out := fset.String("out", "", "jsharvest output directory (flows.jsonl, requests.jsonl, pages.jsonl)")
	logPath := fset.String("log", "", "the testbed server's log, to check what reached the server")
	from := fset.Int("from", 0, "lines of the log written before the crawl")
	min := fset.Float64("min", 0.95, "lowest precision that passes")
	fset.Parse(args)
	if *truthPath == "" || *out == "" {
		return fmt.Errorf("-truth and -out are required")
	}
	t, err := readExploreTruth(*truthPath)
	if err != nil {
		return err
	}

	type entry struct {
		Run    string `json:"run"`
		ID     int    `json:"id"`
		Method string `json:"method"`
		URL    string `json:"url"`
	}
	keys := map[int]string{}
	run := ""
	if err := eachLine(*out+"/requests.jsonl", func(b []byte) error {
		var e entry
		if err := json.Unmarshal(b, &e); err != nil {
			return err
		}
		if e.Run != run {
			run, keys = e.Run, map[int]string{}
		}
		if u, err := url.Parse(e.URL); err == nil {
			keys[e.ID] = e.Method + " " + u.RequestURI()
		}
		return nil
	}); err != nil {
		return err
	}
	type flow struct {
		Run      string `json:"run"`
		Kind     string `json:"kind"`
		Label    string `json:"label"`
		Requests []struct {
			ID int `json:"id"`
		} `json:"requests"`
	}
	var flows []flow
	if err := eachLine(*out+"/flows.jsonl", func(b []byte) error {
		var f flow
		if err := json.Unmarshal(b, &f); err != nil {
			return err
		}
		if f.Run == run && f.Kind != "load" && f.Kind != "background" {
			flows = append(flows, f)
		}
		return nil
	}); err != nil {
		return err
	}

	match := func(p, k string) bool { return requestMatch(p, k, t.loose) }
	failed := false
	for _, c := range t.Cases {
		var best string
		ok := false
		for _, f := range flows {
			var ks []string
			for _, r := range f.Requests {
				ks = append(ks, keys[r.ID])
			}
			all := true
			for _, p := range c.Expect {
				if !slices.ContainsFunc(ks, func(k string) bool { return match(p, k) }) {
					all = false
				}
			}
			if !all {
				continue
			}
			best = fmt.Sprintf("%s %q", f.Kind, f.Label)
			if c.Kind == "" || c.Kind == f.Kind {
				ok = true
				break
			}
		}
		switch {
		case ok:
			fmt.Printf("  pass  %-40s %s\n", c.Name, best)
		case best != "":
			fmt.Printf("  FAIL  %-40s under %s, want kind %s\n", c.Name, best, c.Kind)
			failed = true
		default:
			fmt.Printf("  FAIL  %-40s no action holds %v\n", c.Name, c.Expect)
			failed = true
		}
	}

	assigned, correct := 0, 0
	var wrong []string
	for _, f := range flows {
		for _, r := range f.Requests {
			k := keys[r.ID]
			assigned++
			if slices.ContainsFunc(t.Cases, func(c exploreCase) bool {
				return slices.ContainsFunc(c.Expect, func(p string) bool { return match(p, k) })
			}) {
				correct++
			} else {
				wrong = append(wrong, fmt.Sprintf("%s under %s %q", k, f.Kind, f.Label))
			}
		}
	}
	precision := ratio(correct, assigned)
	fmt.Printf("explore actions: %d; requests under them: %d, precision %.3f\n", len(flows), assigned, precision)
	for _, w := range wrong {
		fmt.Println("  wrong:", w)
	}
	if precision < *min {
		failed = true
	}

	if len(t.URLs) > 0 {
		named := map[string]bool{}
		if err := eachLine(*out+"/pages.jsonl", func(b []byte) error {
			var p struct {
				URL string `json:"url"`
				How string `json:"how"`
			}
			if json.Unmarshal(b, &p) == nil && p.How == "explore" {
				if u, err := url.Parse(p.URL); err == nil {
					named[u.Path] = true
				}
			}
			return nil
		}); err != nil {
			return err
		}
		for _, u := range t.URLs {
			if !named[u] {
				fmt.Printf("  FAIL  url %s not found by explore\n", u)
				failed = true
			}
		}
	}

	if *logPath != "" {
		f, err := os.Open(*logPath)
		if err != nil {
			return err
		}
		defer f.Close()
		counts := map[string]int{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for n := 0; sc.Scan(); n++ {
			if n < *from {
				continue
			}
			// "2026/11/03 22:27:55 200 GET /path?query"
			fs := strings.Fields(sc.Text())
			if len(fs) < 5 {
				continue
			}
			key := fs[3] + " " + fs[4]
			switch fs[3] {
			case "GET", "HEAD", "OPTIONS":
			default:
				fmt.Println("  FAIL  a write reached the server:", key)
				failed = true
			}
			for _, p := range t.Forbidden {
				if requestMatch(p, key, false) {
					fmt.Println("  FAIL  forbidden request reached the server:", key)
					failed = true
				}
			}
			for p := range t.ServerMax {
				if requestMatch(p, key, false) {
					counts[p]++
				}
			}
		}
		for p, max := range t.ServerMax {
			if counts[p] > max {
				fmt.Printf("  FAIL  %s reached the server %d times, at most %d\n", p, counts[p], max)
				failed = true
			}
		}
	}
	if failed {
		return fmt.Errorf("explore score: failed")
	}
	fmt.Println("explore score: ok")
	return nil
}

var numberRe = regexp.MustCompile(`/\d+([/?]|$)`)

type exploreCase struct {
	Name   string   `json:"name"`
	Expect []string `json:"expect"`
	Kind   string   `json:"kind"`
}

type exploreTruth struct {
	Cases     []exploreCase  `json:"cases"`
	Forbidden []string       `json:"forbidden"`
	ServerMax map[string]int `json:"server_max"`
	URLs      []string       `json:"urls"`
	loose     bool
}

// readExploreTruth reads an explore.truth.json, or makes one of a
// flows.truth.json.
func readExploreTruth(p string) (*exploreTruth, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var t exploreTruth
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	if len(t.Cases) > 0 {
		return &t, nil
	}
	ft, err := readTruthFile(p)
	if err != nil {
		return nil, err
	}
	// Explore uses one row of a list: steps that differ only by the ids in
	// their paths (open item 42, open item 108) are one feature.
	seen := map[string]bool{}
	for _, s := range ft.Steps {
		var expect []string
		for _, e := range s.Expect {
			expect = append(expect, numberRe.ReplaceAllString(e, "/{id}$1"))
		}
		key := strings.Join(expect, " ")
		if len(expect) == 0 || seen[key] {
			continue
		}
		seen[key] = true
		t.Cases = append(t.Cases, exploreCase{Name: s.Do + " " + s.Selector, Expect: expect})
	}
	t.loose = true
	return &t, nil
}

// requestMatch matches "METHOD /path?query" against a pattern of that
// form: a {name} segment is any one segment; a query value * is any
// value; a pattern with no query matches any. Loose, a query matches by
// its names only.
func requestMatch(pattern, key string, loose bool) bool {
	pm, prest, _ := strings.Cut(pattern, " ")
	km, krest, _ := strings.Cut(key, " ")
	if pm != km {
		return false
	}
	pp, pq, hasQ := strings.Cut(prest, "?")
	kp, kq, _ := strings.Cut(krest, "?")
	if !expectMatch(pp, kp) {
		return false
	}
	if !hasQ {
		return true
	}
	want, err1 := url.ParseQuery(pq)
	got, err2 := url.ParseQuery(kq)
	if err1 != nil || err2 != nil {
		return false
	}
	for name, vs := range want {
		g, ok := got[name]
		if !ok {
			return false
		}
		if !loose && vs[0] != "*" && !slices.Contains(g, vs[0]) {
			return false
		}
	}
	return true
}
