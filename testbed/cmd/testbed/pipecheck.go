package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// pipecheck is gate 17's checker (testbed/pipeline-check.sh, round 22B)
// on pipe-app's output: -app the crawl of app.jsh.test, -spa0 and -spa1
// the crawls of spa.jsh.test without and with -spa-boot.
//
//	(a) PIP-03: the API host's /api-json (NestJS) and the app's OpenID
//	    configuration read: their endpoints in the catalog, the API's under
//	    its own origin, merged with the code's call of the same URL;
//	(b) PIP-02: the JSON page the crawl visited is observed (both,
//	    confirmed);
//	(c) PIP-01: a line the archive's catalog knows more of is filled
//	    (enriched_from archive) — the archive's files are the shell's;
//	(d) passive server hints: intel.json names Express and NestJS, and CORS * with
//	    credentials;
//	(e) PIP-04: no browser without -spa-boot; with it, the boot call is
//	    observed;
//	(f) request stats: run.json tells the page's requests from the tool's own.
func pipecheck(args []string) error {
	fs := flag.NewFlagSet("pipecheck", flag.ExitOnError)
	app := fs.String("app", "", "output of app.jsh.test (…/app.jsh.test_8770/anon)")
	spa0 := fs.String("spa0", "", "output of spa.jsh.test, no -spa-boot")
	spa1 := fs.String("spa1", "", "output of spa.jsh.test, -spa-boot")
	fs.Parse(args)
	failed := 0
	check := func(name string, ok bool, detail string) {
		if ok {
			fmt.Printf("  pass  %s\n", name)
			return
		}
		failed++
		fmt.Printf("  FAIL  %s: %s\n", name, detail)
	}
	type ep struct {
		Method     string   `json:"method"`
		Host       string   `json:"host"`
		Path       string   `json:"path"`
		Status     string   `json:"status"`
		Kind       string   `json:"kind"`
		Bases      []string `json:"bases"`
		Query      []string `json:"query"`
		Confidence string   `json:"confidence"`
		Enriched   []string `json:"enriched_from"`
		Static     []struct {
			Kind string `json:"kind"`
		} `json:"static"`
	}
	read := func(dir string) []ep {
		f, err := os.Open(filepath.Join(dir, "endpoints.jsonl"))
		if err != nil {
			return nil
		}
		defer f.Close()
		var out []ep
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var e ep
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				out = append(out, e)
			}
		}
		if sc.Err() != nil {
			return nil
		}
		return out
	}
	find := func(eps []ep, method, host, path string) *ep {
		for i, e := range eps {
			if e.Method == method && e.Host == host && e.Path == path {
				return &eps[i]
			}
		}
		return nil
	}
	runOf := func(dir string) map[string]any {
		var r map[string]any
		b, _ := os.ReadFile(filepath.Join(dir, "run.json"))
		json.Unmarshal(b, &r)
		return r
	}

	eps := read(*app)
	// (a)
	for _, p := range []string{"/v1/items", "/v1/items/{}"} {
		e := find(eps, "GET", "", p)
		check("(a) /api-json: GET "+p, e != nil && e.Kind == "openapi" && slices.Equal(e.Bases, []string{"http://api.jsh.test:8770"}),
			fmt.Sprintf("%+v", e))
	}
	if e := find(eps, "GET", "", "/v1/items"); e != nil {
		code := slices.ContainsFunc(e.Static, func(s struct {
			Kind string `json:"kind"`
		}) bool {
			return s.Kind == "fetch"
		})
		check("(a) the code's call of the same URL merged into the spec's", code && find(eps, "GET", "api.jsh.test:8770", "/v1/items") == nil,
			fmt.Sprintf("%+v", e))
	}
	tok := find(eps, "POST", "app.jsh.test:8770", "/oauth/token")
	check("(a) OpenID configuration: POST /oauth/token", tok != nil && tok.Kind == "openapi", fmt.Sprintf("%+v", tok))
	check("(a) OpenID configuration: GET /oauth/userinfo", find(eps, "GET", "app.jsh.test:8770", "/oauth/userinfo") != nil, "missing")
	// (b)
	boot := find(eps, "GET", "", "/api/boot-status")
	check("(b) JSON page observed", boot != nil && boot.Status == "both" && boot.Confidence == "confirmed", fmt.Sprintf("%+v", boot))
	// (c)
	check("(c) filled from the archive's catalog", boot != nil && slices.Contains(boot.Query, "verbose") && slices.Contains(boot.Enriched, "archive"),
		fmt.Sprintf("%+v", boot))
	// (d)
	var intel struct {
		Hints []struct {
			Name string `json:"name"`
		} `json:"server_hints"`
		Notes []struct {
			Kind    string   `json:"kind"`
			Origins []string `json:"origins"`
		} `json:"security_notes"`
	}
	b, err := os.ReadFile(filepath.Join(*app, "intel.json"))
	if err == nil {
		err = json.Unmarshal(b, &intel)
	}
	var names []string
	for _, h := range intel.Hints {
		names = append(names, h.Name)
	}
	check("(d) server hints Express, NestJS", err == nil && slices.Contains(names, "Express") && slices.Contains(names, "NestJS"),
		fmt.Sprintf("%v %v", names, err))
	cors := slices.ContainsFunc(intel.Notes, func(n struct {
		Kind    string   `json:"kind"`
		Origins []string `json:"origins"`
	}) bool {
		return n.Kind == "cors_wildcard_with_credentials" && slices.Equal(n.Origins, []string{"http://api.jsh.test:8770"})
	})
	check("(d) cors_wildcard_with_credentials on the API host", cors, fmt.Sprintf("%+v", intel.Notes))
	// (f)
	r := runOf(*app)
	req, _ := r["requests"].(float64)
	page, _ := r["page_requests"].(float64)
	internal, _ := r["internal_requests"].(float64)
	check("(f) page_requests + internal_requests = requests", req > 0 && page+internal == req && internal > 0 && page >= 2,
		fmt.Sprintf("requests %v page %v internal %v", req, page, internal))
	// (e)
	lines := func(dir string) int {
		b, _ := os.ReadFile(filepath.Join(dir, "runs.jsonl"))
		return strings.Count(string(b), "\n")
	}
	data := "/api/spa-boot-data"
	s0, s1 := find(read(*spa0), "GET", "", data), find(read(*spa1), "GET", "", data)
	_, boot0 := runOf(*spa0)["spa_boot"]
	check("(e) no -spa-boot: one run, no browser", lines(*spa0) == 1 && !boot0 && s0 != nil && s0.Status == "static",
		fmt.Sprintf("runs %d, spa_boot %v, %+v", lines(*spa0), boot0, s0))
	sb, _ := runOf(*spa1)["spa_boot"].([]any)
	check("(e) -spa-boot: the boot call observed", len(sb) == 1 && lines(*spa1) == 2 && s1 != nil && s1.Status == "both",
		fmt.Sprintf("spa_boot %v, runs %d, %+v", sb, lines(*spa1), s1))
	if failed > 0 {
		return errors.New("pipecheck: failed")
	}
	fmt.Println("pipecheck: all pass")
	return nil
}
