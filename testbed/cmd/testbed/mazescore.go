package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// mazescore scores a crawl of security-crawl-maze: an answer counts as
// requested when the server's log has a GET of it, and as listed when
// jsharvest's output names it (pages.jsonl, endpoints.jsonl, requests.jsonl,
// or a stored script's text). The gate is on either.
//
//	testbed mazescore -expected testbed/external/crawlmaze-expected.json -log server.log -out <output>/<host>/<role>
func mazescore(args []string) error {
	fset := flag.NewFlagSet("mazescore", flag.ExitOnError)
	expectedPath := fset.String("expected", "", "crawlmaze-expected.json")
	logPath := fset.String("log", "", "the server's log (docker logs)")
	out := fset.String("out", "", "jsharvest output directory")
	min := fset.Int("min", 0, "fewest answers found (either) that pass")
	minJS := fset.Int("min-js", 0, "fewest of the javascript group that pass")
	fset.Parse(args)
	b, err := os.ReadFile(*expectedPath)
	if err != nil {
		return err
	}
	var all []string
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	var answers []string
	for _, a := range all {
		if !strings.Contains(a, "/frameworks/") { // the 7 that do not build
			answers = append(answers, a)
		}
	}

	requested := map[string]bool{}
	logText, err := os.ReadFile(*logPath)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(ansiRe.ReplaceAllString(string(logText), ""), "\n") {
		if i := strings.Index(line, "\"GET "); i >= 0 {
			p := strings.Fields(line[i+5:])[0]
			p, _, _ = strings.Cut(p, "?")
			requested[p] = true
		}
	}

	// Every URL and path the output names.
	var named []string
	addURL := func(raw string) {
		if u, err := url.Parse(raw); err == nil && u.Path != "" {
			named = append(named, u.Path)
		}
	}
	for _, f := range []string{"pages.jsonl", "requests.jsonl"} {
		eachLine(filepath.Join(*out, f), func(b []byte) error {
			var e struct {
				URL      string `json:"url"`
				FinalURL string `json:"final_url"`
			}
			if json.Unmarshal(b, &e) == nil {
				addURL(e.URL)
				addURL(e.FinalURL)
			}
			return nil
		})
	}
	eachLine(filepath.Join(*out, "endpoints.jsonl"), func(b []byte) error {
		var e struct {
			Path string `json:"path"`
		}
		if json.Unmarshal(b, &e) == nil {
			named = append(named, e.Path)
		}
		return nil
	})
	var scripts []string
	files, _ := filepath.Glob(filepath.Join(*out, "js", "*.js"))
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			scripts = append(scripts, string(b))
		}
	}

	var req, listed, either, js, jsTotal int
	var missed []string
	for _, a := range answers {
		isJS := strings.HasPrefix(a, "/test/javascript/")
		if isJS {
			jsTotal++
		}
		r := requested[a]
		l := false
		for _, p := range named {
			if strings.HasSuffix(p, a) {
				l = true
				break
			}
		}
		if !l {
			for _, s := range scripts {
				if strings.Contains(s, a) {
					l = true
					break
				}
			}
		}
		if r {
			req++
		}
		if l {
			listed++
		}
		if r || l {
			either++
			if isJS {
				js++
			}
		} else {
			missed = append(missed, a)
		}
	}
	fmt.Printf("crawl-maze: requested %d, listed %d, either %d of %d; javascript %d/%d\n", req, listed, either, len(answers), js, jsTotal)
	w := bufio.NewWriter(os.Stdout)
	for _, m := range missed {
		fmt.Fprintln(w, "MISSED", m)
	}
	w.Flush()
	if either < *min || js < *minJS {
		return fmt.Errorf("mazescore failed: either %d < %d or javascript %d < %d", either, *min, js, *minJS)
	}
	return nil
}
