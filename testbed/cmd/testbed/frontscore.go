package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// frontscore checks a frontier crawl of frontier-app against its truth:
// every page to visit was visited, every URL to name is in pages.jsonl
// with its reason, and the server was never asked for a forbidden path.
//
//	testbed frontscore -truth testbed/apps/frontier-app/frontier.truth.json -out <output>/<host>/<role> -log server.log
func frontscore(args []string) error {
	fset := flag.NewFlagSet("frontscore", flag.ExitOnError)
	truthPath := fset.String("truth", "", "frontier.truth.json")
	out := fset.String("out", "", "jsharvest output directory, with pages.jsonl")
	logPath := fset.String("log", "", "the server's log for the crawl")
	fset.Parse(args)
	b, err := os.ReadFile(*truthPath)
	if err != nil {
		return err
	}
	var truth struct {
		Visit     []string          `json:"visit"`
		Listed    map[string]string `json:"listed"`
		Forbidden []string          `json:"forbidden"`
	}
	if err := json.Unmarshal(b, &truth); err != nil {
		return err
	}
	key := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		k := u.Path
		if strings.HasPrefix(u.Fragment, "/") {
			k += "#" + u.Fragment
		}
		return k
	}
	visited := map[string]bool{}
	reasons := map[string][]string{}
	if err := eachLine(*out+"/pages.jsonl", func(b []byte) error {
		var p struct {
			URL      string `json:"url"`
			FinalURL string `json:"final_url"`
			Visited  bool   `json:"visited"`
			Reason   string `json:"reason"`
		}
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		if p.Visited {
			visited[key(p.URL)] = true
			visited[key(p.FinalURL)] = true
		} else {
			reasons[key(p.URL)] = append(reasons[key(p.URL)], p.Reason)
		}
		return nil
	}); err != nil {
		return err
	}
	logText, err := os.ReadFile(*logPath)
	if err != nil {
		return err
	}
	var wrong []string
	okVisit := 0
	for _, v := range truth.Visit {
		if visited[v] {
			okVisit++
		} else {
			wrong = append(wrong, "not visited: "+v)
		}
	}
	okListed := 0
	for p, why := range truth.Listed {
		switch {
		case visited[p]:
			wrong = append(wrong, fmt.Sprintf("visited, want listed (%s): %s", why, p))
		case !contains(reasons[p], why):
			wrong = append(wrong, fmt.Sprintf("not listed as %s: %s (got %v)", why, p, reasons[p]))
		default:
			okListed++
		}
	}
	for _, f := range truth.Forbidden {
		for _, line := range strings.Split(string(logText), "\n") {
			if fields := strings.Fields(line); len(fields) >= 2 {
				if p, _, _ := strings.Cut(fields[len(fields)-1], "?"); p == f {
					wrong = append(wrong, "FORBIDDEN request: "+line)
				}
			}
		}
	}
	sort.Strings(wrong)
	fmt.Printf("frontier: visited %d/%d, listed %d/%d, forbidden requests %d\n", okVisit, len(truth.Visit), okListed, len(truth.Listed),
		strings.Count(strings.Join(wrong, "\n"), "FORBIDDEN"))
	for _, w := range wrong {
		fmt.Println("WRONG", w)
	}
	if len(wrong) > 0 {
		return fmt.Errorf("frontscore failed")
	}
	fmt.Println("frontscore: ok")
	return nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
