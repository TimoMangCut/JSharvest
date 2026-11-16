package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// authzscore checks jsharvest authz's authz.json against authz.truth.json:
// each item's verdict for each role, with -write the verdicts with
// -allow-write, no item the truth does not name; and that no trial of a
// lower role carried a secret of the higher one (sent.jsonl).
//
//	testbed authzscore -truth authz.truth.json -authz <out>/<host>/authz [-write] [-secrets FILE]
func authzscore(args []string) error {
	fset := flag.NewFlagSet("authzscore", flag.ExitOnError)
	truthPath := fset.String("truth", "", "authz.truth.json")
	dir := fset.String("authz", "", "the authz directory (authz.json, sent.jsonl)")
	write := fset.Bool("write", false, "the run had -allow-write")
	secrets := fset.String("secrets", "", "a file of the higher role's secrets, one a line: none may be in a lower role's trial")
	fset.Parse(args)
	var truth struct {
		Items []map[string]string `json:"items"`
	}
	var rep struct {
		Items []struct {
			Key    string `json:"key"`
			Trials []struct {
				Role    string `json:"role"`
				Verdict string `json:"verdict"`
				Reason  string `json:"reason"`
			} `json:"trials"`
		} `json:"items"`
	}
	if err := readJSON(*truthPath, &truth); err != nil {
		return err
	}
	if err := readJSON(*dir+"/authz.json", &rep); err != nil {
		return err
	}
	keyRe := func(k string) *regexp.Regexp {
		var parts []string
		for _, lit := range expectRe.Split(k, -1) {
			parts = append(parts, regexp.QuoteMeta(lit))
		}
		return regexp.MustCompile("^" + strings.Join(parts, `\{[^}]*\}`) + "$")
	}
	bad, ok := 0, 0
	seen := map[int]bool{}
	for _, it := range rep.Items {
		key := stripHost(it.Key)
		found := -1
		for i, w := range truth.Items {
			if keyRe(w["key"]).MatchString(key) {
				found = i
			}
		}
		if found < 0 {
			fmt.Printf("EXTRA %s\n", key)
			bad++
			continue
		}
		seen[found] = true
		w := truth.Items[found]
		for _, t := range it.Trials {
			want := w[t.Role]
			if v, has := w["write_"+t.Role]; *write && has {
				want = v
			}
			if want != t.Verdict {
				fmt.Printf("WRONG %s as %s: %s (%s), want %s\n", key, t.Role, t.Verdict, t.Reason, want)
				bad++
			} else {
				ok++
			}
		}
	}
	for i, w := range truth.Items {
		if !seen[i] {
			fmt.Printf("MISSING %s\n", w["key"])
			bad++
		}
	}
	if *secrets != "" {
		b, err := os.ReadFile(*secrets)
		if err != nil {
			return err
		}
		var secret []string
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); len(l) >= 8 {
				secret = append(secret, l)
			}
		}
		f, err := os.Open(*dir + "/sent.jsonl")
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		trials := 0
		for sc.Scan() {
			var s struct {
				Purpose, Role, Request string
			}
			if json.Unmarshal(sc.Bytes(), &s) != nil || s.Role == "admin" {
				continue
			}
			trials++
			for _, x := range secret {
				if strings.Contains(s.Request, x) {
					fmt.Printf("LEAK a %s request as %s carries the higher role's %s…\n", s.Purpose, s.Role, x[:6])
					bad++
				}
			}
		}
		fmt.Printf("authzscore: %d requests of lower roles checked for %d secrets\n", trials, len(secret))
	}
	fmt.Printf("authzscore: %d right, %d wrong\n", ok, bad)
	if bad > 0 {
		return fmt.Errorf("authzscore: %d failure(s)", bad)
	}
	return nil
}
