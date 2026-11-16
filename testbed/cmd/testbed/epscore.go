package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// epTruth is an app's endpoints.truth.json: what its scripts call.
type epTruth struct {
	Endpoints []epWant `json:"endpoints"`
	Routes    []string `json:"routes"`
	Noise     []string `json:"noise"`
}

type epWant struct {
	Method     string   `json:"method"`
	Host       string   `json:"host"`
	Path       string   `json:"path"`
	Status     string   `json:"status"`
	Chunk      string   `json:"chunk"` // admin: only an admin's page runs it
	Query      []string `json:"query"`
	Body       []string `json:"body"`
	Headers    []string `json:"headers"`
	Operations []string `json:"operations"`
}

type epLine struct {
	Method     string   `json:"method"`
	Host       string   `json:"host"`
	Path       string   `json:"path"`
	Status     string   `json:"status"`
	Query      []string `json:"query"`
	Body       []string `json:"body"`
	Headers    []string `json:"headers"`
	Operations []string `json:"operations"`
	Base       string   `json:"base"`
	Bases      []string `json:"bases"`
	ThirdParty bool     `json:"third_party"`
}

// paths are the full paths an endpoint may stand for: with its confirmed
// base, or with each base the code names.
func (e epLine) paths() []string {
	if e.Base != "" {
		return []string{e.Base + e.Path}
	}
	out := []string{e.Path}
	for _, b := range e.Bases {
		out = append(out, b+strings.TrimPrefix(e.Path, "{}"))
	}
	return out
}

// epscore checks a jsharvest endpoints.jsonl against an app's truth:
//
//	testbed epscore -truth testbed/apps/endpoints-app/endpoints.truth.json -out <output>/<host>/<role>
//
// Every endpoint must be found with its method, parameters and status (what
// the run saw of it); nothing else of the target may be listed; no noise and
// no route may be taken for an endpoint.
func epscore(args []string) error {
	fset := flag.NewFlagSet("epscore", flag.ExitOnError)
	truthPath := fset.String("truth", "", "endpoints.truth.json")
	out := fset.String("out", "", "jsharvest output directory, with endpoints.jsonl")
	ran := fset.String("ran", "", `comma-separated "METHOD /path" of the truth that a later run made: their status must now be both`)
	fset.Parse(args)
	if *truthPath == "" || *out == "" {
		return fmt.Errorf("-truth and -out are required")
	}
	b, err := os.ReadFile(*truthPath)
	if err != nil {
		return err
	}
	var truth epTruth
	if err := json.Unmarshal(b, &truth); err != nil {
		return err
	}
	for _, k := range strings.Split(*ran, ",") {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		method, path, _ := strings.Cut(k, " ")
		i := slices.IndexFunc(truth.Endpoints, func(t epWant) bool {
			return t.Method == method && t.Path == path
		})
		if i < 0 {
			return fmt.Errorf("-ran: %q is not in the truth", k)
		}
		truth.Endpoints[i].Status = "both"
	}
	var got []epLine
	if err := eachLine(*out+"/endpoints.jsonl", func(b []byte) error {
		var e epLine
		if err := json.Unmarshal(b, &e); err != nil {
			return err
		}
		if !e.ThirdParty {
			got = append(got, e)
		}
		return nil
	}); err != nil {
		return err
	}

	var wrong []string
	used := make([]bool, len(got))
	found, admin, admins := 0, 0, 0
	for _, t := range truth.Endpoints {
		if t.Chunk == "admin" {
			admins++
		}
		j := slices.IndexFunc(got, func(e epLine) bool {
			return e.Host == t.Host && (t.Method == "" || e.Method == t.Method) &&
				slices.ContainsFunc(e.paths(), func(p string) bool { return p == t.Path })
		})
		if j < 0 {
			wrong = append(wrong, fmt.Sprintf("missed %s %s%s", t.Method, t.Host, t.Path))
			continue
		}
		used[j] = true
		e := got[j]
		ok := true
		check := func(what string, want, have []string) {
			for _, w := range want {
				if !slices.Contains(have, w) {
					wrong = append(wrong, fmt.Sprintf("%s %s: no %s %q in %v", t.Method, t.Path, what, w, have))
					ok = false
				}
			}
		}
		check("query", t.Query, e.Query)
		check("body", t.Body, e.Body)
		check("header", t.Headers, e.Headers)
		check("operation", t.Operations, e.Operations)
		if e.Status != t.Status {
			wrong = append(wrong, fmt.Sprintf("%s %s: status %s, want %s", t.Method, t.Path, e.Status, t.Status))
			ok = false
		}
		if ok {
			found++
			if t.Chunk == "admin" {
				admin++
			}
		}
	}
	for i, e := range got {
		if !used[i] {
			wrong = append(wrong, fmt.Sprintf("extra %s %s%s (%s)", e.Method, e.Host, e.Path, e.Status))
		}
	}
	for _, e := range got {
		for _, n := range truth.Noise {
			if p := e.Host + e.Path; p == n || (len(n) > 4 && strings.Contains(p, n)) {
				wrong = append(wrong, fmt.Sprintf("noise %q taken for %s", n, p))
			}
		}
		for _, r := range truth.Routes {
			if re := "^" + regexp.QuoteMeta(r) + "$"; regexp.MustCompile(re).MatchString(e.Path) {
				wrong = append(wrong, "route taken for an endpoint: "+r)
			}
		}
	}
	fmt.Printf("endpoints: %d/%d right (admin chunk %d/%d), %d listed\n", found, len(truth.Endpoints), admin, admins, len(got))
	for _, w := range wrong {
		fmt.Println("WRONG", w)
	}
	if len(wrong) > 0 {
		return fmt.Errorf("epscore failed")
	}
	fmt.Println("epscore: ok")
	return nil
}
