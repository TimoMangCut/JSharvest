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
	"time"
)

// flowscore scores flows.jsonl against an app's flows.truth.json and the
// driver's step log:
//
//   - each user action (click, submit, change, input, key) belongs to the
//     step during which it started;
//
//   - precision: of the requests put under user actions, how many belong to
//     that step; recall: of the requests the steps expect, how many were put
//     under their step;
//
//   - the expected templates and depends_on links must be there.
//
//     testbed flowscore -truth flows.truth.json -steps steps.jsonl -out <output>/<host>/<role> [-min 0.95]
func flowscore(args []string) error {
	fset := flag.NewFlagSet("flowscore", flag.ExitOnError)
	truthPath := fset.String("truth", "", "flows.truth.json")
	stepsPath := fset.String("steps", "", "the driver's step log")
	out := fset.String("out", "", "jsharvest output directory (with flows.jsonl and requests.jsonl)")
	min := fset.Float64("min", 0.95, "lowest precision and recall that pass")
	guarded := fset.Bool("guard", false, "the watch ran the guard: its made-up answers carry no values, so depends_on is not checked")
	fset.Parse(args)
	if *truthPath == "" || *stepsPath == "" || *out == "" {
		return fmt.Errorf("-truth, -steps and -out are required")
	}
	truth, err := readTruthFile(*truthPath)
	if err != nil {
		return err
	}
	var starts []time.Time
	if err := eachLine(*stepsPath, func(b []byte) error {
		var s stepLog
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		starts = append(starts, s.Started)
		return nil
	}); err != nil {
		return err
	}

	type entry struct {
		Run    string `json:"run"`
		ID     int    `json:"id"`
		Method string `json:"method"`
		URL    string `json:"url"`
	}
	keys := map[int]string{} // request id -> "METHOD /path?query", for the last run
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
		Run      string    `json:"run"`
		Kind     string    `json:"kind"`
		Label    string    `json:"label"`
		Started  time.Time `json:"started"`
		Requests []struct {
			ID  int    `json:"id"`
			How string `json:"how"`
		} `json:"requests"`
		Endpoints []struct {
			Method   string `json:"method"`
			Template string `json:"template"`
		} `json:"endpoints"`
		DependsOn []struct {
			Request int    `json:"request"`
			At      string `json:"at"`
			From    struct {
				Request int    `json:"request"`
				At      string `json:"at"`
			} `json:"from"`
		} `json:"depends_on"`
	}
	var flows []flow
	if err := eachLine(*out+"/flows.jsonl", func(b []byte) error {
		var f flow
		if err := json.Unmarshal(b, &f); err != nil {
			return err
		}
		if f.Run == run {
			flows = append(flows, f)
		}
		return nil
	}); err != nil {
		return err
	}

	user := map[string]bool{"click": true, "submit": true, "change": true, "input": true, "key": true}
	stepOf := func(t time.Time) int {
		s := -1
		for i, st := range starts {
			if !t.Before(st) {
				s = i
			}
		}
		return s
	}
	// What each step got, as request keys with how they were traced.
	type gotReq struct{ key, how string }
	got := make([][]gotReq, len(truth.Steps))
	assigned, correct := 0, 0
	var wrong []string
	templates := map[string]bool{}
	for _, f := range flows {
		for _, e := range f.Endpoints {
			templates[e.Method+" "+e.Template] = true
		}
		if !user[f.Kind] {
			continue
		}
		s := stepOf(f.Started)
		for _, ref := range f.Requests {
			k := keys[ref.ID]
			assigned++
			if s < 0 {
				wrong = append(wrong, fmt.Sprintf("%s under %s %q before any step", k, f.Kind, f.Label))
				continue
			}
			got[s] = append(got[s], gotReq{k, ref.How})
		}
	}
	expected := 0
	var cases []string
	for i, st := range truth.Steps {
		want := slices.Clone(st.Expect)
		expected += len(want)
		ok := true
		for _, g := range got[i] {
			j := slices.IndexFunc(want, func(p string) bool { return expectMatch(p, g.key) })
			switch {
			case j < 0:
				wrong = append(wrong, fmt.Sprintf("step %d (%s %s) got %s", i, st.Do, st.Selector, g.key))
				ok = false
			case st.How != "" && g.how != st.How:
				wrong = append(wrong, fmt.Sprintf("step %d (%s %s) got %s by %s, want %s", i, st.Do, st.Selector, g.key, g.how, st.How))
				want = slices.Delete(want, j, j+1)
				ok = false
			default:
				want = slices.Delete(want, j, j+1)
				correct++
			}
		}
		for _, k := range want {
			wrong = append(wrong, fmt.Sprintf("step %d (%s %s) missed %s", i, st.Do, st.Selector, k))
			ok = false
		}
		if len(st.Expect) > 0 {
			mark := "pass"
			if !ok {
				mark = "FAIL"
			}
			cases = append(cases, fmt.Sprintf("%s %s %s", mark, st.Do, st.Selector))
		}
	}
	precision, recall := ratio(correct, assigned), ratio(correct, expected)

	var problems []string
	for _, t := range truth.Templates {
		if !templates[t.Method+" "+t.Template] {
			problems = append(problems, "missing template "+t.Method+" "+t.Template)
		}
	}
	for _, d := range truth.DependsOn {
		if *guarded {
			break
		}
		found := false
		for _, f := range flows {
			for _, l := range f.DependsOn {
				if expectMatch(d.Request, keyPath(keys[l.Request])) && l.At == d.At && expectMatch(d.From, keyPath(keys[l.From.Request])) && l.From.At == d.FromAt {
					found = true
				}
			}
		}
		if !found {
			problems = append(problems, fmt.Sprintf("missing depends_on %s %s <- %s %s", d.Request, d.At, d.From, d.FromAt))
		}
	}

	fmt.Printf("run %s: %d flows; precision %d/%d (%.0f%%), recall %d/%d (%.0f%%)\n",
		run, len(flows), correct, assigned, precision*100, correct, expected, recall*100)
	for _, c := range cases {
		fmt.Println(c)
	}
	for _, w := range wrong {
		fmt.Println("WRONG", w)
	}
	for _, p := range problems {
		fmt.Println("PROBLEM", p)
	}
	if precision < *min || recall < *min || len(problems) > 0 {
		return fmt.Errorf("flowscore failed")
	}
	fmt.Println("flowscore: ok")
	return nil
}

var placeholderRe = regexp.MustCompile(`\\\{[a-z_]+\\\}`)

// expectMatch matches a request key against an expected one, where {name}
// stands for one path segment whose value the run made up (a new id).
func expectMatch(pattern, key string) bool {
	if !strings.Contains(pattern, "{") {
		return pattern == key
	}
	re := "^" + placeholderRe.ReplaceAllString(regexp.QuoteMeta(pattern), `[^/?&]+`) + "$"
	ok, _ := regexp.MatchString(re, key)
	return ok
}

// keyPath drops the query of a request key, as the truth's depends_on
// names requests by method and path.
func keyPath(k string) string {
	p, _, _ := strings.Cut(k, "?")
	return p
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func eachLine(p string, f func([]byte) error) error {
	file, err := os.Open(p)
	if err != nil {
		return err
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		if err := f(sc.Bytes()); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return sc.Err()
}
