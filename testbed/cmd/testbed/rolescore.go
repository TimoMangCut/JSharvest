package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// rolescore checks jsharvest diff's diff.json against a roles.truth.json:
// every expected item with its class and lowest role, no item the truth
// says is the same for every role, no item the truth does not name, and
// the warnings it names.
//
//	testbed rolescore -truth roles.truth.json -diff <out>/<host>/diff.json
func rolescore(args []string) error {
	fset := flag.NewFlagSet("rolescore", flag.ExitOnError)
	truthPath := fset.String("truth", "", "roles.truth.json")
	diffPath := fset.String("diff", "", "diff.json")
	fset.Parse(args)
	var truth struct {
		Items []struct {
			Layer, Key, Class, Lowest string
		} `json:"items"`
		Absent   []string `json:"absent"`
		Warnings []string `json:"warnings"`
	}
	var rep struct {
		Warnings []string `json:"warnings"`
		Items    []struct {
			Layer  string            `json:"layer"`
			Key    string            `json:"key"`
			Class  string            `json:"class"`
			Lowest string            `json:"lowest"`
			States map[string]string `json:"states"`
		} `json:"items"`
	}
	for p, v := range map[string]any{*truthPath: &truth, *diffPath: &rep} {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, v); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	// An endpoint's key is "METHOD host/path [op]": compared without the host.
	keyOf := func(layer, key string) string {
		if layer != "endpoint" {
			return key
		}
		method, rest, _ := strings.Cut(key, " ")
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[i:]
		}
		return method + " " + rest
	}
	match := func(pattern, key string) bool {
		if !strings.Contains(pattern, "{") {
			return pattern == key
		}
		return expectMatch(pattern, key)
	}
	failed := false
	used := make([]bool, len(rep.Items))
	for _, want := range truth.Items {
		found := -1
		for i, it := range rep.Items {
			if it.Layer == want.Layer && match(want.Key, keyOf(it.Layer, it.Key)) {
				found = i
				break
			}
		}
		switch {
		case found < 0:
			fmt.Printf("  FAIL  %-8s %-45s missing (want %s from %s)\n", want.Layer, want.Key, want.Class, want.Lowest)
			failed = true
		case rep.Items[found].Class != want.Class || rep.Items[found].Lowest != want.Lowest:
			it := rep.Items[found]
			fmt.Printf("  FAIL  %-8s %-45s %s from %s, want %s from %s %v\n", want.Layer, want.Key, it.Class, it.Lowest, want.Class, want.Lowest, it.States)
			failed = true
			used[found] = true
		default:
			fmt.Printf("  pass  %-8s %-45s %s from %s\n", want.Layer, want.Key, want.Class, want.Lowest)
			used[found] = true
		}
	}
	for i, it := range rep.Items {
		if used[i] {
			continue
		}
		k := keyOf(it.Layer, it.Key)
		why := "not in the truth"
		for _, a := range truth.Absent {
			if a == k {
				why = "must not be reported"
			}
		}
		fmt.Printf("  FAIL  %-8s %-45s %s from %s: %s %v\n", it.Layer, k, it.Class, it.Lowest, why, it.States)
		failed = true
	}
	for _, w := range truth.Warnings {
		if !strings.Contains(strings.Join(rep.Warnings, "\n"), w) {
			fmt.Printf("  FAIL  no warning about %q\n", w)
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("roles score: failed")
	}
	fmt.Println("roles score: ok")
	return nil
}
