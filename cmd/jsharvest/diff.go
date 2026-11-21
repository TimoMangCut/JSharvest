package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/roles"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// runDiff compares the roles of one target (see docs/gd4-roles-design.md).
// It reads the crawl output and sends nothing.
func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	target := fs.String("target", "", "the target's host, as its output directory is named")
	order := fs.String("roles", "", "the roles, lowest first (e.g. anon,user,admin); default: the role directories, if all have known names")
	all := fs.Bool("all", false, "report what is the same for every role too")
	reveal := fs.Bool("reveal", false, "quote URLs and labels as they are (by default credentials are masked)")
	fs.Parse(args)
	if *target == "" {
		return errors.New("diff: -target is required")
	}
	root := filepath.Join(*out, targetDir(*target))
	var names []string
	if *order != "" {
		names = strings.Split(*order, ",")
	} else {
		ents, err := os.ReadDir(root)
		if err != nil {
			return fmt.Errorf("diff: %w", err)
		}
		var found []string
		for _, e := range ents {
			if e.IsDir() && roleRe.MatchString(e.Name()) {
				if _, err := os.Stat(filepath.Join(root, e.Name(), "runs.jsonl")); err == nil {
					found = append(found, e.Name())
				}
			}
		}
		sort.Strings(found)
		if names, err = roles.Order(found); err != nil {
			return err
		}
	}
	for _, n := range names {
		if !roleRe.MatchString(n) || strings.Contains(n, "..") {
			return fmt.Errorf("diff: bad role %q", n)
		}
	}
	in, err := scope.New(hostOnly(*target), results.ScopeMode(filepath.Join(root, names[len(names)-1])))
	if err != nil {
		return err
	}
	o := roles.Options{Root: root, Roles: names, All: *all, InScope: in}
	if !*reveal {
		red := traffic.NewRedactor()
		o.Redact = func(s string) string { return roles.MaskTokens(red.URL(s)) }
	}
	rep, err := roles.Compare(o)
	if err != nil {
		return err
	}
	if err := rep.Write(root); err != nil {
		return err
	}
	fprintClean(os.Stderr, "roles %s: %d items\n", strings.Join(names, " < "), len(rep.Items))
	for _, w := range rep.Warnings {
		fprintlnClean(os.Stderr, "warning:", w)
	}
	layers := make([]string, 0, len(rep.Summary))
	for l := range rep.Summary {
		layers = append(layers, l)
	}
	sort.Strings(layers)
	for _, l := range layers {
		var parts []string
		for c, n := range rep.Summary[l] {
			parts = append(parts, fmt.Sprintf("%s %d", c, n))
		}
		sort.Strings(parts)
		fmt.Fprintf(os.Stderr, "  %-9s %s\n", l, strings.Join(parts, ", "))
	}
	fmt.Fprintf(os.Stderr, "wrote %s and %s\n", filepath.Join(root, "diff.json"), filepath.Join(root, "diff.md"))
	return nil
}

// hostOnly is the host name of what -target is given (host, host:port,
// host_port, a URL): what the scope is made from.
func hostOnly(h string) string { return scope.TargetHost(h) }

// targetDir is the output directory's name of what -target is given.
func targetDir(h string) string { return scope.NormalizeTargetArg(h) }
