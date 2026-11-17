package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/archive"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
	"github.com/TimoMangCut/JSharvest/internal/verify"
)

// runVerify asks the target which of the catalog's endpoints are there
// (docs/gd6-waf-design.md, 20). It SENDS requests, reads only unless
// -allow-write: authorized targets only. -dry-run sends nothing.
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	profiles := fs.String("profiles", env("JSHARVEST_PROFILES", "profiles"), "profiles root of jsharvest login: the role's saved cookies go with its requests (env JSHARVEST_PROFILES)")
	target := fs.String("target", "", "the target's host, as its output directory is named (host, host:port, host_port or a URL)")
	role := fs.String("role", "anon", "the role whose catalog is verified, and as whom")
	historical := fs.Bool("include-historical", false, "verify the archive's historical endpoints too (archive/historical.jsonl)")
	includeDocs := fs.Bool("include-docs", true, "verify the lines only a document names (confidence doc)")
	includeStrings := fs.Bool("include-strings", false, "probe bare method-less path strings too (confidence string)")
	includeSourceOnly := fs.Bool("include-source-only", false, "probe endpoints found only in sourcemaps (tree-shaken from active bundles)")
	noCloudProbe := fs.Bool("no-cloud-probe", false, "skip safe ACL checks of cloud storage URLs in intel.json")
	scopeMode := fs.String("scope", "", "rdn or fqdn: the hosts requests may go to; default: the crawl's -scope")
	concurrency := fs.Int("concurrency", 8, "hosts verified at once, each one request at a time (-rate stays the ceiling on all requests)")
	gateAfter := fs.Int("gate-after", 0, "probes in a row on a host that all answer alike, as their canaries (a login, a device or app header before every route): the host's other drafts are not sent (0: never)")
	rf := addReplayFlags(fs)
	fs.Parse(args)
	if *target == "" {
		return errors.New("verify: -target is required")
	}
	if !roleRe.MatchString(*role) {
		return fmt.Errorf("verify: bad -role %q", *role)
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if *rf.dryRun && !given["max"] {
		*rf.max = 0 // a plan of every request, none sent
	}
	dir := filepath.Join(*out, targetDir(*target), *role)
	mode := *scopeMode
	if mode == "" {
		mode = results.ScopeMode(dir)
	}
	in, err := scope.New(hostOnly(*target), mode)
	if err != nil {
		return err
	}
	inputs, err := verify.Load(dir, filepath.Join(*out, hostOnly(*target), "archive"), *historical)
	if err != nil {
		return err
	}
	inputs.InScope = in
	drafts := verify.Drafts(inputs)
	dest := filepath.Join(dir, "verify")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	snap, _ := session.Load(filepath.Join(*profiles, targetDir(*target), *role))
	ua := pickUA(snap, dir, filepath.Join(*out, targetDir(*target), "*"))
	if *concurrency < 1 {
		return errors.New("verify: -concurrency must be 1 or more")
	}
	sender, policy, err := rf.sender(filepath.Join(dest, "sent.jsonl"), *concurrency, ua, *target)
	if err != nil {
		return err
	}
	defer sender.Close()
	o := verify.Options{Target: targetDir(*target), Role: *role, Drafts: drafts, Sender: sender, Policy: policy, InScope: in,
		AllowWrite: *rf.allowWrite, IncludeDocs: *includeDocs, IncludeStrings: *includeStrings, IncludeSourceOnly: *includeSourceOnly,
		Dir: dest, GateAfter: *gateAfter, Concurrency: *concurrency, Cloud: inputs.Intel.Cloud, IntelDir: dir, NoCloudProbe: *noCloudProbe}
	_, o.Recorded = archive.CrawlHosts(*out, in)
	// The role's identity: its saved login's cookies, and the credential
	// headers its traffic carried (Authorization, an API key), as replay
	// takes them (POL-23-2). anon with no login sends none: a draft's
	// sample credential is never sent.
	// The role's lines are kept only when they make its identity: anon
	// with no login reads none (round 25J).
	var entries []traffic.Entry
	if snap != nil || *role != "anon" {
		entries = roleEntries(dir)
	}
	if snap != nil || (*role != "anon" && len(entries) > 0) {
		o.Identity = replay.NewIdentity(*role, snap, entries, time.Now())
		fmt.Fprintf(os.Stderr, "as %s: %d credential header(s) from its traffic, cookies of %s\n", *role, len(o.Identity.Creds),
			map[bool]string{true: "its saved login", false: "its traffic"}[snap != nil])
		for _, n := range o.Identity.Notes {
			fmt.Fprintln(os.Stderr, "note:", n)
		}
	}
	if !sender.DryRun() {
		fmt.Fprintf(os.Stderr, "verify SENDS requests to %s (reads only%s), at -rate %.1f/s, -max %d: authorized targets only\n",
			targetDir(*target), map[bool]string{true: ", and writes: -allow-write", false: ""}[*rf.allowWrite], *rf.rate, *rf.max)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, rerr := verify.Run(ctx, o)
	if err := verify.Write(dest, rep); err != nil {
		return err
	}
	idx, err := verify.WriteDraftsFull(filepath.Join(dest, "drafts"), verify.WithUserAgent(drafts, ua), *includeDocs, *includeStrings, *includeSourceOnly, verify.AliveKeys(dest))
	if err != nil {
		return err
	}
	var parts []string
	for _, k := range slices.Sorted(mapKeys(rep.Verdicts)) {
		parts = append(parts, fmt.Sprintf("%s %d", k, rep.Verdicts[k]))
	}
	fmt.Fprintf(os.Stderr, "verify %s (%s): %d drafts, %d canaries, %d request(s)%s: %s; drafts/ %d files\n", targetDir(*target), *role,
		len(drafts), len(rep.Canaries), rep.Sent, map[bool]string{true: " planned (dry run)", false: " sent"}[rep.DryRun],
		strings.Join(parts, ", "), idx.Files)
	if rep.Stopped != "" {
		fmt.Fprintln(os.Stderr, "stopped:", rep.Stopped)
	}
	printBlockedHosts(rep.HostsBlocked)
	for h, why := range rep.HostsGated {
		fmt.Fprintf(os.Stderr, "host gated: %s: %s\n", h, why)
	}
	fmt.Fprintln(os.Stderr, "wrote", dest)
	return rerr
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// pickUA is the User-Agent a role's requests go with when theirs say none
// (round 25I review): its login's browser (the session's cookies may be
// bound to it), else what its own crawls' browser sent, else what any
// crawl of the target sent; "" leaves the Sender's fallback.
func pickUA(snap *session.Snapshot, roleDir, targetGlob string) string {
	if snap != nil && snap.UserAgent != "" && !strings.Contains(snap.UserAgent, "HeadlessChrome") {
		return snap.UserAgent
	}
	// One pass over the target's role directories (round 25J): each
	// requests.jsonl read once, as a stream, its lines not kept.
	role, all := uaCounts{}, uaCounts{}
	dirs, _ := filepath.Glob(targetGlob)
	if !slices.Contains(dirs, roleDir) {
		dirs = append(dirs, roleDir)
	}
	for _, d := range dirs {
		c := &all
		if filepath.Clean(d) == filepath.Clean(roleDir) {
			c = &role
		}
		scanEntries(d, c.add)
	}
	if ua := role.best(); ua != "" {
		return ua
	}
	all.merge(role)
	return all.best()
}

// observedUA is the User-Agent the run's browser sent most, read from the
// requests.jsonl of the role directories the patterns name: what the
// Sender says of itself when a raw request says nothing (round 25I, N0).
// A library's default or a headless one is never taken; "" when none.
func observedUA(patterns ...string) string {
	var c uaCounts
	for _, pat := range patterns {
		dirs, _ := filepath.Glob(pat)
		for _, d := range dirs {
			scanEntries(d, c.add)
		}
	}
	return c.best()
}

// uaCounts counts the User-Agents of recorded requests: Chrome's own
// apart from the HTTP engine's (tag http), which say the UA it was given
// and count only when no browser ran.
type uaCounts struct{ browser, engine map[string]int }

func (c *uaCounts) add(e traffic.Entry) {
	ua := e.Headers["user-agent"]
	if ua == "" || !strings.HasPrefix(ua, "Mozilla/5.0") || strings.Contains(ua, "HeadlessChrome") || strings.Contains(strings.ToLower(ua), "jsharvest") {
		return
	}
	if c.browser == nil {
		c.browser, c.engine = map[string]int{}, map[string]int{}
	}
	if slices.Contains(e.Tags, "http") {
		c.engine[ua]++
	} else {
		c.browser[ua]++
	}
}

func (c *uaCounts) merge(o uaCounts) {
	if c.browser == nil {
		c.browser, c.engine = map[string]int{}, map[string]int{}
	}
	for ua, n := range o.browser {
		c.browser[ua] += n
	}
	for ua, n := range o.engine {
		c.engine[ua] += n
	}
}

func (c uaCounts) best() string {
	most := func(count map[string]int) string {
		best := ""
		for ua, n := range count {
			if n > count[best] || n == count[best] && ua > best {
				best = ua
			}
		}
		return best
	}
	if ua := most(c.browser); ua != "" {
		return ua
	}
	return most(c.engine)
}

// roleEntries are a role's requests (requests.jsonl, oldest first), the
// tool's own and challenges' aside.
func roleEntries(dir string) []traffic.Entry {
	var out []traffic.Entry
	scanEntries(dir, func(e traffic.Entry) { out = append(out, e) })
	return out
}

// scanEntries hands each of a role's requests (requests.jsonl, oldest
// first) to f as it reads them, the tool's own and challenges' aside.
func scanEntries(dir string, f func(traffic.Entry)) {
	file, err := os.Open(filepath.Join(dir, "requests.jsonl"))
	if err != nil {
		return
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var e traffic.Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || slices.Contains(e.Tags, "jsharvest") || slices.Contains(e.Tags, "challenge") {
			continue
		}
		f(e)
	}
}
