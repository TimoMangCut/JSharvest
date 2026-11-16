package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// replayFlags are the safety and pace flags of the commands that send.
type replayFlags struct {
	allowWrite *bool
	readAllow  *string
	allowAuth  *string
	rate       *float64
	max        *int
	proxy      *string
	insecure   *bool
	hosts      *string
	dryRun     *bool
	timeout    *time.Duration
	onBlock    *string
	chrome     *string
	hostRules  *string
}

func addReplayFlags(fs *flag.FlagSet) replayFlags {
	return replayFlags{
		allowWrite: fs.Bool("allow-write", false, "send writes too (POST, PUT, PATCH, GraphQL mutations, GETs that name an action): only on a target you may change"),
		readAllow:  fs.String("read-allow", "", "regexp of URLs whose POSTs only read (a search): sent without -allow-write"),
		allowAuth:  fs.String("allow-auth", "", "regexp of login-flow URLs to send all the same (never sent by default: they may rotate the session)"),
		rate:       fs.Float64("rate", 2, "requests per second, at most"),
		max:        fs.Int("max", 300, "requests in all, at most (sources, controls, probes and trials)"),
		proxy:      fs.String("proxy", "", "send through this proxy (Burp, Caido, ZAP), e.g. http://127.0.0.1:8080; default JSHARVEST_PROXY, HTTPS_PROXY, HTTP_PROXY; none: no proxy"),
		insecure:   fs.Bool("insecure", false, "accept any TLS certificate"),
		hosts:      fs.String("hosts", "", "the hosts (host:port as recorded) to send to, comma separated; default: those of the requests tried, in scope"),
		dryRun:     fs.Bool("dry-run", false, "send nothing: write what would be sent to sent.jsonl"),
		timeout:    fs.Duration("timeout", 20*time.Second, "a request's timeout (EventSource and long polls need more)"),
		hostRules:  fs.String("host-resolver-rules", env("JSHARVEST_HOST_RESOLVER_RULES", ""), `Chrome host resolver rules, e.g. "MAP *.example.test 127.0.0.1": a host they map is reached where the rule says (env JSHARVEST_HOST_RESOLVER_RULES)`),
		chrome:     fs.String("chrome", env("JSHARVEST_CHROME", ""), "the Chrome whose version the User-Agent and client hints follow when a request says none (env JSHARVEST_CHROME); default: search PATH"),
		onBlock:    fs.String("on-block", replay.OnBlockHost, "when a CDN/WAF answers in the application's place: host (the item is marked blocked; one control request asks whether the host still answers, and the host alone is given up when it does not), skip (mark the item, nothing else) or stop (the first block stops the run)"),
	}
}

// sender makes the Sender; concurrency is how many requests may be in
// flight at once (-rate stays the ceiling on all of them).
func (f replayFlags) sender(log string, concurrency int, ua, target string) (*replay.Sender, replay.Policy, error) {
	var p replay.Policy
	var err error
	if *f.readAllow != "" {
		if p.ReadAllow, err = regexp.Compile(*f.readAllow); err != nil {
			return nil, p, fmt.Errorf("-read-allow: %w", err)
		}
	}
	if *f.allowAuth != "" {
		if p.AuthAllow, err = regexp.Compile(*f.allowAuth); err != nil {
			return nil, p, fmt.Errorf("-allow-auth: %w", err)
		}
	}
	o := replay.SenderOptions{Max: *f.max, Timeout: *f.timeout, Insecure: *f.insecure, Log: log, DryRun: *f.dryRun, Concurrency: concurrency, OnBlock: *f.onBlock, UserAgent: ua, ChromePath: *f.chrome}
	if _, err := replay.ParseOnBlock(o.OnBlock); err != nil {
		return nil, p, err
	}
	if o.HostRules, err = netsafe.ParseHostRules(*f.hostRules); err != nil {
		return nil, p, fmt.Errorf("-host-resolver-rules: %w", err)
	}
	if *f.rate > 0 {
		o.Rate = time.Duration(float64(time.Second) / *f.rate)
	}
	if pv, err := resolveProxy(*f.proxy); err != nil {
		return nil, p, err
	} else if pv != "" {
		if o.Proxy, err = url.Parse(pv); err != nil {
			return nil, p, fmt.Errorf("-proxy: %w", err)
		}
		fmt.Fprintln(os.Stderr, "note: through a proxy, the check that a host still resolves where the browser reached it cannot be made")
	}
	// Private addresses are reachable only when the target itself is
	// internal; a target not known to be is public (closed). Behind a proxy
	// no name is looked up here: a literal or a host rule decides.
	o.AllowPrivate = netsafe.InternalTargetVia(context.Background(), liveHost(target), o.HostRules, nil, o.Proxy != nil)
	if *f.hosts != "" {
		o.Hosts = map[string]bool{}
		for _, h := range strings.Split(*f.hosts, ",") {
			o.Hosts[strings.TrimSpace(h)] = true
		}
	}
	s, err := replay.NewSender(o)
	return s, p, err
}

// runAuthz tries the higher roles' requests as the lower roles (see
// docs/gd5-replay-design.md). It sends requests: authorized targets only.
func runAuthz(args []string) error {
	fs := flag.NewFlagSet("authz", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	profiles := fs.String("profiles", env("JSHARVEST_PROFILES", "profiles"), "profiles root of jsharvest login (env JSHARVEST_PROFILES)")
	target := fs.String("target", "", "the target's host, as its output directory is named (diff.json must be there)")
	classes := fs.String("classes", strings.Join(replay.DefaultClasses, ","), "the diff classes to try")
	controlWrites := fs.Bool("control-writes", false, "with -allow-write, send the higher role's write too, as a control (it then does what it does)")
	concurrency := fs.Int("concurrency", 1, "endpoints tried at once (the trials and controls of one stay in order); -rate stays the ceiling on all requests")
	scopeMode := fs.String("scope", "fqdn", "rdn or fqdn: the hosts requests may go to (only those of the requests tried, within it)")
	peers := fs.String("peers", "", "horizontal test (BOLA): two peers of the same level, a,b (roles crawled with -role): each one's requests are sent under the other's identity, both ways; not with -classes (docs/gd7-bola-design.md)")
	relation := fs.String("relation", "", "with -peers (required): same-org (the peers share an org: B reading A's object is a bypass only when it is private) or cross-org (any read of A's private data by B is a bypass)")
	substitute := fs.Bool("substitute", false, "with -peers: for a request with two ids or more that B's parent check refuses, put each id alone in B's own request (finds a leaf that forgets its parent)")
	private := fs.String("private", "", "with -peers -relation same-org: regexp of the URLs or endpoint keys whose data is private to a person (a finding is then a bypass, not shared)")
	reveal := fs.Bool("reveal", false, "with -peers: write the evidence's values as they are in bola.json and bola.md (else REDACTED_<hash>)")
	rf := addReplayFlags(fs)
	fs.Parse(args)
	if *target == "" {
		return errors.New("authz: -target is required")
	}
	if *peers != "" {
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		if set["concurrency"] {
			return errors.New("authz: -concurrency is not for -peers (the trials of a pair go one at a time, in order; -rate paces them)")
		}
		if set["classes"] || *controlWrites {
			return errors.New("authz: -peers and the vertical test (-classes, -control-writes) exclude each other")
		}
		return runBola(*peers, *relation, *substitute, *private, *reveal, *out, *profiles, *target, *scopeMode, rf)
	}
	if *relation != "" || *substitute || *private != "" || *reveal {
		return errors.New("authz: -relation, -substitute, -private and -reveal are for -peers")
	}
	root := filepath.Join(*out, targetDir(*target))
	in, err := scope.New(hostOnly(*target), *scopeMode)
	if err != nil {
		return err
	}
	dest := filepath.Join(root, "authz")
	if *concurrency < 1 {
		return errors.New("authz: -concurrency must be 1 or more")
	}
	sender, policy, err := rf.sender(filepath.Join(dest, "sent.jsonl"), *concurrency, observedUA(filepath.Join(root, "*")), *target)
	if err != nil {
		return err
	}
	defer sender.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := replay.Authz(ctx, replay.AuthzOptions{Root: root, Profiles: filepath.Join(*profiles, targetDir(*target)), Classes: strings.Split(*classes, ","),
		Policy: policy, AllowWrite: *rf.allowWrite, ControlWrites: *controlWrites, Sender: sender, InScope: in, Out: dest, Concurrency: *concurrency})
	if err != nil {
		return err
	}
	if err := rep.Write(dest); err != nil {
		return err
	}
	var parts []string
	for v, n := range rep.Summary {
		parts = append(parts, fmt.Sprintf("%s %d", v, n))
	}
	sort.Strings(parts)
	verb := "sent"
	if *rf.dryRun {
		verb = "that would be sent (dry run)"
	}
	fmt.Fprintf(os.Stderr, "authz %s (%s): %d items, %d requests %s to %s; %s\n", rep.Host, strings.Join(rep.Roles, " < "), len(rep.Items), rep.Sent, verb,
		strings.Join(sender.Hosts(), ", "), strings.Join(parts, ", "))
	for _, n := range rep.Notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	if rep.Stopped != "" {
		fmt.Fprintln(os.Stderr, "stopped:", rep.Stopped)
	}
	printBlockedHosts(rep.HostsBlocked)
	fmt.Fprintf(os.Stderr, "wrote %s and %s\n", filepath.Join(dest, "authz.json"), filepath.Join(dest, "authz.md"))
	return nil
}

// printBlockedHosts says which hosts a run gave up, and why (round 25H).
func printBlockedHosts(m map[string]string) {
	hosts := make([]string, 0, len(m))
	for h := range m {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		fmt.Fprintf(os.Stderr, "host given up: %s: %s\n", h, m[h])
	}
}

// resolveProxy picks the run's one proxy (netsafe.ProxyFrom: -proxy, then
// JSHARVEST_PROXY, HTTPS_PROXY, HTTP_PROXY; "none" for none) and says so on
// stderr, without its credential. It returns the URL as a string, "" for no
// proxy.
func resolveProxy(flagVal string) (string, error) {
	u, _, err := netsafe.ProxyFrom(flagVal, os.Getenv)
	if err != nil {
		return "", fmt.Errorf("-proxy: %w", err)
	}
	if u == nil {
		return "", nil
	}
	fmt.Fprintln(os.Stderr, netsafe.ProxyLine(u))
	return u.String(), nil
}

// runBola is authz -peers: the horizontal test.
func runBola(peers, relation string, substitute bool, private string, reveal bool, out, profiles, target, scopeMode string, rf replayFlags) error {
	names := strings.Split(peers, ",")
	if len(names) != 2 {
		return errors.New("authz: -peers takes two roles, a,b")
	}
	var pair [2]string
	for i, n := range names {
		n = strings.TrimSpace(n)
		if !roleRe.MatchString(n) || strings.Contains(n, "..") || n == "anon" || n == "archive" {
			return fmt.Errorf("authz: -peers: %q is no role of two people to compare", n)
		}
		pair[i] = n
	}
	if pair[0] == pair[1] {
		return errors.New("authz: -peers takes two different roles")
	}
	rel := replay.Relation(relation)
	if rel != replay.RelSameOrg && rel != replay.RelCrossOrg {
		return errors.New("authz: -peers needs -relation same-org or cross-org")
	}
	var priv *regexp.Regexp
	if private != "" {
		if rel != replay.RelSameOrg {
			return errors.New("authz: -private is for -relation same-org")
		}
		var err error
		if priv, err = regexp.Compile(private); err != nil {
			return fmt.Errorf("-private: %w", err)
		}
	}
	root := filepath.Join(out, targetDir(target))
	in, err := scope.New(hostOnly(target), scopeMode)
	if err != nil {
		return err
	}
	dest := filepath.Join(root, "authz")
	sender, policy, err := rf.sender(filepath.Join(dest, "bola.sent.jsonl"), 1, observedUA(filepath.Join(root, "*")), target)
	if err != nil {
		return err
	}
	defer sender.Close()
	if *rf.allowWrite {
		fmt.Fprintln(os.Stderr, "warning: -allow-write with -peers sends writes in both directions, as blind writes, to the real data of both peers")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := replay.Bola(ctx, replay.BolaOptions{Root: root, Profiles: filepath.Join(profiles, targetDir(target)), Peers: pair, Relation: rel,
		Private: priv, Substitute: substitute, AllowWrite: *rf.allowWrite, Reveal: reveal, Policy: policy, Sender: sender, InScope: in, Out: dest})
	if err != nil {
		return err
	}
	if err := rep.Write(dest); err != nil {
		return err
	}
	var parts []string
	for v, n := range rep.Summary {
		parts = append(parts, fmt.Sprintf("%s %d", v, n))
	}
	sort.Strings(parts)
	verb := "sent"
	if *rf.dryRun {
		verb = "that would be sent (dry run)"
	}
	fmt.Fprintf(os.Stderr, "authz %s (%s, %s): %d items, %d requests %s to %s; %s\n", rep.Host, pair[0]+" <-> "+pair[1], rel, len(rep.Items), rep.Sent, verb,
		strings.Join(sender.Hosts(), ", "), strings.Join(parts, ", "))
	for _, n := range rep.Notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	if rep.Stopped != "" {
		fmt.Fprintln(os.Stderr, "stopped:", rep.Stopped)
	}
	printBlockedHosts(rep.HostsBlocked)
	fmt.Fprintf(os.Stderr, "wrote %s and %s\n", filepath.Join(dest, "bola.json"), filepath.Join(dest, "bola.md"))
	return nil
}
