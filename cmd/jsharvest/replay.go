package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// runReplay sends one flow again, its values taken fresh (see
// docs/gd5-replay-design.md). It sends requests: authorized targets only.
func runReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	profiles := fs.String("profiles", env("JSHARVEST_PROFILES", "profiles"), "profiles root of jsharvest login (env JSHARVEST_PROFILES)")
	target := fs.String("target", "", "the target's host, as its output directory is named")
	role := fs.String("role", "anon", "the role whose flow it is")
	as := fs.String("as", "", "send as this role (its login, or its recorded traffic); default: -role")
	action := fs.String("flow", "", "the flow's action id (a8; flows.jsonl, or the export's flows/)")
	run := fs.String("run", "", "the flow's run; default: the newest run with that flow")
	allowDestructive := fs.Bool("allow-destructive", false, "with -allow-write, send destructive requests too (DELETE, purge, remove…): never a logout")
	keepIDs := fs.Bool("keep-ids", false, "take only credentials (a CSRF token) fresh; keep the ids and values earlier answers gave as recorded")
	scopeMode := fs.String("scope", "fqdn", "rdn or fqdn: the hosts requests may go to")
	rf := addReplayFlags(fs)
	fs.Parse(args)
	if *target == "" || *action == "" {
		return errors.New("replay: -target and -flow are required")
	}
	if *as == "" {
		*as = *role
	}
	for _, r := range []string{*role, *as} {
		if !roleRe.MatchString(r) {
			return fmt.Errorf("replay: bad role %q", r)
		}
	}
	in, err := scope.New(hostOnly(*target), *scopeMode)
	if err != nil {
		return err
	}
	root := filepath.Join(*out, targetDir(*target))
	m, err := export.Load(export.Options{Dir: filepath.Join(root, *role), Run: "all", InScope: in})
	if err != nil {
		return err
	}
	// The identity: the role's login snapshot, and what its traffic carried.
	idModel := m
	if *as != *role {
		if idModel, err = export.Load(export.Options{Dir: filepath.Join(root, *as), Run: "all", InScope: in}); err != nil {
			return fmt.Errorf("replay: -as %s: %w", *as, err)
		}
	}
	var snap *session.Snapshot
	if s, err := session.Load(filepath.Join(*profiles, targetDir(*target), *as)); err == nil {
		snap = s
	}
	entries := make([]traffic.Entry, len(idModel.Requests))
	for i, r := range idModel.Requests {
		entries[i] = r.Entry
	}
	id := replay.NewIdentity(*as, snap, entries, time.Now())
	for _, n := range id.Notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	dest := filepath.Join(root, *role, "replay", fmt.Sprintf("%s-%s", *action, strings.ReplaceAll(time.Now().UTC().Format("20060102T150405.000"), ".", "")))
	sender, policy, err := rf.sender(filepath.Join(dest, "sent.jsonl"), 1, pickUA(snap, filepath.Join(root, *as), filepath.Join(root, "*")), *target) // a flow's steps hang on each other
	if err != nil {
		return err
	}
	defer sender.Close()
	hosts := map[string]bool{}
	for _, r := range m.Requests {
		if u, err := urlOf(r.Entry.URL); err == nil && in(u.Hostname()) {
			hosts[u.Host] = true
		}
	}
	sender.Allow(hosts, nil)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := replay.ReplayFlow(ctx, replay.FlowOptions{Model: m, Run: *run, Action: *action, As: id, Owner: *role, Policy: policy,
		AllowWrite: *rf.allowWrite, AllowDestructive: *allowDestructive, KeepIDs: *keepIDs, Sender: sender, InScope: in})
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(res, "", " ")
	if err := os.WriteFile(filepath.Join(dest, "summary.json"), append(b, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "replay of %s (%s) as %s:\n", res.Action, res.Label, res.As)
	for _, s := range res.Steps {
		state := fmt.Sprintf("%d (recorded %d)", s.Status, s.Recorded)
		switch {
		case s.Skipped != "":
			state = "skipped: " + s.Skipped
		case s.Error == "dry run":
			state = "not sent (dry run)"
		case s.Error != "":
			state = "error: " + s.Error
		case s.Blocked != "":
			state = fmt.Sprintf("%d BLOCKED: %s", s.Status, s.Blocked)
		}
		fmt.Fprintf(os.Stderr, "  %-12s #%-4d %-7s %-50s %s", s.Purpose, s.ID, s.Method, s.Endpoint, state)
		if len(s.Refreshed) > 0 {
			fmt.Fprintf(os.Stderr, " fresh %v", s.Refreshed)
		}
		if len(s.Stale) > 0 {
			fmt.Fprintf(os.Stderr, " STALE %v", s.Stale)
		}
		fmt.Fprintln(os.Stderr)
	}
	if res.Stopped != "" {
		fmt.Fprintln(os.Stderr, "stopped:", res.Stopped)
	}
	printBlockedHosts(res.HostsBlocked)
	fmt.Fprintln(os.Stderr, "wrote", dest)
	return nil
}

func urlOf(raw string) (*url.URL, error) { return url.Parse(raw) }
