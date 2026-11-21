package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/monitor"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// errChanges is monitor's exit 5: changes at -fail-on or above.
var errChanges = errors.New("changes at or above -fail-on")

// runMonitor compares a target's crawls since the last snapshot with its
// baseline (see docs/gd5-monitor-design.md). It reads the output; the only
// request it sends is the webhook's.
func runMonitor(args []string) error {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	target := fs.String("target", "", "the target's host, as its output directory is named")
	keep := fs.Int("keep", 30, "snapshots to keep (the baselines are always kept)")
	failOn := fs.String("fail-on", "", "exit 5 when there are changes of this severity or above: high, medium, low")
	webhookFile := fs.String("webhook-file", "", "a file holding the webhook's URL (or env JSHARVEST_WEBHOOK; never on the command line: it is a secret)")
	proxyFlag := fs.String("proxy", "", "send the webhook through this proxy (default JSHARVEST_PROXY, HTTPS_PROXY, HTTP_PROXY; none: no proxy)")
	webhookMin := fs.String("webhook-min", "medium", "send the webhook for changes of this severity or above")
	webhookDetail := fs.String("webhook-detail", "counts", "counts, or keys: the endpoints too (they tell a chat the target's paths)")
	dryRun := fs.Bool("dry-run", false, "compare and print; write nothing, send nothing")
	waitLock := waitLockFlag(fs)
	fs.Parse(args)
	if *target == "" {
		return errors.New("monitor: -target is required")
	}
	root := filepath.Join(*out, targetDir(*target))
	monDir := filepath.Join(root, "monitor")
	if !*dryRun {
		unlock, err := lockDirs("monitor", *waitLock, monDir)
		if err != nil {
			return err
		}
		defer unlock()
	}
	in, err := scope.New(hostOnly(*target), results.ScopeMode(root))
	if err != nil {
		return err
	}
	hook := os.Getenv("JSHARVEST_WEBHOOK")
	if *webhookFile != "" {
		b, err := os.ReadFile(*webhookFile)
		if err != nil {
			return fmt.Errorf("-webhook-file: %w", err)
		}
		hook = strings.TrimSpace(string(b))
	}
	ctx := context.Background()
	var hookProxy *url.URL
	if hook != "" && !*dryRun {
		pv, err := resolveProxy(*proxyFlag)
		if err != nil {
			return err
		}
		if pv != "" {
			if hookProxy, err = url.Parse(pv); err != nil {
				return fmt.Errorf("-proxy: %w", err)
			}
		}
	}
	if hook != "" && !*dryRun {
		// A payload the webhook did not take last time goes first; keep the
		// file on disk until delivery succeeds so a crash never drops it.
		if p := monitor.ReadPending(monDir); p != nil {
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := monitor.SendWith(sctx, hook, p, hookProxy)
			cancel()
			if err != nil {
				fmt.Fprintln(os.Stderr, "webhook (the last run's):", err)
			} else {
				monitor.ClearPending(monDir)
			}
		}
	}
	res, err := monitor.Run(monitor.Options{Root: root, InScope: in, Keep: *keep, DryRun: *dryRun})
	if err != nil {
		return err
	}
	if res.Nothing {
		fmt.Fprintln(os.Stderr, "monitor: no new crawl since the last snapshot")
		return nil
	}
	if !*dryRun {
		if err := res.Write(root, *target); err != nil {
			return err
		}
	}
	c := monitor.Counts(res.Changes)
	fprintClean(os.Stderr, "monitor %s, snapshot %s: %d high, %d medium, %d low, %d info\n", *target, res.Snapshot.ID, c[monitor.High], c[monitor.Medium], c[monitor.Low], c[monitor.Info])
	for _, r := range res.Baseline {
		fprintClean(os.Stderr, "  %s: first runs, the baseline\n", r)
	}
	for _, n := range res.Notes {
		fprintlnClean(os.Stderr, "note:", n)
	}
	for _, ch := range res.Changes {
		if ch.Severity != monitor.Info {
			fprintlnClean(os.Stderr, " ", ch)
		}
	}
	report := filepath.Join(root, "monitor", "latest.md")
	if hook != "" && !*dryRun {
		p := monitor.NewPayload(res, *target, report, *webhookMin, *webhookDetail == "keys")
		if len(p.Counts) > 0 {
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := monitor.SendWith(sctx, hook, p, hookProxy); err != nil {
				fmt.Fprintln(os.Stderr, "webhook:", err, "(kept for the next run)")
				monitor.Pending(filepath.Join(root, "monitor"), p)
			}
			cancel()
		}
	}
	if !*dryRun {
		fmt.Fprintln(os.Stderr, "wrote", report)
	}
	if *failOn != "" {
		for _, ch := range res.Changes {
			if monitor.AtLeast(ch.Severity, *failOn) {
				return errChanges
			}
		}
	}
	return nil
}
