package main

import (
	"errors"
	"flag"
	"testing"
)

// B1: crawl parses archive's flags in its own process: a bad one is an
// error, never an exit, and the stage flags are gone from the CLI.
func TestRound371ArchiveFlagsNeverExit(t *testing.T) {
	if _, err := parseArchiveFlags([]string{"-target", "example.test", "-no-such-flag"}); err == nil {
		t.Fatal("an unknown flag was accepted")
	}
	for _, internal := range []string{"-list-only", "-stage2"} {
		if _, err := parseArchiveFlags([]string{"-target", "example.test", internal}); err == nil {
			t.Errorf("%s is still a flag of jsharvest archive", internal)
		}
	}
	if _, err := parseArchiveFlags([]string{"-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v, want flag.ErrHelp", err)
	}
	if _, err := parseArchiveFlags([]string{"-concurrency", "0", "-target", "example.test"}); err == nil {
		t.Error("-concurrency 0 accepted")
	}
}

// B2: an env holds the archive lock for its whole life (both stages of a
// crawl) and gives it back on Close, so the next target, or another
// jsharvest archive, gets it.
func TestRound371ArchiveEnvHoldsLockUntilClose(t *testing.T) {
	out := t.TempDir()
	cfg, err := parseArchiveFlags([]string{"-o", out, "-target", "example.test", "-proxy", "none"})
	if err != nil {
		t.Fatal(err)
	}
	e1, err := newArchiveEnv(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e2, err := newArchiveEnv(cfg); err == nil {
		e2.Close()
		t.Fatal("a second env got the lock while the first was open")
	}
	e1.Close()
	e2, err := newArchiveEnv(cfg)
	if err != nil {
		t.Fatalf("lock not released by Close: %v", err)
	}
	e2.Close()
	e2.Close() // closing twice is harmless
	if e1.Stage1Ran() {
		t.Error("a fresh env says stage 1 ran")
	}
}
