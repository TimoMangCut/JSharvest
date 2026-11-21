package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/browser"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/session"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRound41SignalHelperHelperProcess(t *testing.T) {
	mode := os.Getenv("JSHARVEST_TEST_SIGNAL_HELPER")
	if mode == "" {
		return
	}
	profDir := os.Getenv("JSHARVEST_TEST_PROF_DIR")
	upDir := os.Getenv("JSHARVEST_TEST_UPLOAD_DIR")
	unregProf := browser.RegisterTempDir(profDir)
	unregUp := browser.RegisterTempDir(upDir)

	ctx, stop := notifyCleanupSignals()
	defer stop()
	fmt.Println("READY")
	<-ctx.Done()
	fmt.Println("CANCELED")

	switch mode {
	case "two":
		time.Sleep(250 * time.Millisecond)
		unregProf()
		unregUp()
		_ = os.RemoveAll(profDir)
		_ = os.RemoveAll(upDir)
		fmt.Println("CLEAN_DONE")
		os.Exit(0)
	case "three":
		select {}
	}
}

func TestRound41SecondSignalWarnsAndCleansUp(t *testing.T) {
	// 1. Deterministic state machine check via handleCleanupSignals.
	{
		tmp := t.TempDir()
		pDir := filepath.Join(tmp, "jsharvest-profile-unit")
		uDir := filepath.Join(tmp, "jsharvest-upload-unit")
		if err := os.MkdirAll(pDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(uDir, 0o700); err != nil {
			t.Fatal(err)
		}
		_ = browser.RegisterTempDir(pDir)
		_ = browser.RegisterTempDir(uDir)

		sigs := make(chan os.Signal, 3)
		var stderr syncBuf
		exited := make(chan int, 1)
		ctx, stop := handleCleanupSignals(context.Background(), sigs, &stderr, func(code int) {
			exited <- code
		})
		defer stop()

		sigs <- os.Interrupt
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("first signal did not cancel context")
		}
		if stderr.String() != "" {
			t.Fatalf("first signal printed unexpected warning: %q", stderr.String())
		}

		sigs <- os.Interrupt
		deadline := time.Now().Add(2 * time.Second)
		for !strings.Contains(stderr.String(), "cleaning up; press Ctrl-C again to force exit (held requests in -attach may be sent)") {
			if time.Now().After(deadline) {
				t.Fatalf("second signal did not print cleanup warning; got %q", stderr.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
		select {
		case code := <-exited:
			t.Fatalf("second signal unexpectedly forced exit %d", code)
		default:
		}
		if _, err := os.Stat(pDir); err != nil {
			t.Fatalf("temp dir removed before normal cleanup or third signal: %v", err)
		}

		sigs <- os.Interrupt
		select {
		case code := <-exited:
			if code != 130 {
				t.Fatalf("third signal exit code = %d, want 130", code)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("third signal did not trigger forceExit")
		}
		for _, d := range []string{pDir, uDir} {
			if _, err := os.Stat(d); !os.IsNotExist(err) {
				t.Fatalf("expected %s cleaned up on third signal, stat err=%v", d, err)
			}
		}
	}

	// 2. Real OS SIGINT delivery: 2 signals warn and let cleanup complete; 3 signals force exit 130 and clean temp dirs.
	runSub := func(mode string, sigCount int) (int, string, string, string, string) {
		t.Helper()
		tmp := t.TempDir()
		pDir := filepath.Join(tmp, "jsharvest-profile-sub")
		uDir := filepath.Join(tmp, "jsharvest-upload-sub")
		if err := os.MkdirAll(pDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(uDir, 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestRound41SignalHelperHelperProcess$")
		cmd.Env = append(os.Environ(),
			"JSHARVEST_TEST_SIGNAL_HELPER="+mode,
			"JSHARVEST_TEST_PROF_DIR="+pDir,
			"JSHARVEST_TEST_UPLOAD_DIR="+uDir,
		)
		var outBuf, errBuf syncBuf
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waitFor := func(sub string) {
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(outBuf.String(), sub) && !strings.Contains(errBuf.String(), sub) {
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					t.Fatalf("timed out waiting for %q (stdout=%q stderr=%q)", sub, outBuf.String(), errBuf.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		waitFor("READY")
		_ = cmd.Process.Signal(syscall.SIGINT)
		waitFor("CANCELED")
		_ = cmd.Process.Signal(syscall.SIGINT)
		waitFor("cleaning up; press Ctrl-C again to force exit")
		if sigCount >= 3 {
			_ = cmd.Process.Signal(syscall.SIGINT)
		}
		err := cmd.Wait()
		code := 0
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else {
				t.Fatalf("wait: %v", err)
			}
		}
		return code, outBuf.String(), errBuf.String(), pDir, uDir
	}

	code2, out2, err2, p2, u2 := runSub("two", 2)
	if code2 != 0 || !strings.Contains(out2, "CLEAN_DONE") {
		t.Fatalf("2x SIGINT aborted cleanup: code=%d stdout=%q stderr=%q", code2, out2, err2)
	}
	if !strings.Contains(err2, "cleaning up; press Ctrl-C again to force exit (held requests in -attach may be sent)") {
		t.Fatalf("2x SIGINT missing warning: %q", err2)
	}
	for _, d := range []string{p2, u2} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("2x SIGINT left temp dir %s", d)
		}
	}

	code3, _, err3, p3, u3 := runSub("three", 3)
	if code3 != 130 {
		t.Fatalf("3x SIGINT exit code = %d, want 130 (stderr=%q)", code3, err3)
	}
	for _, d := range []string{p3, u3} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("3x SIGINT left temp dir %s", d)
		}
	}
}

func TestRound41ArchiveUAFlag(t *testing.T) {
	cfg, err := parseArchiveFlags([]string{"-o", t.TempDir(), "-target", "app.example", "-archive-ua", "CustomUA/1.0"})
	if err != nil {
		t.Fatalf("parseArchiveFlags: %v", err)
	}
	if cfg.archiveUA != "CustomUA/1.0" {
		t.Fatalf("archiveUA = %q, want CustomUA/1.0", cfg.archiveUA)
	}
	env, err := newArchiveEnv(cfg)
	if err != nil {
		t.Fatalf("newArchiveEnv: %v", err)
	}
	defer env.Close()
	if env.opts.Wayback.Client.UA != "CustomUA/1.0" || env.opts.Wayback.IndexClient.UA != "CustomUA/1.0" ||
		env.opts.OTX.Client.UA != "CustomUA/1.0" || env.opts.CC.Client.UA != "CustomUA/1.0" || env.opts.URLScan.Client.UA != "CustomUA/1.0" {
		t.Fatalf("custom -archive-ua not applied to all archive clients")
	}
}

func TestRound41CrawlLocksProfile(t *testing.T) {
	// 1. Anonymous crawl must NOT create directories under -profiles.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()

	anonOut := t.TempDir()
	anonProfiles := filepath.Join(t.TempDir(), "profiles")
	err := runCrawl([]string{
		"-u", srv.URL,
		"-o", anonOut,
		"-profiles", anonProfiles,
		"-engine", "http",
		"-depth", "0",
		"-probe=false",
		"-archive=false",
		"-archive-fallback=false",
	})
	if err != nil {
		t.Fatalf("anonymous crawl failed: %v", err)
	}
	if _, statErr := os.Stat(anonProfiles); !os.IsNotExist(statErr) {
		entries, _ := os.ReadDir(anonProfiles)
		t.Fatalf("anonymous crawl created unexpected entries in -profiles: %v (err=%v)", entries, statErr)
	}

	// 2. When login holds the profile lock with a half-written jsharvest-session.json,
	// both -u and -urls fail at lockDirs ("in use") BEFORE loadLogin reads corrupt JSON.
	profilesRoot := t.TempDir()
	uApp, _ := parseTarget("https://app.example/")
	hostDir := scope.TargetDir(uApp)
	profDir := filepath.Join(profilesRoot, hostDir, "user")
	if err := os.MkdirAll(profDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profDir, "jsharvest-session.json"), []byte(`{"saved":`), 0o600); err != nil {
		t.Fatal(err)
	}
	urlsPath := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(urlsPath, []byte("https://app.example/a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unlockLogin, err := lockDirs("login", 0, profDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := runCrawl([]string{"-u", "https://app.example/a", "-role", "user", "-o", t.TempDir(), "-profiles", profilesRoot}); err == nil || !strings.Contains(err.Error(), "in use") {
		unlockLogin()
		t.Fatalf("crawl -u did not lock profile before loadLogin: %v", err)
	}
	if err := runCrawl([]string{"-urls", urlsPath, "-role", "user", "-o", t.TempDir(), "-profiles", profilesRoot}); err == nil || !strings.Contains(err.Error(), "in use") {
		unlockLogin()
		t.Fatalf("crawl -urls did not lock profile before loadLogin: %v", err)
	}
	unlockLogin()

	// 3. While crawl holds profile P (for both -u and -urls), login -profile P reports "in use".
	snap := &session.Snapshot{Saved: time.Now().UTC()}
	if err := snap.Save(profDir); err != nil {
		t.Fatal(err)
	}
	fakeChrome := filepath.Join(t.TempDir(), "fake-chrome.sh")
	startedFile := filepath.Join(t.TempDir(), "started")
	releaseFile := filepath.Join(t.TempDir(), "release")
	script := fmt.Sprintf("#!/bin/sh\necho ok >%q\nfor _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -f %q ] && exit 1; sleep 0.05; done\nexit 1\n", startedFile, releaseFile)
	if err := os.WriteFile(fakeChrome, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, modeArgs := range [][]string{
		{"-u", "https://app.example/a"},
		{"-urls", urlsPath},
	} {
		_ = os.Remove(startedFile)
		_ = os.Remove(releaseFile)
		done := make(chan error, 1)
		args := append([]string{}, modeArgs...)
		args = append(args, "-role", "user", "-o", t.TempDir(), "-profiles", profilesRoot, "-engine", "cdp", "-chrome", fakeChrome)
		go func() {
			done <- runCrawl(args)
		}()
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(startedFile); err == nil {
				break
			}
			if time.Now().After(deadline) {
				_ = os.WriteFile(releaseFile, []byte("1"), 0o600)
				t.Fatalf("crawl (%v) did not reach browser launch: err=%v", modeArgs, <-done)
			}
			time.Sleep(20 * time.Millisecond)
		}
		lerr := runLogin([]string{"-u", "https://app.example/login", "-role", "user", "-profile", profDir})
		_ = os.WriteFile(releaseFile, []byte("1"), 0o600)
		<-done
		if lerr == nil || !strings.Contains(lerr.Error(), "in use") {
			t.Fatalf("login during crawl (%v) got %v, want 'in use'", modeArgs, lerr)
		}
	}
}
