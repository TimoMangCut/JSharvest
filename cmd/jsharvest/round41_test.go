package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/browser"
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
