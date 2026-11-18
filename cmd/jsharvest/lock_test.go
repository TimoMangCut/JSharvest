package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/store"
)

// The test binary is its own child process: JSH_CHILD picks what it does
// instead of running the tests.
func TestMain(m *testing.M) {
	switch os.Getenv("JSH_CHILD") {
	case "main": // the real CLI: JSH_ARGS separated by \x1f
		os.Args = append([]string{"jsharvest"}, strings.Split(os.Getenv("JSH_ARGS"), "\x1f")...)
		main()
		os.Exit(0)
	case "hold": // take the lock of a directory, say so, keep it until killed
		unlock, err := lockDirs("crawl", 0, os.Getenv("JSH_DIR"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = unlock
		fmt.Println("ready")
		time.Sleep(time.Hour)
	case "store": // what a writing command does to a store, with barriers
		os.Exit(storeChild())
	}
	os.Exit(m.Run())
}

// storeChild: lock (unless JSH_NOLOCK), open the store, add one script, wait
// (up to 600 ms) for the other child to have done the same, then flush; the
// second child flushes only after the first one has.
func storeChild() int {
	dir, name, sync := os.Getenv("JSH_DIR"), os.Getenv("JSH_NAME"), os.Getenv("JSH_SYNC")
	if os.Getenv("JSH_NOLOCK") == "" {
		wait, _ := time.ParseDuration(os.Getenv("JSH_WAIT"))
		unlock, err := lockDirs("crawl", wait, dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer unlock()
	}
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// Both have loaded the (empty) index before either adds: loading after
	// the other's Add would find its script file and index it.
	os.WriteFile(filepath.Join(sync, "loaded-"+name), nil, 0o600)
	other := map[string]string{"a": "b", "b": "a"}[name]
	barrier := 600 * time.Millisecond
	if os.Getenv("JSH_NOLOCK") != "" {
		barrier = 5 * time.Second // the other process is slow to start under -race
	}
	waitFor(filepath.Join(sync, "loaded-"+other), barrier)
	if _, err := st.Add(store.Record{Body: []byte("var " + name + "=1;"), URL: "https://h.test/" + name + ".js", Kind: "file", Via: "network"}); err != nil {
		return 2
	}
	os.WriteFile(filepath.Join(sync, "opened-"+name), nil, 0o600)
	waitFor(filepath.Join(sync, "opened-"+other), barrier)
	if name == "b" {
		waitFor(filepath.Join(sync, "flushed-a"), 3*time.Second)
	}
	if err := st.Flush(); err != nil {
		return 2
	}
	os.WriteFile(filepath.Join(sync, "flushed-"+name), nil, 0o600)
	return 0
}

func waitFor(path string, d time.Duration) {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
	}
}

func child(mode string, env ...string) *exec.Cmd {
	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(), append([]string{"JSH_CHILD=" + mode}, env...)...)
	return c
}

func cli(args ...string) *exec.Cmd {
	return child("main", "JSH_ARGS="+strings.Join(args, "\x1f"))
}

func indexLines(t *testing.T, dir string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(b, []byte("\n"))
}

func runStore(t *testing.T, dir, sync string, nolock bool, wait string) (a, b *exec.Cmd, ob, oa *bytes.Buffer) {
	t.Helper()
	mk := func(name string) (*exec.Cmd, *bytes.Buffer) {
		env := []string{"JSH_DIR=" + dir, "JSH_NAME=" + name, "JSH_SYNC=" + sync, "JSH_WAIT=" + wait}
		if nolock {
			env = append(env, "JSH_NOLOCK=1")
		}
		c := child("store", env...)
		var buf bytes.Buffer
		c.Stderr = &buf
		return c, &buf
	}
	a, oa = mk("a")
	b, ob = mk("b")
	return
}

// The hazard, without the lock: both processes load an empty index, each adds
// a script, and the second flush replaces the first one's index.
func TestTwoProcessesWithoutLockLoseAnEntry(t *testing.T) {
	dir, sync := filepath.Join(t.TempDir(), "h", "anon"), t.TempDir()
	a, b, _, _ := runStore(t, dir, sync, true, "")
	a.Start()
	b.Start()
	if err := a.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := b.Wait(); err != nil {
		t.Fatal(err)
	}
	if n := indexLines(t, dir); n != 1 {
		t.Fatalf("index.jsonl has %d entries; the hazard is that 2 scripts were added and 1 is left", n)
	}
	t.Log("without the lock: two scripts added, index.jsonl has 1 entry (an update lost, silently)")
}

// Open removes the .tmp-* file of an interrupted write: another process's
// write in progress looks the same.
func TestOpenRemovesAForeignTempFile(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "js"), 0o700)
	tmp := filepath.Join(dir, "js", ".tmp-123")
	os.WriteFile(tmp, []byte("half"), 0o600)
	if _, err := store.Open(dir, store.Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); err == nil {
		t.Fatal("expected Open to remove the temp file (the hazard the lock guards against)")
	}
}

func TestSecondWriterFailsClearly(t *testing.T) {
	dir, sync := filepath.Join(t.TempDir(), "h", "anon"), t.TempDir()
	a, b, ob, _ := runStore(t, dir, sync, false, "")
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(filepath.Join(sync, "opened-a"), 10*time.Second)
	err := b.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Fatalf("second writer: want exit 1, got %v", err)
	}
	msg := ob.String()
	if !strings.Contains(msg, "is in use by pid") || !strings.Contains(msg, "(crawl)") || !strings.Contains(msg, dir) {
		t.Fatalf("message: %q", msg)
	}
	if err := a.Wait(); err != nil {
		t.Fatal(err)
	}
	if n := indexLines(t, dir); n != 1 {
		t.Fatalf("index has %d entries, want 1 (the first writer's)", n)
	}
	t.Log("message:", strings.TrimSpace(msg))
}

func TestWaitLockWaitsThenRuns(t *testing.T) {
	dir, sync := filepath.Join(t.TempDir(), "h", "anon"), t.TempDir()
	a, b, ob, _ := runStore(t, dir, sync, false, "10s")
	a.Start()
	waitFor(filepath.Join(sync, "opened-a"), 10*time.Second)
	if err := b.Run(); err != nil {
		t.Fatalf("b: %v: %s", err, ob)
	}
	if err := a.Wait(); err != nil {
		t.Fatal(err)
	}
	if n := indexLines(t, dir); n != 2 {
		t.Fatalf("index has %d entries, want 2", n)
	}
}

func TestLockDropsWhenHolderIsKilled(t *testing.T) {
	out := t.TempDir()
	dir := filepath.Join(out, "h.test", "anon")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "index.jsonl"), nil, 0o600)

	h := child("hold", "JSH_DIR="+dir)
	pipe, _ := h.StdoutPipe()
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	pipe.Read(buf)

	// The real endpoints command refuses, and says who.
	var stderr bytes.Buffer
	c := cli("endpoints", "-o", out, "-target", "h.test")
	c.Stderr = &stderr
	err := c.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || !strings.Contains(stderr.String(), "is in use by pid") {
		t.Fatalf("endpoints while held: %v %q", err, stderr.String())
	}
	if info, err := os.Stat(filepath.Join(dir, ".jsharvest.lock")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v %v", info, err)
	}

	// Read-only commands are not held up by it.
	for _, args := range [][]string{{"export", "-o", out, "-target", "h.test"}, {"diff", "-o", out, "-target", "h.test"}} {
		var se bytes.Buffer
		c := cli(args...)
		c.Stderr = &se
		c.Run()
		if strings.Contains(se.String(), "in use") {
			t.Fatalf("%s took the lock: %s", args[0], se.String())
		}
	}

	// -wait-lock waits until the holder is gone.
	var ws bytes.Buffer
	w := cli("endpoints", "-o", out, "-target", "h.test", "-wait-lock", "20s")
	w.Stderr = &ws
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	h.Process.Signal(syscall.SIGKILL)
	h.Wait()
	if err := w.Wait(); err != nil {
		t.Fatalf("waiting endpoints: %v: %s", err, ws.String())
	}
	// And after the kill, a plain run goes through (nothing to clean up).
	if err := cli("endpoints", "-o", out, "-target", "h.test").Run(); err != nil {
		t.Fatalf("after kill: %v", err)
	}
}
