// Package lock is the lock between jsharvest commands that write the same
// directory (an output <out>/<host>/<role>, or a login's profile): two of
// them at once lose index.jsonl updates (each flush rewrites the file) and
// the one's startup recovery removes the other's .tmp-* files.
//
// It is an flock(2) on <dir>/.jsharvest.lock. The kernel drops it when the
// process dies, so nothing needs cleaning up; the pid and command written in
// the file are only for the message of the one that waits.
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// File is the lock file's name in a locked directory.
const File = ".jsharvest.lock"

// BusyError says who holds a directory.
type BusyError struct {
	Dir string
	PID int    // 0: unknown
	Cmd string // "" : unknown
}

func (e *BusyError) Error() string {
	who := "another jsharvest process"
	if e.PID > 0 {
		who = fmt.Sprintf("pid %d", e.PID)
		if e.Cmd != "" {
			who += " (" + e.Cmd + ")"
		}
	}
	return fmt.Sprintf("%s is in use by %s: wait (-wait-lock), or use another -o", e.Dir, who)
}

// Lock is the directories held; Release lets them go.
type Lock struct{ files []*os.File }

// Release drops the locks. The lock files stay (a file that is never
// deleted cannot be locked twice through two inodes).
func (l *Lock) Release() {
	if l == nil {
		return
	}
	for _, f := range l.files {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}
	l.files = nil
}

const poll = 100 * time.Millisecond

// Acquire locks every dir, in sorted order (two commands that want the same
// directories cannot wait for each other), creating a directory that is not
// there yet (0700). With wait 0 a held directory is an immediate *BusyError;
// otherwise it is waited for, up to wait. cmd is the command's name, for the
// message. On failure nothing stays locked.
func Acquire(cmd string, wait time.Duration, dirs ...string) (*Lock, error) {
	seen := map[string]bool{}
	var list []string
	for _, d := range dirs {
		d = filepath.Clean(d)
		if !seen[d] {
			seen[d] = true
			list = append(list, d)
		}
	}
	sort.Strings(list)
	deadline := time.Now().Add(wait)
	l := &Lock{}
	for _, d := range list {
		f, err := lockOne(cmd, d, deadline)
		if err != nil {
			l.Release()
			return nil, err
		}
		l.files = append(l.files, f)
	}
	return l, nil
}

func lockOne(cmd, dir string, deadline time.Time) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, File), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", dir, err)
		}
		if !time.Now().Before(deadline) {
			b := &BusyError{Dir: dir}
			b.PID, b.Cmd = holder(f)
			f.Close()
			return nil, b
		}
		time.Sleep(poll)
	}
	f.Chmod(0o600)
	f.Truncate(0)
	fmt.Fprintf(f, "%d %s\n", os.Getpid(), cmd)
	return f, nil
}

func holder(f *os.File) (int, string) {
	b := make([]byte, 256)
	n, _ := f.ReadAt(b, 0)
	pid, cmd, _ := strings.Cut(strings.TrimSpace(string(b[:n])), " ")
	p, _ := strconv.Atoi(pid)
	return p, cmd
}
