package engine

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/store"
)

// outDir is one output directory (<out>/<host>/<role>) as the runs of one
// process share it: crawl -urls -tabs N runs two URLs of a host at once,
// and two Stores on one index.jsonl would each write the other's out.
type outDir struct {
	st   *store.Store
	refs int
	stop context.CancelFunc // the store's background flush
	// mu is held around writes to the directory's other files that are
	// rewritten whole or appended in several writes: endpoints.jsonl,
	// flows.jsonl, blocked.jsonl, blocked.har, run.json, runs.jsonl.
	mu sync.Mutex
}

var outDirs = struct {
	sync.Mutex
	m map[string]*outDir
}{m: map[string]*outDir{}}

// openOutDir opens the store of dir, or shares the one already open.
// Each call is paired with release.
func openOutDir(dir string, opts store.Options) (*outDir, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	outDirs.Lock()
	defer outDirs.Unlock()
	if d := outDirs.m[abs]; d != nil {
		d.refs++
		return d, nil
	}
	st, err := store.Open(abs, opts)
	if err != nil {
		return nil, err
	}
	if rec, disc := st.Recovered(); rec > 0 || disc > 0 {
		slog.Warn("cleaned up after an interrupted run", "indexed", rec, "removed_damaged", disc)
	}
	ctx, stop := context.WithCancel(context.Background())
	go st.AutoFlush(ctx, 10*time.Second)
	d := &outDir{st: st, refs: 1, stop: stop}
	outDirs.m[abs] = d
	return d, nil
}

// release is the end of one run's use of the directory. The last one
// stops the background flush; the runs flush the index themselves.
func (d *outDir) release() {
	outDirs.Lock()
	defer outDirs.Unlock()
	if d.refs--; d.refs > 0 {
		return
	}
	d.stop()
	for k, v := range outDirs.m {
		if v == d {
			delete(outDirs.m, k)
		}
	}
}

var runIDs = struct {
	sync.Mutex
	issued map[string]bool
}{issued: map[string]bool{}}

// newRunID names a run by its start, to the millisecond; two runs that
// start in the same millisecond (crawl -tabs) get -2, -3… after it.
func newRunID(t time.Time) string {
	base := t.Format("20060102T150405.000Z")
	runIDs.Lock()
	defer runIDs.Unlock()
	id := base
	for n := 2; runIDs.issued[id]; n++ {
		id = base + "-" + strconv.Itoa(n)
	}
	runIDs.issued[id] = true
	return id
}

// writeFileAtomic replaces path whole: a reader never sees half a file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o600)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
