package archive

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// Options configure a run of archive.
type Options struct {
	Dir     string // <out>/<host>/archive
	Root    string // <out>: the crawls' catalogs, under <out>/<host>/<role>
	Host    string
	InScope func(host string) bool
	Sources []string // wayback, otx, commoncrawl
	Since   time.Time
	// ExtraHosts are the target's other hosts the crawls reached (with
	// -scope rdn): OTX and urlscan are asked of each too (MAX-06), at
	// most MaxExtraHosts. The Wayback and Common Crawl list the domain's
	// subdomains already.
	ExtraHosts []string
	// Live checks whether an old script's URL still serves it, through
	// Sender, on LiveHosts only (the hosts the crawls reached, unless
	// named): an old subdomain may point at someone else now.
	Live      bool
	LiveHosts map[string]bool
	Sender    *replay.Sender
	MaxFiles  int
	MaxPages  int // CDX pages to list, at most (0: all)
	// MaxHTML is how many old pages (text/html captures) to read for the
	// scripts they name, the newest capture of each URL, the root first
	// (0: none).
	MaxHTML int
	Vendor  bool // fetch vendor libraries too
	MaxBody int
	Workers int // concurrent listing/fetch workers (0: default 8)
	Wayback *Wayback
	OTX     *OTX
	CC      *CommonCrawl
	URLScan *URLScan
	Log     func(format string, args ...any)
}

// Summary is what a run did; archive.json keeps it with the run's place.
type Summary struct {
	Listed   map[string]int `json:"listed"` // captures listed, by source
	URLs     int            `json:"urls"`
	JS       int            `json:"js_captures"`
	Revisits int            `json:"revisits"`
	Digests  int            `json:"js_contents"`
	Known    int            `json:"already_held"` // by today's crawls: not fetched
	// HeldAfter: a URL listed without a digest whose bytes, once fetched,
	// are a script today's crawls hold.
	HeldAfter int `json:"held_after_fetch,omitempty"`
	Merged    int `json:"merged,omitempty"` // fetched before, under another listing: its archive side merged
	Fetched   int `json:"fetched"`
	WARC      int `json:"from_warc,omitempty"` // fetched from Common Crawl's WARC files
	// Source maps read, the app's own sources they held; build manifests
	// read (MAX-04).
	Maps       int `json:"source_maps,omitempty"`
	MapSources int `json:"map_sources,omitempty"`
	Manifests  int `json:"manifests,omitempty"`
	Alive      int `json:"alive"`
	LiveSame   int `json:"live_same"`
	Mismatch   int `json:"digest_mismatch"`
	NotJS      int `json:"not_script"`
	Failed     int `json:"failed"`
	// Old pages: captures listed, pages read, the scripts they named, their
	// inline code stored; and the chunks the fetched scripts named.
	HTML        int            `json:"html_captures,omitempty"`
	Pages       int            `json:"pages_read,omitempty"`
	PageScripts int            `json:"page_scripts,omitempty"`
	Inline      int            `json:"inline,omitempty"`
	Resolved    int            `json:"resolved,omitempty"`
	NotArchived int            `json:"not_archived,omitempty"` // a script named, not in the Wayback (alive or not)
	Skipped     map[string]int `json:"skipped,omitempty"`
	Credential  []string       `json:"credential_urls,omitempty"` // archived URLs carrying a credential, masked
	Historical  map[string]int `json:"historical,omitempty"`
	Notes       []string       `json:"notes,omitempty"`
}

// stateVersion is what a listing keeps: 3 since HTMLTop replaced html.jsonl.
const stateVersion = 3

// state is archive.json: where the listing stands, so a run resumes.
type state struct {
	Query   string `json:"query"` // the listing's parameters: a resume key fits these only
	Wayback struct {
		Resume    string       `json:"resume,omitempty"`
		NumPages  int          `json:"num_pages,omitempty"`
		PagesDone map[int]bool `json:"pages_done,omitempty"`
		Done      bool         `json:"done"`
	} `json:"wayback"`
	OTX struct {
		Page int  `json:"page"`
		Done bool `json:"done"`
	} `json:"otx"`
	CC struct {
		Collections []string `json:"collections,omitempty"`
		// Next is each collection's next page to list; Listed, the
		// collections done. One that failed is listed on by the next run.
		Next   map[string]int  `json:"next,omitempty"`
		Listed map[string]bool `json:"listed,omitempty"`
		Done   bool            `json:"done"`
	} `json:"commoncrawl"`
	URLScan struct {
		After    string   `json:"after,omitempty"` // the search's cursor
		Searched bool     `json:"searched"`
		Scans    []string `json:"scans,omitempty"` // "<id> <time>" of the target's own pages, to read
		Read     int      `json:"read"`
	} `json:"urlscan"`
	// Extra are the other hosts' listings done, as "<source> <host>".
	Extra   map[string]bool `json:"extra,omitempty"`
	HTMLTop []Capture       `json:"html_top,omitempty"`
	Listed  bool            `json:"listed"`
	Summary Summary         `json:"summary"`
	Updated time.Time       `json:"updated"`
}

type runner struct {
	// mu: the sources list at once; the state, the summary and the files
	// are shared.
	mu       sync.Mutex
	o        Options
	st       state
	urls     *os.File // urls.jsonl
	urlsBuf  *bufio.Writer
	js       *os.File // js.jsonl: the script captures, for the fetch
	jsBuf    *bufio.Writer
	html     *os.File // legacy field kept for unit-test compatibility
	doneFile *os.File
	doneBuf  *bufio.Writer
	lastSave time.Time

	seenURLs  map[[16]byte]struct{}
	htmlPool  map[string]Capture
	htmlWorst Capture
	hasWorst  bool

	// Streaming shard -> memento prefetch state during sharded Wayback listing.
	prefetchCh     chan *group
	prefetchSeen   map[string]bool
	prefetchFam    map[string]int
	prefetchFirst  map[string]time.Time
	prefetchHalted atomic.Bool

	// namedURLs are the scripts old pages and fetched scripts named, filed
	// once.
	namedURLs map[string]bool
	done      map[string]bool
	store     *store.Store
	cred      map[string]bool
	cur       *current
	// partial: the listing stopped at -max-pages, its place kept.
	partial bool
	// lives are the live checks made, by kind and URL: a URL the archive
	// holds in several versions is asked once.
	livesMu       sync.Mutex
	lives         map[string]liveAns
	liveWait      map[string]chan struct{}
	httpsUpgrades map[string]int
	httpPlainOK   map[string]bool
}

func (r *runner) workers() int {
	if r.o.Workers > 0 {
		return r.o.Workers
	}
	return 8
}

func (r *runner) sum(fn func(*Summary)) {
	r.mu.Lock()
	fn(&r.st.Summary)
	r.mu.Unlock()
}

type liveAns struct {
	alive *bool
	body  []byte
	url   string
}

func (r *runner) encodeURLLocked(l *URLLine) {
	if r.urlsBuf != nil {
		_ = json.NewEncoder(r.urlsBuf).Encode(l)
		return
	}
	if r.urls != nil {
		_ = json.NewEncoder(r.urls).Encode(l)
	}
}

func (r *runner) encodeJSLocked(c Capture) {
	if r.jsBuf != nil {
		_ = json.NewEncoder(r.jsBuf).Encode(c)
		return
	}
	if r.js != nil {
		_ = json.NewEncoder(r.js).Encode(c)
	}
}

func (r *runner) flushFiles() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushFilesLocked()
}

func (r *runner) flushFilesLocked() {
	if r.urlsBuf != nil {
		_ = r.urlsBuf.Flush()
	}
	if r.jsBuf != nil {
		_ = r.jsBuf.Flush()
	}
	if r.doneBuf != nil {
		_ = r.doneBuf.Flush()
	}
}

// Run lists the archives, fetches the old scripts, and writes what only
// history calls. It resumes where a run stopped, when the query is the
// same.
func Run(ctx context.Context, o Options) (*Summary, error) {
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	r := &runner{
		o:             o,
		done:          map[string]bool{},
		cred:          map[string]bool{},
		namedURLs:     map[string]bool{},
		seenURLs:      map[[16]byte]struct{}{},
		htmlPool:      map[string]Capture{},
		lives:         map[string]liveAns{},
		liveWait:      map[string]chan struct{}{},
		httpsUpgrades: map[string]int{},
		httpPlainOK:   map[string]bool{},
	}
	wbMode := ""
	if o.Wayback != nil && (o.Wayback.Sharded || o.Wayback.Collapse != "") {
		wbMode = fmt.Sprintf("|wb:%v:%s", o.Wayback.Sharded, o.Wayback.Collapse)
	}
	// stateVersion is in the key: a checkpoint of an older jsharvest is
	// listed again rather than resumed.
	q := sha256.Sum256([]byte(fmt.Sprint(stateVersion, "|", o.Host, "|", o.Sources, "|", o.Since.Format(time.DateOnly), wbMode)))
	query := hex.EncodeToString(q[:8])
	resuming := false
	if b, err := os.ReadFile(filepath.Join(o.Dir, "archive.json")); err == nil && json.Unmarshal(b, &r.st) == nil && r.st.Query == query {
		resuming = true
		o.Log("resuming: the listing %s", map[bool]string{true: "is done", false: "goes on"}[r.st.Listed])
		for _, tc := range r.st.HTMLTop {
			r.htmlPool[tc.URL] = tc
		}
	} else {
		r.st = state{Query: query}
		for _, f := range []string{"urls.jsonl", "js.jsonl", "html.jsonl", "done.log"} {
			os.Remove(filepath.Join(o.Dir, f))
		}
	}
	if r.st.Summary.Listed == nil {
		r.st.Summary.Listed = map[string]int{}
	}
	if r.st.Summary.Skipped == nil {
		r.st.Summary.Skipped = map[string]int{}
	}
	if r.st.Summary.Historical == nil {
		r.st.Summary.Historical = map[string]int{}
	}
	if r.st.CC.Next == nil {
		r.st.CC.Next = map[string]int{}
	}
	if r.st.CC.Listed == nil {
		r.st.CC.Listed = map[string]bool{}
	}
	if r.st.Extra == nil {
		r.st.Extra = map[string]bool{}
	}
	if r.st.Wayback.PagesDone == nil {
		r.st.Wayback.PagesDone = map[int]bool{}
	}
	var err error
	if resuming && !r.st.Listed {
		seedSeenURLs(filepath.Join(o.Dir, "urls.jsonl"), r.seenURLs)
	}
	if r.urls, err = appendFile(filepath.Join(o.Dir, "urls.jsonl")); err != nil {
		return nil, err
	}
	r.urlsBuf = bufio.NewWriterSize(r.urls, 4<<20)
	defer func() {
		r.flushFiles()
		r.urls.Close()
	}()
	if r.js, err = appendFile(filepath.Join(o.Dir, "js.jsonl")); err != nil {
		return nil, err
	}
	r.jsBuf = bufio.NewWriterSize(r.js, 1<<20)
	defer func() {
		r.flushFiles()
		r.js.Close()
	}()
	defer func() {
		r.mu.Lock()
		if r.doneBuf != nil {
			_ = r.doneBuf.Flush()
		}
		if r.doneFile != nil {
			_ = r.doneFile.Close()
			r.doneFile = nil
		}
		r.mu.Unlock()
	}()
	r.loadDone()
	for _, c := range r.st.Summary.Credential {
		r.cred[c] = true
	}

	if r.store, err = store.Open(o.Dir, store.Options{MaxBody: o.MaxBody}); err != nil {
		return nil, err
	}
	r.cur = loadCurrent(o.Root, o.InScope)

	if !r.st.Listed {
		err := r.list(ctx)
		r.flushFiles()
		r.mu.Lock()
		if len(r.seenURLs) > 0 {
			r.st.Summary.URLs = len(r.seenURLs)
		} else {
			r.st.Summary.URLs = distinctURLs(filepath.Join(o.Dir, "urls.jsonl"))
		}
		r.mu.Unlock()
		_ = r.store.Flush()
		if err != nil {
			r.save()
			return &r.st.Summary, err
		}
		r.st.Listed = !r.partial
		r.save()
	}
	// Release the listing URL dedup map once listing is done to free RAM for fetch/AST.
	r.seenURLs = nil
	if len(r.cur.roles) == 0 {
		r.note("no crawl of the target to compare with: every endpoint of the old scripts will read as historical; crawl the target first")
	}

	err = r.pages(ctx)
	if err == nil {
		err = r.fetch(ctx)
	}
	if ferr := r.store.Flush(); err == nil {
		err = ferr
	}
	if err == nil {
		err = r.history(ctx)
	}
	r.save()
	return &r.st.Summary, err
}

func (r *runner) note(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.noteLocked(s)
}

func (r *runner) noteLocked(s string) {
	if !slices.Contains(r.st.Summary.Notes, s) {
		r.st.Summary.Notes = append(r.st.Summary.Notes, s)
	}
}

// history writes the old scripts' catalog, and historical.jsonl: what they
// call that no crawl of the target has.
func (r *runner) history(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scripts, err := endpoints.AnalyzeSlim(r.o.Dir, 0)
	if err != nil {
		return err
	}
	if r.store.Len() > 1000 {
		endpoints.ClearResultMemCache()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d := results.Open(r.o.Dir)
	if err := d.Refresh(); err != nil {
		return err
	}
	eps := endpoints.Assemble(r.o.Dir, scripts, endpoints.Requests(d), r.o.InScope)
	if err := endpoints.Write(r.o.Dir, eps); err != nil {
		return err
	}
	// Old code's client headers and buckets: a secret rotated out of
	// today's bundle may still work.
	if _, err := endpoints.SaveIntelFromScripts(r.o.Dir, scripts, r.o.InScope, nil); err != nil {
		return err
	}
	scripts = nil
	if r.store.Len() > 1000 {
		endpoints.ClearMemCache()
	}
	lines, _, err := classifyCtx(ctx, eps, r.cur, r.store.Entry)
	if err != nil {
		return err
	}
	s := &r.st.Summary
	s.Historical = map[string]int{"in_current_code": 0}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	for _, l := range lines {
		enc.Encode(l)
		s.Historical[l.Class]++
	}
	tmp := filepath.Join(r.o.Dir, "historical.jsonl.tmp")
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(r.o.Dir, "historical.jsonl"))
}

func appendFile(p string) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return f, f.Chmod(0o600)
}

func (r *runner) save() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushFilesLocked()
	r.saveLocked()
}

func (r *runner) saveMaybeLocked() {
	if time.Since(r.lastSave) < 2*time.Second {
		return
	}
	r.flushFilesLocked()
	r.saveLocked()
}

func (r *runner) saveLocked() {
	if r.o.Dir == "" {
		return
	}
	r.st.HTMLTop = r.snapshotHTMLTopLocked()
	r.st.Updated = time.Now().UTC()
	r.lastSave = r.st.Updated
	b, _ := json.MarshalIndent(r.st, "", " ")
	tmp := filepath.Join(r.o.Dir, "archive.json.tmp")
	if os.WriteFile(tmp, append(b, '\n'), 0o600) == nil {
		os.Rename(tmp, filepath.Join(r.o.Dir, "archive.json"))
	}
}
