package archive

import (
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
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/replay"
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

// stateVersion is what a listing keeps: 2 since the old pages (html.jsonl).
const stateVersion = 2

// state is archive.json: where the listing stands, so a run resumes.
type state struct {
	Query   string `json:"query"` // the listing's parameters: a resume key fits these only
	Wayback struct {
		Resume string `json:"resume,omitempty"`
		Done   bool   `json:"done"`
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
	Listed  bool            `json:"listed"`
	Summary Summary         `json:"summary"`
	Updated time.Time       `json:"updated"`
}

type runner struct {
	// mu: the sources list at once; the state, the summary and the files
	// are shared.
	mu   sync.Mutex
	o    Options
	st   state
	urls *os.File // urls.jsonl
	js   *os.File // js.jsonl: the script captures, for the fetch
	html *os.File // html.jsonl: the page captures, for pages
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
	livesMu sync.Mutex
	lives   map[string]liveAns
}

type liveAns struct {
	alive *bool
	body  []byte
	url   string
}

// Run lists the archives, fetches the old scripts, and writes what only
// history calls. It resumes where a run stopped, when the query is the
// same.
func Run(ctx context.Context, o Options) (*Summary, error) {
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	r := &runner{o: o, done: map[string]bool{}, cred: map[string]bool{}, namedURLs: map[string]bool{}, lives: map[string]liveAns{}}
	// stateVersion is in the key: a checkpoint of an older jsharvest, whose
	// listing kept less (before 2: no html.jsonl, so no old page read), is
	// listed again rather than resumed.
	q := sha256.Sum256([]byte(fmt.Sprint(stateVersion, "|", o.Host, "|", o.Sources, "|", o.Since.Format(time.DateOnly))))
	query := hex.EncodeToString(q[:8])
	if b, err := os.ReadFile(filepath.Join(o.Dir, "archive.json")); err == nil && json.Unmarshal(b, &r.st) == nil && r.st.Query == query {
		o.Log("resuming: the listing %s", map[bool]string{true: "is done", false: "goes on"}[r.st.Listed])
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
	var err error
	if r.urls, err = appendFile(filepath.Join(o.Dir, "urls.jsonl")); err != nil {
		return nil, err
	}
	defer r.urls.Close()
	if r.js, err = appendFile(filepath.Join(o.Dir, "js.jsonl")); err != nil {
		return nil, err
	}
	defer r.js.Close()
	if r.html, err = appendFile(filepath.Join(o.Dir, "html.jsonl")); err != nil {
		return nil, err
	}
	defer r.html.Close()
	r.loadDone()
	for _, c := range r.st.Summary.Credential {
		r.cred[c] = true
	}

	if !r.st.Listed {
		err := r.list(ctx)
		r.st.Summary.URLs = distinctURLs(filepath.Join(o.Dir, "urls.jsonl"))
		if err != nil {
			r.save()
			return &r.st.Summary, err
		}
		r.st.Listed = !r.partial
		r.save()
	}
	if r.store, err = store.Open(o.Dir, store.Options{MaxBody: o.MaxBody}); err != nil {
		return nil, err
	}
	r.cur = loadCurrent(o.Root, o.InScope)
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
	eps, err := endpoints.Catalog(r.o.Dir, r.o.InScope, true)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := endpoints.Write(r.o.Dir, eps); err != nil {
		return err
	}
	// Old code's client headers and buckets: a secret rotated out of
	// today's bundle may still work.
	if _, err := endpoints.SaveIntel(r.o.Dir, r.o.InScope, nil); err != nil {
		return err
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
	r.saveLocked()
}

func (r *runner) saveLocked() {
	r.st.Updated = time.Now().UTC()
	b, _ := json.MarshalIndent(r.st, "", " ")
	tmp := filepath.Join(r.o.Dir, "archive.json.tmp")
	if os.WriteFile(tmp, append(b, '\n'), 0o600) == nil {
		os.Rename(tmp, filepath.Join(r.o.Dir, "archive.json"))
	}
}
