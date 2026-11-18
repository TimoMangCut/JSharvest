// Package store keeps the scripts of one target and role on disk, deduplicated
// by the SHA-256 of their content.
//
// Layout:
//
//	<dir>/js/<sha256>.js
//	<dir>/index.jsonl
//
// The index is loaded on Open, so repeated runs against the same target and
// role add to what earlier runs found. Indexes written by v1 load as well.
package store

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Caps on the list fields of an entry, so that a script seen on thousands of
// pages does not grow its index line without bound.
const (
	maxURLs       = 200
	maxPages      = 50
	maxInitiators = 20
)

// flushEveryNew is how many new scripts trigger a flush on their own.
const flushEveryNew = 50

// keptHeaders are the response headers worth keeping for later analysis.
var keptHeaders = []string{"content-type", "etag", "last-modified", "sourcemap", "x-sourcemap"}

var ErrTooLarge = errors.New("script body over the size limit")

// Record is one sighting of a script, as the capture reports it.
type Record struct {
	Body []byte
	// SHA256 identifies the script when Body is empty: a sighting of content
	// the store already has, which only merges the record's fields.
	SHA256       string
	URL          string // empty for eval
	Kind         string // file, inline or eval
	Via          string // network or debugger
	Target       string // page, iframe, worker, service_worker or shared_worker
	Page         string
	MIME         string
	Headers      map[string]string
	SourceMapURL string
	IsModule     bool
	Initiator    *Initiator
	Tags         []string
	Source       string // live, or an archive's name: wayback, commoncrawl, otx
	// Of an archived script: whether its old URL still serves a script,
	// whether that is the archived one, and when the archives saw it.
	Alive    *bool
	LiveSame bool
	Archive  *ArchiveSeen
}

// ArchiveSeen is what the archives say of a script.
type ArchiveSeen struct {
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Captures int       `json:"captures"`
}

type Initiator struct {
	Type string `json:"type"`
	URL  string `json:"url,omitempty"`
	Line int64  `json:"line,omitempty"`
	Col  int64  `json:"col,omitempty"`
}

type Entry struct {
	SHA256        string            `json:"sha256"`
	SHA1B32       string            `json:"sha1_b32,omitempty"`
	Kinds         []string          `json:"kinds,omitempty"`
	URLs          []string          `json:"urls"`
	CanonicalKeys []string          `json:"canonical_keys,omitempty"`
	Via           []string          `json:"via,omitempty"`
	Targets       []string          `json:"targets,omitempty"`
	Pages         []string          `json:"pages,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	MIME          string            `json:"mime,omitempty"`
	Size          int               `json:"size"`
	Headers       map[string]string `json:"headers,omitempty"`
	SourceMapURL  string            `json:"sourcemap_url,omitempty"`
	IsModule      bool              `json:"is_module,omitempty"`
	Initiators    []Initiator       `json:"initiators,omitempty"`
	Source        string            `json:"source"`            // live, wayback (any archive) or both
	Sources       []string          `json:"sources,omitempty"` // which: live, wayback, commoncrawl…
	Alive         *bool             `json:"alive,omitempty"`
	LiveSame      bool              `json:"live_same,omitempty"`
	Archive       *ArchiveSeen      `json:"archive,omitempty"`
	FirstSeen     time.Time         `json:"first_seen"`
	LastSeen      time.Time         `json:"last_seen"`
}

type Options struct {
	// MaxBody is the largest body Add accepts; 0 means no limit.
	MaxBody int
}

type Store struct {
	dir  string
	opts Options

	mu            sync.Mutex
	entries       map[string]*Entry
	order         []string // keeps index.jsonl stable across runs
	unflushed     int      // changes not yet in index.jsonl
	newSinceFlush int
	recovered     int
	discarded     int
	sha1          map[string]string // SHA1B32 -> SHA-256, built when first asked
}

func Open(dir string, opts Options) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "js"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, opts: opts, entries: map[string]*Entry{}}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("load index: %w", err)
	}
	if err := s.recoverOrphans(); err != nil {
		return nil, fmt.Errorf("recover orphans: %w", err)
	}
	return s, nil
}

func (s *Store) load() error {
	f, err := os.Open(filepath.Join(s.dir, "index.jsonl"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return err
		}
		s.upgrade(&e)
		s.entries[e.SHA256] = &e
		s.order = append(s.order, e.SHA256)
	}
	return sc.Err()
}

// upgrade fills the fields that a v1 index does not have. v1 only stored
// files fetched over the network.
func (s *Store) upgrade(e *Entry) {
	if len(e.Kinds) == 0 {
		e.Kinds = []string{"file"}
	}
	if len(e.Via) == 0 && e.Source == "live" {
		e.Via = []string{"network"}
	}
	if len(e.CanonicalKeys) == 0 {
		for _, u := range e.URLs {
			e.CanonicalKeys = appendUnique(e.CanonicalKeys, CanonicalKey(u), maxURLs)
		}
	}
	if e.SHA1B32 == "" {
		if b, err := os.ReadFile(s.jsPath(e.SHA256)); err == nil {
			e.SHA1B32 = SHA1B32(b)
		}
	}
}

// recoverOrphans indexes script files that a killed run wrote to disk but
// never got into index.jsonl. A file whose content does not hash to its name
// is damaged and removed, as are temp files of interrupted writes.
func (s *Store) recoverOrphans() error {
	dir := filepath.Join(s.dir, "js")
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".tmp-") {
			os.Remove(filepath.Join(dir, f.Name()))
			continue
		}
		key, ok := strings.CutSuffix(f.Name(), ".js")
		if !ok || len(key) != 64 || s.entries[key] != nil {
			continue
		}
		b, err := os.ReadFile(s.jsPath(key))
		if err != nil {
			return err
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != key {
			os.Remove(s.jsPath(key))
			s.discarded++
			continue
		}
		info, err := f.Info()
		if err != nil {
			return err
		}
		t := info.ModTime().UTC()
		s.entries[key] = &Entry{
			SHA256: key, SHA1B32: SHA1B32(b), Kinds: []string{"unknown"}, URLs: []string{},
			Source: "live", Size: len(b), FirstSeen: t, LastSeen: t,
		}
		s.order = append(s.order, key)
		s.unflushed++
		s.recovered++
	}
	return nil
}

// Recovered reports how many orphaned files Open put back into the index,
// and how many damaged ones it removed.
func (s *Store) Recovered() (recovered, discarded int) { return s.recovered, s.discarded }

// Add records one sighting of a script. It reports whether the content is new
// to this store. Every flushEveryNew new scripts it also rewrites the index.
func (s *Store) Add(r Record) (bool, error) {
	_, isNew, err := s.Put(r)
	return isNew, err
}

// Put is Add, and also returns the script's SHA-256 ("" when nothing was
// recorded): a run that shares the store with others (crawl -tabs) keeps
// its own scripts by it.
func (s *Store) Put(r Record) (string, bool, error) {
	if len(r.Body) == 0 {
		if r.SHA256 == "" {
			return "", false, nil
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		e := s.entries[r.SHA256]
		if e == nil {
			return "", false, nil
		}
		merge(e, r, time.Now().UTC())
		s.unflushed++
		return r.SHA256, false, nil
	}
	if s.opts.MaxBody > 0 && len(r.Body) > s.opts.MaxBody {
		return "", false, ErrTooLarge
	}
	sum := sha256.Sum256(r.Body)
	key := hex.EncodeToString(sum[:])
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		if err := writeFileAtomic(s.jsPath(key), r.Body); err != nil {
			return "", false, err
		}
		e = &Entry{
			SHA256: key, SHA1B32: SHA1B32(r.Body), URLs: []string{},
			MIME: r.MIME, Size: len(r.Body), Source: r.Source, FirstSeen: now,
		}
		s.entries[key] = e
		s.order = append(s.order, key)
		if s.sha1 != nil {
			s.sha1[e.SHA1B32] = key
		}
	}
	merge(e, r, now)

	// Every Add changes the index, a merge too; only new scripts count
	// toward the early flush, since merges are frequent and small.
	s.unflushed++
	if !ok {
		s.newSinceFlush++
		if s.newSinceFlush >= flushEveryNew {
			if err := s.flushLocked(); err != nil {
				return "", false, err
			}
		}
	}
	return key, !ok, nil
}

func merge(e *Entry, r Record, now time.Time) {
	e.LastSeen = now
	e.Kinds = appendUnique(e.Kinds, r.Kind, 0)
	e.Via = appendUnique(e.Via, r.Via, 0)
	e.Targets = appendUnique(e.Targets, r.Target, 0)
	e.URLs = appendUnique(e.URLs, r.URL, maxURLs)
	switch r.Kind {
	case "inline":
		// An inline script carries the URL of the document it sits in, which
		// for a frame is not the page.
		doc := r.URL
		if doc == "" {
			doc = r.Page
		}
		e.CanonicalKeys = appendUnique(e.CanonicalKeys, CanonicalKey(doc)+"#inline", maxURLs)
	case "eval":
	default:
		e.CanonicalKeys = appendUnique(e.CanonicalKeys, CanonicalKey(r.URL), maxURLs)
	}
	e.Pages = appendUnique(e.Pages, r.Page, maxPages)
	for _, t := range r.Tags {
		e.Tags = appendUnique(e.Tags, t, 0)
	}
	if e.MIME == "" {
		e.MIME = r.MIME
	}
	for _, h := range keptHeaders {
		if v := headerValue(r.Headers, h); v != "" {
			if e.Headers == nil {
				e.Headers = map[string]string{}
			}
			if e.Headers[h] == "" {
				e.Headers[h] = v
			}
		}
	}
	if e.SourceMapURL == "" {
		e.SourceMapURL = r.SourceMapURL
		// An inline map can be megabytes; record only that there is one.
		if strings.HasPrefix(e.SourceMapURL, "data:") {
			e.SourceMapURL = "data:(inline)"
		}
	}
	e.IsModule = e.IsModule || r.IsModule
	if r.Initiator != nil && len(e.Initiators) < maxInitiators && !slices.Contains(e.Initiators, *r.Initiator) {
		e.Initiators = append(e.Initiators, *r.Initiator)
	}
	if r.Source != "" {
		if len(e.Sources) == 0 && e.Source != "" && e.Source != "both" {
			e.Sources = []string{e.Source} // an index of before the field
		}
		e.Sources = appendUnique(e.Sources, r.Source, 8)
		e.Source = sourceOf(e.Sources)
	}
	if r.Alive != nil {
		e.Alive = r.Alive
	}
	e.LiveSame = e.LiveSame || r.LiveSame
	if a := r.Archive; a != nil {
		if e.Archive == nil {
			e.Archive = &ArchiveSeen{First: a.First, Last: a.Last}
		}
		if a.First.Before(e.Archive.First) {
			e.Archive.First = a.First
		}
		if a.Last.After(e.Archive.Last) {
			e.Archive.Last = a.Last
		}
		e.Archive.Captures = max(e.Archive.Captures, a.Captures)
	}
}

// sourceOf says where a script was seen, as the source field has it: live,
// wayback (an archive, whichever), or both.
func sourceOf(sources []string) string {
	live, archived := false, false
	for _, s := range sources {
		if s == "live" {
			live = true
		} else {
			archived = true
		}
	}
	switch {
	case live && archived:
		return "both"
	case archived:
		return "wayback"
	}
	return "live"
}

// BySHA1 returns the SHA-256 of the content whose SHA-1, base32, is an
// archive's digest, "" when the store has none: content it has need not
// be fetched again.
func (s *Store) BySHA1(b32 string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sha1 == nil {
		s.sha1 = map[string]string{}
		for k, e := range s.entries {
			s.sha1[e.SHA1B32] = k
		}
	}
	return s.sha1[b32]
}

// Entry returns a copy of an entry, false when there is none.
func (s *Store) Entry(sha256 string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[sha256]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// headerValue looks a header up without regard to case, as CDP passes them
// with the case the server used.
func headerValue(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// Dir is the directory of the store.
func (s *Store) Dir() string { return s.dir }

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// AutoFlush rewrites the index every interval until ctx ends, so that a run
// killed with SIGKILL loses at most one interval of index entries.
func (s *Store) AutoFlush(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			if s.unflushed > 0 {
				s.flushLocked()
			}
			s.mu.Unlock()
		}
	}
}

// Flush rewrites index.jsonl. It writes a temp file and renames it, so an
// interrupted flush leaves the previous index intact. A background flush
// that failed is retried here, so a successful Flush means the index on disk
// is complete.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

func (s *Store) flushLocked() error {
	tmp, err := os.CreateTemp(s.dir, ".index-*.jsonl")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	w := bufio.NewWriter(tmp)
	enc := json.NewEncoder(w)
	for _, k := range s.order {
		if err := enc.Encode(s.entries[k]); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(s.dir, "index.jsonl")); err != nil {
		return err
	}
	s.unflushed, s.newSinceFlush = 0, 0
	return nil
}

// writeFileAtomic writes to a temp file and renames it into place, so a run
// killed mid-write never leaves a truncated script under its final name.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *Store) jsPath(key string) string {
	return filepath.Join(s.dir, "js", key+".js")
}

// SHA1B32 is the base32 SHA-1 of b, the form of the digest field of the
// Wayback Machine CDX API, so archived copies can be matched before download.
func SHA1B32(b []byte) string {
	sum := sha1.Sum(b)
	return base32.StdEncoding.EncodeToString(sum[:])
}

// appendUnique appends v unless it is empty, already present, or the list
// has reached max (0 means no cap).
func appendUnique(list []string, v string, max int) []string {
	if v == "" || slices.Contains(list, v) || (max > 0 && len(list) >= max) {
		return list
	}
	return append(list, v)
}
