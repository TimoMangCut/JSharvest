package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/debugger"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/marker"
)

const (
	// maxScriptsCache bounds the sources V8 keeps for collected scripts.
	maxScriptsCache = 100 << 20
	// maxScriptsPerSession stops a page that evals without end from running
	// the capture into the ground; past it, only scripts with a URL are read.
	maxScriptsPerSession = 20000
	// cdpSelf is the expression chromedp evaluates on every target it
	// attaches to (chromedp.go:583). It is not the page's code.
	cdpSelf = "self"
)

// ownScript reports whether a script is jsharvest's own: chromedp's
// probe, the capture's and explore's code, the action tagger.
func ownScript(url, src string) bool {
	return (url == "" && src == cdpSelf) || marker.InSource(src)
}

// scriptTracker reads every script V8 compiles on a session: inline
// scripts, eval and new Function code, blob: workers, and the scripts that
// ran before the session attached, which Debugger.enable reports again.
type scriptTracker struct {
	s *session

	mu      sync.Mutex
	docURLs map[string]bool // every URL a document of this page or frame has had
	count   int
}

func newScriptTracker(s *session) *scriptTracker {
	t := &scriptTracker{s: s, docURLs: map[string]bool{}}
	if s.targetURL != "" {
		t.docURLs[stripFragment(s.targetURL)] = true
	}
	return t
}

// start subscribes before enabling the Debugger, so that neither the scripts
// it reports again nor a pause is missed.
func (t *scriptTracker) start() error {
	ctx := t.s.ctx
	parsed := chromedp.Events(ctx, debugger.ScriptParsed)
	paused := chromedp.Events(ctx, debugger.Paused)
	if t.hasDocument() {
		navigated := chromedp.Events(ctx, page.FrameNavigated)
		within := chromedp.Events(ctx, page.NavigatedWithinDocument)
		go func() {
			for ev, err := range navigated {
				if err != nil {
					return
				}
				t.addDocURL(ev.Frame.URL)
			}
		}()
		go func() {
			for ev, err := range within {
				if err != nil {
					return
				}
				t.addDocURL(ev.URL)
			}
		}()
	}

	// A debugger statement can pause the page between Enable and
	// SetSkipAllPauses taking effect; resume at once if it does.
	go func() {
		for _, err := range paused {
			if err != nil {
				return
			}
			cctx, cancel := context.WithTimeout(ctx, t.s.c.opts.CallTimeout)
			chromedp.Call(cctx, debugger.Resume, debugger.ResumeParams{})
			cancel()
		}
	}()
	go func() {
		for ev, err := range parsed {
			if err != nil {
				return
			}
			t.parsed(&ev)
		}
	}()

	cctx, cancel := context.WithTimeout(ctx, t.s.c.opts.CallTimeout)
	defer cancel()
	if _, err := chromedp.Call(cctx, debugger.Enable, debugger.EnableParams{MaxScriptsCacheSize: maxScriptsCache}); err != nil {
		return err
	}
	_, err := chromedp.Call(cctx, debugger.SetSkipAllPauses, debugger.SetSkipAllPausesParams{Skip: true})
	return err
}

func (t *scriptTracker) hasDocument() bool {
	return t.s.kind == "page" || t.s.kind == "iframe"
}

func (t *scriptTracker) addDocURL(u string) {
	t.mu.Lock()
	t.docURLs[stripFragment(u)] = true
	t.mu.Unlock()
}

func (t *scriptTracker) parsed(ev *debugger.EventScriptParsed) {
	if ev.ScriptLanguage == debugger.ScriptLanguageWebAssembly || strings.HasPrefix(ev.URL, "chrome-extension:") {
		return
	}
	// Content scripts of extensions run in isolated worlds of the page.
	if len(ev.ExecutionContextAuxData) > 0 {
		var aux struct {
			IsDefault *bool `json:"isDefault"`
		}
		if json.Unmarshal(ev.ExecutionContextAuxData, &aux) == nil && aux.IsDefault != nil && !*aux.IsDefault {
			return
		}
	}

	t.mu.Lock()
	t.count++
	over := t.count > maxScriptsPerSession
	t.mu.Unlock()
	if over && (ev.URL == "" || ev.HasSourceURL) {
		return
	}

	c := t.s.c
	key := ev.Hash
	if key == "" {
		key = string(t.s.id) + "/" + string(ev.ScriptID)
	}
	// Where this script was seen, for when its content is already known or
	// being read: only the sighting is recorded.
	sighting := Script{Kind: t.kind(ev), Via: "debugger", URL: ev.URL,
		Target: t.s.kind, TargetURL: t.s.targetURL, Page: c.currentPage()}
	if ev.HasSourceURL {
		sighting.URL = ""
	}
	sha, state := c.claimHash(key, sighting)
	switch state {
	case hashKnown:
		sighting.SHA256 = sha
		c.emit(sighting)
		return
	case hashPending:
		// claimHash queued the sighting; knownHash emits it once the
		// content is stored.
		return
	}

	// A challenge's code is not read at all: Cloudflare's VM evaluates
	// several 1.3 MB blocks per page, none of them the target's.
	initiator := ""
	if st := ev.StackTrace; st != nil && len(st.CallFrames) > 0 {
		initiator = st.CallFrames[0].URL
	}
	if detect.ChallengeURL(ev.URL) || (initiator != "" && detect.ChallengeURL(initiator)) {
		c.skipChallenge(key, ev.URL, initiator)
		c.knownHash(key, challengeSHA)
		return
	}

	page := c.currentPage()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ok := false
		defer func() {
			if !ok {
				c.releaseHash(key)
			}
		}()
		if !c.acquire(t.s.ctx) {
			c.lost("canceled")
			return
		}
		defer c.release()
		ctx, cancel := context.WithTimeout(t.s.ctx, c.opts.CallTimeout)
		defer cancel()
		res, err := chromedp.Call(ctx, debugger.GetScriptSource, debugger.GetScriptSourceParams{ScriptID: ev.ScriptID})
		if err != nil {
			c.lost(bodyErrReason(err))
			slog.Debug("get script source", "target", t.s.kind, "url", ev.URL, "err", err)
			return
		}
		src := res.ScriptSource
		if src == "" {
			return
		}
		sum := sha256.Sum256([]byte(src))
		sha := hex.EncodeToString(sum[:])
		ok = true
		if ownScript(ev.URL, src) {
			c.internal()
			c.knownHash(key, sha)
			return
		}
		s := Script{
			Body: []byte(src), Kind: t.kind(ev), Via: "debugger", URL: ev.URL,
			Target: t.s.kind, TargetURL: t.s.targetURL, Page: page,
			SourceMapURL: ev.SourceMapURL, IsModule: ev.IsModule,
			Tags: detect.ScriptTags(ev.URL),
		}
		if ev.HasSourceURL {
			// eval code that named itself: keep the name, not as a URL.
			s.Kind, s.URL, s.Tags = "eval", "", append(s.Tags, "sourceURL:"+ev.URL)
		}
		if st := ev.StackTrace; st != nil && len(st.CallFrames) > 0 {
			f := st.CallFrames[0]
			s.Initiator = &Initiator{Type: "script", URL: f.URL, Line: f.LineNumber, Col: f.ColumnNumber}
		}
		// Store the content first: a sighting of content the store does not
		// have yet would be dropped.
		c.emit(s)
		c.knownHash(key, sha)
	}()
}

// kind classifies a script. An empty URL is eval or new Function code; a
// script whose URL is a document URL of this page or frame is inline. In a
// worker, the target URL is the main script, which is a file.
func (t *scriptTracker) kind(ev *debugger.EventScriptParsed) string {
	if ev.URL == "" || ev.HasSourceURL {
		return "eval"
	}
	if t.hasDocument() {
		t.mu.Lock()
		doc := t.docURLs[stripFragment(ev.URL)]
		t.mu.Unlock()
		if doc || stripFragment(ev.URL) == stripFragment(t.s.c.currentPage()) {
			return "inline"
		}
	}
	return "file"
}

func stripFragment(u string) string {
	if i := strings.IndexByte(u, '#'); i >= 0 {
		return u[:i]
	}
	return u
}

type hashState int

const (
	hashNew hashState = iota
	hashPending
	hashKnown
)

// claimHash checks a V8 script hash across all sessions. The first caller
// gets hashNew and must fetch the source, then call knownHash or
// releaseHash. While that read runs, other callers get hashPending and their
// sighting is queued for knownHash. A hash only counts as known once its
// source was read, so a failed read in one session does not hide the script
// in another.
func (c *Capture) claimHash(key string, sighting Script) (string, hashState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sha, ok := c.hashes[key]
	switch {
	case !ok:
		c.hashes[key] = ""
		return "", hashNew
	case sha == "":
		c.hashWaiters[key] = append(c.hashWaiters[key], sighting)
		return "", hashPending
	}
	return sha, hashKnown
}

// knownHash records the content of a hash and emits the sightings that
// waited for it. Call it after the content itself was emitted.
func (c *Capture) knownHash(key, sha string) {
	c.mu.Lock()
	c.hashes[key] = sha
	waiters := c.hashWaiters[key]
	delete(c.hashWaiters, key)
	c.mu.Unlock()
	for _, w := range waiters {
		w.SHA256 = sha
		c.emit(w)
	}
}

// releaseHash gives a hash up after its source could not be read. The
// queued sightings go with it; the next parse of the script claims it anew.
func (c *Capture) releaseHash(key string) {
	c.mu.Lock()
	if c.hashes[key] == "" {
		delete(c.hashes, key)
		delete(c.hashWaiters, key)
	}
	c.mu.Unlock()
}

func (c *Capture) internal() {
	c.mu.Lock()
	c.stats.CDPInternal++
	c.mu.Unlock()
}
