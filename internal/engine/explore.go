package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/domdebugger"
	"github.com/chromedp/cdproto/domsnapshot"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/explore"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/marker"
)

// ExploreStats goes into run.json.
type ExploreStats struct {
	Pages       int            `json:"pages"`
	Actions     map[string]int `json:"actions"`           // done, by kind
	Skipped     map[string]int `json:"skipped,omitempty"` // left undone, by reason
	Untrusted   int            `json:"untrusted,omitempty"`
	Restores    int            `json:"restores,omitempty"`
	Navigations int            `json:"navigations"` // held by the guard, handed to the frontier
	NewURLs     int            `json:"new_urls"`
	Dialogs     int            `json:"dialogs,omitempty"`
	Popups      int            `json:"popups,omitempty"`
	SessionEnds int            `json:"session_ends,omitempty"` // controls after which the session was lost
	Errors      int            `json:"errors,omitempty"`
	TookMS      int64          `json:"took_ms"`
}

const (
	exploreWorld = "jsharvest-explore"
	exploreGroup = "jsharvest-explore"
	// maxReclicks bounds how often one control is used again on a page,
	// when the page has changed since (a wizard's one "Next" button).
	maxReclicks = 3
	maxRestores = 10
	maxDialogs  = 20 // in one action: a page that alerts without end
	inputWait   = 5 * time.Second
)

var errHung = errors.New("the page did not take the input")

// explorer does to each page what a person could: see package explore for
// what, and docs/gd4-explore-design.md for how.
type explorer struct {
	e       *engine
	sh      *exploreShared
	main    string // the tab's main frame: it has the tab's id
	stats   *ExploreStats
	dialogs atomic.Int64
	worlds  map[string]runtime.ExecutionContextID // explore's world in each frame of the document
	lost    bool                                  // the session was lost and could not be restored
	lib     string
}

// exploreShared is what the explorers of a run's tabs share (crawl -tabs):
// the controls used, so that a tab does not use one another used, when the
// run began (-explore-total), and the files to upload.
type exploreShared struct {
	mu      sync.Mutex
	seen    map[string]bool // signatures used, or taken by a tab about to use them
	started time.Time
	dir     string
}

func newExploreShared() (*exploreShared, error) {
	dir, err := os.MkdirTemp("", "jsharvest-upload-")
	if err != nil {
		return nil, err
	}
	sh := &exploreShared{seen: map[string]bool{}, started: time.Now(), dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "document.txt"), []byte("test upload\n"), 0o600); err != nil {
		sh.close()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "image.png"), onePixelPNG, 0o600); err != nil {
		sh.close()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "IM000001"), sampleDICOM(), 0o600); err != nil {
		sh.close()
		return nil, err
	}
	return sh, nil
}

func (sh *exploreShared) close() { os.RemoveAll(sh.dir) }

func (sh *exploreShared) used(sig string) bool {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.seen[sig]
}

// claim takes a control for a tab to use: false when another has it.
func (sh *exploreShared) claim(sig string) bool {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.seen[sig] {
		return false
	}
	sh.seen[sig] = true
	return true
}

// unclaim gives back a control a tab took and could not use (yet).
func (sh *exploreShared) unclaim(sig string) {
	sh.mu.Lock()
	delete(sh.seen, sig)
	sh.mu.Unlock()
}

// addExploreStats sums the tabs' counts.
func addExploreStats(all []*ExploreStats) *ExploreStats {
	out := &ExploreStats{Actions: map[string]int{}, Skipped: map[string]int{}}
	for _, s := range all {
		out.Pages += s.Pages
		for k, n := range s.Actions {
			out.Actions[k] += n
		}
		for k, n := range s.Skipped {
			out.Skipped[k] += n
		}
		out.Untrusted += s.Untrusted
		out.Restores += s.Restores
		out.Navigations += s.Navigations
		out.NewURLs += s.NewURLs
		out.Dialogs += s.Dialogs
		out.Popups += s.Popups
		out.SessionEnds += s.SessionEnds
		out.Errors += s.Errors
		out.TookMS += s.TookMS
	}
	return out
}

func newExplorer(ctx context.Context, e *engine, sh *exploreShared) (*explorer, error) {
	x := &explorer{e: e, sh: sh, worlds: map[string]runtime.ExecutionContextID{},
		stats: &ExploreStats{Actions: map[string]int{}, Skipped: map[string]int{}}}
	samples := maps.Clone(frontier.Samples)
	samples["password"] = "Test1234!x" // eight and more, every kind of character
	b, _ := json.Marshal(samples)
	x.lib = strings.Replace(exploreLib, "SAMPLES", string(b), 1)
	x.bindTab(ctx)

	tab := e.tabCtx()
	cctx, cancel := context.WithTimeout(tab, 10*time.Second)
	defer cancel()
	tctx := tabUntil(tab, ctx)
	// Downloads write nothing: in a browser of its own, the crawl denies
	// them all; in the user's, it cancels those of its tab.
	if e.cfg.Browser.Attach == "" {
		if _, err := chromedp.CallBrowser(cctx, cdpbrowser.SetDownloadBehavior, cdpbrowser.SetDownloadBehaviorParams{Behavior: cdpbrowser.SetDownloadBehaviorBehaviorDeny}); err != nil {
			slog.Debug("explore: downloads", "err", err)
		}
	} else {
		yes := true
		begins := chromedp.BrowserEvents(tctx, cdpbrowser.DownloadWillBegin)
		if _, err := chromedp.CallBrowser(cctx, cdpbrowser.SetDownloadBehavior, cdpbrowser.SetDownloadBehaviorParams{Behavior: cdpbrowser.SetDownloadBehaviorBehaviorDefault, EventsEnabled: &yes}); err != nil {
			slog.Debug("explore: downloads", "err", err)
		}
		go each(begins, func(ev *cdpbrowser.EventDownloadWillBegin) {
			if string(ev.FrameID) != e.mainFrameID() {
				return
			}
			c, cancel := context.WithTimeout(e.tabCtx(), inputWait)
			defer cancel()
			chromedp.CallBrowser(c, cdpbrowser.CancelDownload, cdpbrowser.CancelDownloadParams{GUID: ev.GUID})
		})
	}
	return x, nil
}

// bindTab wires the explorer's frame ID, worlds and file-chooser interception
// to x.e.tab (initially and after a wedged tab is recycled).
func (x *explorer) bindTab(ctx context.Context) {
	tab := x.e.tabCtx()
	x.main = string(chromedp.FromContext(tab).Target.TargetID)
	clear(x.worlds)
	cctx, cancel := context.WithTimeout(tab, 10*time.Second)
	defer cancel()
	// A page's own upload button calls input.click(): the chooser it opens
	// is answered with a file.
	chooser := chromedp.Events(tabUntil(tab, ctx), page.FileChooserOpened)
	if _, err := chromedp.Call(cctx, page.SetInterceptFileChooserDialog, page.SetInterceptFileChooserDialogParams{Enabled: true}); err != nil {
		slog.Debug("explore: file chooser", "err", err)
	}
	go each(chooser, func(ev *page.EventFileChooserOpened) {
		if ev.BackendNodeID == 0 {
			return
		}
		c, cancel := context.WithTimeout(tab, inputWait)
		defer cancel()
		// A folder picker (webkitdirectory, a DICOM viewer's "open folder")
		// takes a folder: the upload directory, two harmless files in it.
		// A file there would set nothing, and no change event
		// would ever come.
		files := []string{filepath.Join(x.sh.dir, "document.txt")}
		if folderInput(c, ev.BackendNodeID) {
			files = []string{x.sh.dir}
		}
		if _, err := chromedp.Call(c, dom.SetFileInputFiles, dom.SetFileInputFilesParams{Files: files, BackendNodeID: ev.BackendNodeID}); err != nil {
			slog.Debug("explore: file chooser", "mode", ev.Mode, "err", err)
		}
	})
}

// folderInput reports a file input that picks a folder (webkitdirectory).
func folderInput(ctx context.Context, backend cdp.BackendNodeID) bool {
	obj, err := chromedp.Call(ctx, dom.ResolveNode, dom.ResolveNodeParams{BackendNodeID: backend, ObjectGroup: "jsharvest-chooser"})
	if err != nil || obj.Object == nil {
		return false
	}
	defer chromedp.Call(ctx, runtime.ReleaseObjectGroup, runtime.ReleaseObjectGroupParams{ObjectGroup: "jsharvest-chooser"})
	byValue := true
	res, err := chromedp.Call(ctx, runtime.CallFunctionOn, runtime.CallFunctionOnParams{
		FunctionDeclaration: "function() {\n//# sourceURL=" + marker.Internal + "\nreturn !!this.webkitdirectory;\n}",
		ObjectID:            obj.Object.ObjectID, ReturnByValue: &byValue,
	})
	if err != nil || res.ExceptionDetails != nil || res.Result == nil {
		return false
	}
	var dir bool
	return json.Unmarshal(res.Result.Value, &dir) == nil && dir
}

// tabUntil is a context of the tab (chromedp listens on those only) that
// ends with ctx.
func tabUntil(tab, ctx context.Context) context.Context {
	c, cancel := context.WithCancel(tab)
	context.AfterFunc(ctx, cancel)
	return c
}

// handleDialogs answers every dialog of the tab, for the whole crawl: an
// alert on load would hold the page, and a beforeunload the next visit.
// confirm() is accepted, to reach what it guards (the guard holds back the
// write); a prompt gets "test"; beforeunload lets the page go: explore's
// navigations are held anyway, and the crawl's own must happen.
func (e *engine) handleDialogs(ctx context.Context, count func()) {
	tab := e.tabCtx()
	dialogs := chromedp.Events(tabUntil(tab, ctx), page.JavascriptDialogOpening)
	go each(dialogs, func(ev *page.EventJavascriptDialogOpening) {
		if count != nil {
			count()
		}
		p := page.HandleJavaScriptDialogParams{Accept: true}
		if ev.Type == page.DialogTypePrompt {
			p.PromptText = "test"
		}
		slog.Debug("dialog", "type", ev.Type, "message", ev.Message)
		// Not on this goroutine: the call that opened the dialog waits on it.
		go func() {
			c, cancel := context.WithTimeout(tab, inputWait)
			defer cancel()
			if _, err := chromedp.Call(c, page.HandleJavaScriptDialog, p); err != nil {
				slog.Debug("dialog", "err", err)
			}
		}()
	})
}

// state is a snapshot of the page and what can be done on it.
type state struct {
	pg      *explore.Page
	cands   []explore.Candidate
	by      map[cdp.BackendNodeID]int
	sigs    map[string]bool
	raws    map[string]bool // the controls exactly (Candidate.Raw)
	print   string          // what the page offers: its controls, exactly
	skipped map[string]int
}

func (x *explorer) snapshot() (*state, error) {
	ctx, cancel := context.WithTimeout(x.e.tab, 20*time.Second)
	defer cancel()
	snap, err := chromedp.Call(ctx, domsnapshot.CaptureSnapshot, domsnapshot.CaptureSnapshotParams{ComputedStyles: explore.Styles})
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	listeners := map[cdp.BackendNodeID][]string{}
	depth, pierce := int64(-1), true
	for _, d := range snap.Documents {
		if d.Nodes == nil || len(d.Nodes.BackendNodeID) == 0 {
			continue
		}
		obj, err := chromedp.Call(ctx, dom.ResolveNode, dom.ResolveNodeParams{BackendNodeID: d.Nodes.BackendNodeID[0], ObjectGroup: exploreGroup})
		if err != nil || obj.Object == nil {
			continue
		}
		ls, err := chromedp.Call(ctx, domdebugger.GetEventListeners, domdebugger.GetEventListenersParams{ObjectID: obj.Object.ObjectID, Depth: &depth, Pierce: &pierce})
		if err != nil {
			slog.Debug("explore: listeners", "err", err)
			continue
		}
		for _, l := range ls.Listeners {
			if !slices.Contains(listeners[l.BackendNodeID], l.Type) {
				listeners[l.BackendNodeID] = append(listeners[l.BackendNodeID], l.Type)
			}
		}
	}
	chromedp.Call(ctx, runtime.ReleaseObjectGroup, runtime.ReleaseObjectGroupParams{ObjectGroup: exploreGroup})
	pg := explore.FromSnapshot(&snap, listeners)
	cands, skipped := explore.Candidates(pg)
	s := &state{pg: pg, cands: cands, by: pg.ByBackend(), sigs: map[string]bool{}, raws: map[string]bool{}, skipped: skipped}
	var raws []string
	for _, c := range cands {
		s.sigs[c.Sig] = true
		if !s.raws[c.Raw] {
			s.raws[c.Raw] = true
			raws = append(raws, c.Raw)
		}
	}
	slices.Sort(raws)
	sum := sha256.Sum256([]byte(strings.Join(raws, "\n")))
	s.print = hex.EncodeToString(sum[:8])
	return s, nil
}

// pageRun is explore's work on one page.
type pageRun struct {
	done    map[string]int             // signature -> times used on this page
	tried   map[string]map[string]bool // signature -> the page states it was used in
	changed map[string]bool            // signature -> using it last changed what the page offers
	after   map[string][]string        // signature -> what using it last brought (Raw)
	handled map[string]bool            // Raw -> acted on
	covered map[string]bool            // put back once for being under another element
	acted   int
}

// page explores the page the tab is on, which the crawl reached as it.
// It returns the URLs it found: navigations it held, routes the page
// changed to, popups.
func (x *explorer) page(ctx context.Context, it frontier.Item) []frontier.Found {
	e := x.e
	start := time.Now()
	defer func() { x.stats.TookMS += time.Since(start).Milliseconds() }()
	if total := e.cfg.ExploreTotal; total > 0 && time.Since(x.sh.started) > total {
		x.stats.Skipped["run-budget"]++
		return nil
	}
	x.stats.Pages++
	deadline := start.Add(e.cfg.ExploreTime)
	// Controls left alone, counted once a page: the most any state had.
	skipped := map[string]int{}
	defer func() {
		for k, n := range skipped {
			x.stats.Skipped[k] += n
		}
	}()
	snapshot := func() (*state, error) {
		s, err := x.snapshot()
		if err == nil {
			for k, n := range s.skipped {
				skipped[k] = max(skipped[k], n)
			}
		}
		return s, err
	}
	release := e.guard.HoldNavigations(x.main)
	defer func() { release() }()
	x.worlds = map[string]runtime.ExecutionContextID{}

	var found []frontier.Found
	seenURL := map[string]bool{}
	note := func(u string) {
		if u == "" || seenURL[u] || strings.HasPrefix(u, "about:") {
			return
		}
		seenURL[u] = true
		x.stats.NewURLs++
		found = append(found, frontier.Found{URL: u, How: frontier.Explore, Visit: true})
	}
	pageURL := x.href()
	if pageURL == "" {
		pageURL = it.URL
	}
	// reload brings the page back as the crawl reached it, the navigation
	// lock lifted while it loads.
	restores := 0
	reload := func() bool {
		if restores >= maxRestores {
			x.stats.Skipped["restores"]++
			return false
		}
		restores++
		x.stats.Restores++
		release()
		e.visit(ctx, frontier.Item{URL: pageURL, Depth: it.Depth, From: it.From, How: it.How})
		release = e.guard.HoldNavigations(x.main)
		x.worlds = map[string]runtime.ExecutionContextID{}
		return true
	}

	st, err := snapshot()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			e.timedOut = true
		}
		x.stats.Errors++
		slog.Warn("explore", "page", pageURL, "err", err)
		return nil
	}
	if x.scroll(ctx) {
		if s2, err := snapshot(); err == nil {
			st = s2
		}
	}
	r := &pageRun{done: map[string]int{}, tried: map[string]map[string]bool{}, changed: map[string]bool{}, after: map[string][]string{}, handled: map[string]bool{}, covered: map[string]bool{}}
	prev := st.raws
	for {
		if ctx.Err() != nil {
			break
		}
		var ep int64 // the session's epoch as the action begins (NEW-C5-02)
		if k := e.keeper; k != nil {
			k.wait() // another tab is putting the session back (REV-C-06)
			ep = k.Epoch()
		}
		queue := x.order(st, prev, r)
		if len(queue) == 0 {
			break
		}
		if time.Now().After(deadline) {
			x.stats.Skipped["time"] += len(queue)
			break
		}
		if r.acted >= e.cfg.ExploreActions {
			x.stats.Skipped["budget"] += len(queue)
			break
		}
		c := queue[0]
		if slog.Default().Enabled(ctx, slog.LevelDebug) {
			var head []string
			for _, q := range queue[:min(len(queue), 5)] {
				head = append(head, string(q.Action)+" "+q.Selector)
			}
			slog.Debug("explore: queue", "len", len(queue), "head", head)
		}
		// The control is taken before it is used: another tab is not to
		// use it too meanwhile (NEW-C5-04).
		claimed := false
		if r.done[c.Sig] == 0 {
			if !x.sh.claim(c.Sig) {
				continue // another tab took it just now
			}
			claimed = true
		}
		before := x.dialogs.Load()
		outcome, err := x.act(ctx, st, c, r.covered[c.Sig])
		if claimed && (errors.Is(err, errHung) || outcome == "covered") {
			x.sh.unclaim(c.Sig)
		}
		if errors.Is(err, errHung) {
			if ctx.Err() == nil {
				e.timedOut = true
			}
			x.stats.Errors++
			slog.Warn("explore: the page stopped taking input; leaving it", "page", pageURL, "element", c.Selector)
			break
		}
		if outcome == "covered" {
			r.covered[c.Sig] = true
			continue
		}
		r.done[c.Sig]++
		r.handled[c.Raw] = true
		if r.tried[c.Sig] == nil {
			r.tried[c.Sig] = map[string]bool{}
		}
		r.tried[c.Sig][st.print] = true
		if outcome != "ok" && outcome != "untrusted" {
			if err == nil && (outcome == "covered-for-good" || outcome == "gone") {
				x.stats.Skipped[outcome]++
			} else {
				x.stats.Errors++
			}
			slog.Debug("explore: could not act", "action", c.Action, "element", c.Selector, "outcome", outcome, "err", err)
			if s2, err := snapshot(); err == nil {
				prev, st = st.raws, s2
			}
			continue
		}
		r.acted++
		x.stats.Actions[string(c.Action)]++
		if outcome == "untrusted" {
			x.stats.Untrusted++
		}
		slog.Info("explore", "action", c.Action, "element", c.Label, "selector", c.Selector)
		slog.Debug("explore: signature", "sig", c.Sig)
		x.settle(ctx)
		// The pointer back to a corner: the page scrolls under a pointer at
		// rest, and what slides under it would be hovered by no action.
		// Not after a hover: what it showed (a menu) stays while the pointer
		// is on it, to be clicked next.
		if c.Action != explore.Hover {
			x.mouse(input.DispatchMouseEventTypeMouseMoved, 0, 0, input.MouseButtonNone, 0)
		}
		x.stats.Popups += x.closePopups()

		toLogin := false
		for _, u := range e.guard.TakeNavigations(x.main) {
			x.stats.Navigations++
			note(u)
			if k := e.keeper; k != nil && pathOf(u) == pathOf(k.login.Snapshot.LoginURL) {
				toLogin = true
			}
		}
		if n := x.dialogs.Load() - before; n > maxDialogs {
			// A storm of alerts, perhaps without end: a fresh page stops it.
			x.stats.Skipped["dialogs"]++
			slog.Warn("explore: the action kept opening dialogs; loading the page again", "page", pageURL, "element", c.Selector, "dialogs", n)
			if !reload() {
				break
			}
			if s2, err := snapshot(); err == nil {
				prev, st = s2.raws, s2
			}
			continue
		}

		// The session: a control that ended it is not used again.
		if k := e.keeper; k != nil {
			cause := k.check(e, e.harvest.MainDocument(), pageURL)
			// The page sent itself to the login page (held): a lost session,
			// or a link to it. The server tells which.
			if cause == "" && toLogin {
				if ok, _ := k.verify(e); !ok {
					cause = "login-page"
				}
			}
			if cause == "" && k.Epoch() != ep {
				// Another tab lost the session while this action ran: the
				// action may have met a logged-out server. The page anew.
				if k.lost() {
					x.lost = true
					return found
				}
				if !reload() {
					break
				}
				if s2, err := snapshot(); err == nil {
					prev, st = s2.raws, s2
				}
				continue
			}
			if cause != "" {
				x.stats.SessionEnds++
				release()
				ok := k.recover(ctx, e, ep, cause, pageURL)
				release = e.guard.HoldNavigations(x.main)
				x.worlds = map[string]runtime.ExecutionContextID{}
				if !ok {
					x.lost = true
					return found
				}
				if !reload() {
					break
				}
				if s2, err := snapshot(); err == nil {
					prev, st = s2.raws, s2
				}
				continue
			}
		}

		s2, err := snapshot()
		if err != nil {
			x.stats.Errors++
			break
		}
		r.changed[c.Sig] = s2.print != st.print
		r.after[c.Sig] = nil
		for raw := range s2.raws {
			if !st.raws[raw] {
				r.after[c.Sig] = append(r.after[c.Sig], raw)
			}
		}
		href := x.href()
		changed := href != "" && href != pageURL
		if changed {
			note(href)
		}
		// What was still to do and is gone: another view took the page's
		// place. Signatures, not nodes: frameworks render nodes anew.
		gone := 0
		for _, q := range queue[1:] {
			if !s2.sigs[q.Sig] {
				gone++
			}
		}
		if changed || (len(queue) > 2 && gone*2 > len(queue)-1) {
			slog.Debug("explore: the view changed; loading the page again", "url", href, "gone", gone)
			if !reload() {
				break
			}
			if s3, err := snapshot(); err == nil {
				s2 = s3
			}
			prev, st = s2.raws, s2
			continue
		}
		prev, st = st.raws, s2
	}
	for _, u := range e.guard.TakeNavigations(x.main) {
		x.stats.Navigations++
		note(u)
	}
	x.stats.Popups += x.closePopups()
	return found
}

// order is what to do next in a state: what the last action brought
// first (a dialog it opened, the next step of a wizard), fields before
// buttons, then the page's order; what was under another element last.
// A control used on an earlier page is not used again; one used on this
// page is, a few times, once the page offers something else.
func (x *explorer) order(st *state, prev map[string]bool, r *pageRun) []explore.Candidate {
	var out []explore.Candidate
	inQueue := map[string]bool{}
	for _, c := range st.cands {
		if inQueue[c.Sig] {
			continue
		}
		switch n := r.done[c.Sig]; {
		case n == 0 && x.sh.used(c.Sig):
			continue // done on another page
		case c.Action == explore.Type:
			// A field is cheap, and a wizard's next one is like the last:
			// each field of this page, once.
			if r.handled[c.Raw] {
				continue
			}
		case n > 0 && !x.again(st, r, c):
			continue
		}
		inQueue[c.Sig] = true
		out = append(out, c)
	}
	rank := func(c explore.Candidate) int {
		k := 0
		if r.covered[c.Sig] {
			k += 4
		}
		if prev[c.Raw] {
			k += 2
		}
		if c.Action != explore.Type {
			k++
		}
		return k
	}
	slices.SortStableFunc(out, func(a, b explore.Candidate) int { return rank(a) - rank(b) })
	return out
}

// again reports whether a control used on this page is used once more: a
// wizard's one "Next" button, whose use brings the next step's fields.
// Only if its last use brought something, all of that has been done, and
// the page is in a state it was not used in.
func (x *explorer) again(st *state, r *pageRun, c explore.Candidate) bool {
	if r.done[c.Sig] >= maxReclicks || c.Action == explore.Type || !r.changed[c.Sig] || len(r.after[c.Sig]) == 0 || r.tried[c.Sig][st.print] {
		return false
	}
	for _, raw := range r.after[c.Sig] {
		if st.raws[raw] && !r.handled[raw] {
			return false
		}
	}
	return true
}

// act does one candidate. It returns ok, untrusted (done from script: the
// element was under another), covered (try later), or why it could not.
func (x *explorer) act(ctx context.Context, st *state, c explore.Candidate, force bool) (string, error) {
	switch c.Action {
	case explore.Type:
		return x.typeInto(c)
	case explore.Key:
		if err := x.focus(c); err != nil {
			return "gone", err
		}
		if v, _ := x.callString(c, "value"); v == "" {
			if v, err := x.callString(c, "choose"); err == nil {
				if err := x.keys(v); err != nil {
					return "failed", err
				}
			}
		}
		return "ok", x.press("Enter", "Enter", 13, "\r")
	case explore.Select:
		if err := x.focus(c); err != nil {
			return "gone", err
		}
		before, _ := x.callString(c, "value")
		if err := x.press("ArrowDown", "ArrowDown", 40, ""); err != nil {
			return "failed", err
		}
		x.callString(c, "selectNext", before)
		return "ok", nil
	case explore.Upload:
		file := "document.txt"
		if a, _ := x.callString(c, "accept"); strings.Contains(a, "image") {
			file = "image.png"
		}
		cctx, cancel := context.WithTimeout(x.e.tab, inputWait)
		defer cancel()
		if _, err := chromedp.Call(cctx, dom.SetFileInputFiles, dom.SetFileInputFilesParams{Files: []string{filepath.Join(x.sh.dir, file)}, BackendNodeID: c.Backend}); err != nil {
			return "gone", err
		}
		return "ok", nil
	case explore.Submit:
		x.callString(c, "prepare")
	}

	px, py, outcome, err := x.point(st, c)
	if outcome == "covered" || outcome == "unknown" {
		// Scrolled just into view, it may sit under a fixed bar or banner:
		// to the middle of the view, and look again.
		if _, err := x.callString(c, "center"); err == nil {
			px, py, outcome, err = x.point(st, c)
		}
	}
	if outcome == "unknown" {
		// Something the snapshot did not have is on top (made since): look
		// again, once.
		if s2, err2 := x.snapshot(); err2 == nil {
			*st = *s2
			px, py, outcome, err = x.point(st, c)
		}
		if outcome == "unknown" {
			outcome = "covered"
		}
	}
	switch outcome {
	case "ok":
	case "covered":
		if !force {
			return "covered", nil
		}
		// Under another element even now: from script, as the page itself
		// would. Only a click has such a form.
		if c.Action == explore.Click || c.Action == explore.Submit || c.Action == explore.Check {
			if _, err := x.callString(c, "click"); err != nil {
				return "failed", err
			}
			return "untrusted", nil
		}
		return "covered-for-good", nil
	default:
		return outcome, err
	}
	switch c.Action {
	case explore.Hover:
		x.note(c, "hover")
		return "ok", x.mouse(input.DispatchMouseEventTypeMouseMoved, px, py, input.MouseButtonNone, 0)
	case explore.DblClick:
		if err := x.click(px, py, input.MouseButtonLeft, 1); err != nil {
			return "failed", err
		}
		return "ok", x.click(px, py, input.MouseButtonLeft, 2)
	case explore.ContextMenu:
		return "ok", x.click(px, py, input.MouseButtonRight, 1)
	default:
		return "ok", x.click(px, py, input.MouseButtonLeft, 1)
	}
}

// point scrolls an element into view and finds a point of it that the
// pointer would hit: its center, or a point between it and its corners.
func (x *explorer) point(st *state, c explore.Candidate) (float64, float64, string, error) {
	ctx, cancel := context.WithTimeout(x.e.tab, inputWait)
	defer cancel()
	if _, err := chromedp.Call(ctx, dom.ScrollIntoViewIfNeeded, dom.ScrollIntoViewIfNeededParams{BackendNodeID: c.Backend}); err != nil {
		return 0, 0, "gone", err
	}
	q, err := chromedp.Call(ctx, dom.GetContentQuads, dom.GetContentQuadsParams{BackendNodeID: c.Backend})
	if err != nil || len(q.Quads) == 0 {
		return 0, 0, "gone", err
	}
	var best dom.Quad
	bestArea := 0.0
	for _, quad := range q.Quads {
		if len(quad) != 8 {
			continue
		}
		w, h := quad[2]-quad[0], quad[5]-quad[1]
		if a := w * h; a > bestArea {
			best, bestArea = quad, a
		}
	}
	if bestArea < 1 {
		return 0, 0, "gone", nil
	}
	cx, cy := (best[0]+best[2]+best[4]+best[6])/4, (best[1]+best[3]+best[5]+best[7])/4
	points := [][2]float64{{cx, cy}, {(cx + best[0]) / 2, (cy + best[1]) / 2}, {(cx + best[4]) / 2, (cy + best[5]) / 2}}
	// Quads and input are in the view's coordinates; the hit test is in the
	// document's (measured): add how far the page is scrolled.
	var sx, sy float64
	if m, err := chromedp.Call(ctx, page.GetLayoutMetrics, cdp.Empty{}); err == nil && m.CSSVisualViewport != nil {
		sx, sy = m.CSSVisualViewport.PageX, m.CSSVisualViewport.PageY
	}
	unknown := false
	for _, p := range points {
		if p[0] < 0 || p[1] < 0 {
			continue
		}
		ignore := false
		hit, err := chromedp.Call(ctx, dom.GetNodeForLocation, dom.GetNodeForLocationParams{X: int64(p[0] + sx), Y: int64(p[1] + sy), IgnorePointerEventsNone: &ignore})
		if err != nil {
			slog.Debug("explore: hit test", "want", c.Selector, "at", fmt.Sprintf("%.0f,%.0f", p[0], p[1]), "err", err)
			continue
		}
		idx, ok := st.by[hit.BackendNodeID]
		if !ok || !st.pg.Contains(c.Node, idx) {
			what := "unknown"
			if ok {
				nd := st.pg.Nodes[idx]
				what = fmt.Sprintf("%s#%s type=%d", nd.Tag, nd.Attrs["id"], nd.Type)
			}
			slog.Debug("explore: hit", "want", c.Selector, "at", fmt.Sprintf("%.0f,%.0f", p[0], p[1]), "hit", what, "backend", hit.BackendNodeID)
		}
		switch {
		case !ok:
			unknown = true
		case st.pg.Contains(c.Node, idx):
			return p[0], p[1], "ok", nil
		}
	}
	if unknown {
		return 0, 0, "unknown", nil
	}
	return 0, 0, "covered", nil
}

func (x *explorer) mouse(t input.DispatchMouseEventType, px, py float64, b input.MouseButton, clicks int64) error {
	ctx, cancel := context.WithTimeout(x.e.tab, inputWait)
	defer cancel()
	p := input.DispatchMouseEventParams{Type: t, X: px, Y: py, Button: b, ClickCount: clicks}
	switch {
	case t == input.DispatchMouseEventTypeMousePressed && b == input.MouseButtonLeft:
		p.Buttons = 1
	case t == input.DispatchMouseEventTypeMousePressed && b == input.MouseButtonRight:
		p.Buttons = 2
	}
	if _, err := chromedp.Call(ctx, input.DispatchMouseEvent, p); err != nil {
		if ctx.Err() != nil {
			return errHung
		}
		return err
	}
	return nil
}

func (x *explorer) click(px, py float64, b input.MouseButton, clicks int64) error {
	for _, t := range []input.DispatchMouseEventType{input.DispatchMouseEventTypeMouseMoved, input.DispatchMouseEventTypeMousePressed, input.DispatchMouseEventTypeMouseReleased} {
		bb, n := b, clicks
		if t == input.DispatchMouseEventTypeMouseMoved {
			bb, n = input.MouseButtonNone, 0
		}
		if err := x.mouse(t, px, py, bb, n); err != nil {
			return err
		}
	}
	return nil
}

func (x *explorer) focus(c explore.Candidate) error {
	ctx, cancel := context.WithTimeout(x.e.tab, inputWait)
	defer cancel()
	if _, err := chromedp.Call(ctx, dom.ScrollIntoViewIfNeeded, dom.ScrollIntoViewIfNeededParams{BackendNodeID: c.Backend}); err != nil {
		return err
	}
	_, err := chromedp.Call(ctx, dom.Focus, dom.FocusParams{BackendNodeID: c.Backend})
	return err
}

// typeInto types a value the field accepts, a key at a time, so that the
// page's key and input listeners see a person typing. Fields that take no
// typing (dates) get the value set.
func (x *explorer) typeInto(c explore.Candidate) (string, error) {
	if err := x.focus(c); err != nil {
		return "gone", err
	}
	switch c.Type {
	case "date", "datetime-local", "month", "week", "time":
		if _, err := x.callString(c, "fix"); err != nil {
			return "failed", err
		}
		return "ok", nil
	}
	v, err := x.callString(c, "choose")
	if err != nil {
		return "failed", err
	}
	if err := x.keys(v); err != nil {
		return "failed", err
	}
	if ok, _ := x.callString(c, "valid"); ok == "false" {
		x.callString(c, "fix")
	}
	return "ok", nil
}

func (x *explorer) keys(v string) error {
	for _, r := range v {
		s := string(r)
		if err := x.key(input.DispatchKeyEventTypeKeyDown, s, "", 0, s); err != nil {
			return err
		}
		if err := x.key(input.DispatchKeyEventTypeKeyUp, s, "", 0, ""); err != nil {
			return err
		}
	}
	return nil
}

func (x *explorer) press(key, code string, vk int64, text string) error {
	if err := x.key(input.DispatchKeyEventTypeKeyDown, key, code, vk, text); err != nil {
		return err
	}
	return x.key(input.DispatchKeyEventTypeKeyUp, key, code, vk, "")
}

func (x *explorer) key(t input.DispatchKeyEventType, key, code string, vk int64, text string) error {
	ctx, cancel := context.WithTimeout(x.e.tab, inputWait)
	defer cancel()
	p := input.DispatchKeyEventParams{Type: t, Key: key, Code: code, WindowsVirtualKeyCode: vk, NativeVirtualKeyCode: vk, Text: text, UnmodifiedText: text}
	if _, err := chromedp.Call(ctx, input.DispatchKeyEvent, p); err != nil {
		if ctx.Err() != nil {
			return errHung
		}
		return err
	}
	return nil
}

// note adds an action for what explore does that no event the page reports
// names (a hover, a scroll): the requests that follow, with no tag of their
// own, are placed under it. Its tag is in the page's clock, as the
// reporter's are.
func (x *explorer) note(c explore.Candidate, kind string) {
	clock, err := x.evalString(c.Frame, "clock")
	if err != nil {
		return
	}
	x.e.onEvent(flow.Event{Tag: clock + ":" + kind, Type: kind, Wall: time.Now().UTC(), Trusted: true, Top: c.Frame == x.main,
		URL: x.href(), Element: &flow.Element{Tag: c.Tag, ID: c.ID, Role: c.Role, Label: c.Label, Selector: c.Selector}})
}

// scroll scrolls the page, and its scrolling boxes, to their ends until
// nothing more comes, each step an action of its own. It reports whether
// anything came.
func (x *explorer) scroll(ctx context.Context) bool {
	last, grew := "", false
	for step := 0; step < 10 && ctx.Err() == nil; step++ {
		x.note(explore.Candidate{Frame: x.main, Tag: "html", Label: "page"}, "scroll")
		sum, err := x.evalString(x.main, "scroll")
		if err != nil {
			break
		}
		x.settle(ctx)
		if sum == last {
			break // nothing came of the last step
		}
		if last != "" {
			grew = true
		}
		last = sum
		x.stats.Actions["scroll"]++
	}
	x.evalString(x.main, "top")
	return grew
}

// settle waits for what an action started: at least the explore wait,
// then until the network is quiet a moment, for 3 seconds at most. Polls
// and streams do not hold it longer; what comes later still finds its
// action by the tags it carries.
func (x *explorer) settle(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(x.e.cfg.ExploreWait):
	}
	x.e.harvest.WaitIdle(ctx, 400*time.Millisecond, 3*time.Second, 2)
}

// closePopups closes the pages the tab opened: input to the tab waits
// while a popup is open (measured). Their URLs were held as navigations.
func (x *explorer) closePopups() int {
	ctx, cancel := context.WithTimeout(x.e.tab, inputWait)
	defer cancel()
	res, err := chromedp.CallBrowser(ctx, target.GetTargets, target.GetTargetsParams{})
	if err != nil {
		return 0
	}
	byID := map[target.ID]*target.Info{}
	for _, t := range res.TargetInfos {
		byID[t.TargetID] = t
	}
	n := 0
	for _, t := range res.TargetInfos {
		if t.Type != "page" || string(t.TargetID) == x.main {
			continue
		}
		for o, hops := t, 0; o != nil && o.OpenerID != "" && hops < 16; o, hops = byID[o.OpenerID], hops+1 {
			if string(o.OpenerID) == x.main {
				chromedp.CallBrowser(ctx, target.CloseTarget, target.CloseTargetParams{TargetID: t.TargetID})
				n++
				break
			}
		}
	}
	if n > 0 && x.e.lane == 0 {
		// One tab: back to the front. With several, the others' focus is
		// emulated, and bringing one forward could close another's open
		// <select> (NEW-C5-05).
		chromedp.Call(ctx, page.BringToFront, cdp.Empty{})
	}
	return n
}

// world returns explore's isolated world in a frame, with its library.
func (x *explorer) world(frame string) (runtime.ExecutionContextID, error) {
	if id, ok := x.worlds[frame]; ok {
		return id, nil
	}
	ctx, cancel := context.WithTimeout(x.e.tab, inputWait)
	defer cancel()
	res, err := chromedp.Call(ctx, page.CreateIsolatedWorld, page.CreateIsolatedWorldParams{FrameID: cdp.FrameID(frame), WorldName: exploreWorld})
	if err != nil {
		return 0, err
	}
	if _, err := chromedp.Call(ctx, runtime.Evaluate, runtime.EvaluateParams{Expression: x.lib, ContextID: res.ExecutionContextID}); err != nil {
		return 0, err
	}
	x.worlds[frame] = res.ExecutionContextID
	return res.ExecutionContextID, nil
}

// callString calls a library function on an element, in its frame's
// world, and returns its result as a string.
func (x *explorer) callString(c explore.Candidate, fn string, args ...any) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		world, err := x.world(c.Frame)
		if err != nil {
			return "", err
		}
		ctx, cancel := context.WithTimeout(x.e.tab, inputWait)
		obj, err := chromedp.Call(ctx, dom.ResolveNode, dom.ResolveNodeParams{BackendNodeID: c.Backend, ExecutionContextID: world, ObjectGroup: exploreGroup})
		if err != nil || obj.Object == nil {
			cancel()
			delete(x.worlds, c.Frame) // the frame's document may be new
			continue
		}
		var cargs []*runtime.CallArgument
		for _, a := range args {
			b, _ := json.Marshal(a)
			cargs = append(cargs, &runtime.CallArgument{Value: b})
		}
		byValue, await := true, true
		params := runtime.CallFunctionOnParams{
			FunctionDeclaration: "function(...a) {\n//# sourceURL=" + marker.Internal + "\nreturn String(globalThis.__jshx." + fn + "(this, ...a));\n}",
			ObjectID:            obj.Object.ObjectID, Arguments: cargs, ReturnByValue: &byValue, AwaitPromise: &await,
		}
		if fn == "click" {
			ug := true
			params.UserGesture = &ug
		}
		res, err := chromedp.Call(ctx, runtime.CallFunctionOn, params)
		chromedp.Call(ctx, runtime.ReleaseObjectGroup, runtime.ReleaseObjectGroupParams{ObjectGroup: exploreGroup})
		cancel()
		if err != nil {
			return "", err
		}
		if res.ExceptionDetails != nil {
			return "", fmt.Errorf("%s: %s", fn, res.ExceptionDetails.Text)
		}
		var s string
		json.Unmarshal(res.Result.Value, &s)
		return s, nil
	}
	return "", fmt.Errorf("%s: the element is gone", fn)
}

// evalString calls a library function of a frame's world that takes no
// element.
func (x *explorer) evalString(frame, fn string) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		world, err := x.world(frame)
		if err != nil {
			return "", err
		}
		ctx, cancel := context.WithTimeout(x.e.tab, inputWait)
		byValue := true
		res, err := chromedp.Call(ctx, runtime.Evaluate, runtime.EvaluateParams{
			Expression: "String(globalThis.__jshx." + fn + "())\n//# sourceURL=" + marker.Internal, ContextID: world, ReturnByValue: &byValue,
		})
		cancel()
		if err != nil || res.ExceptionDetails != nil {
			delete(x.worlds, frame)
			continue
		}
		var s string
		json.Unmarshal(res.Result.Value, &s)
		return s, nil
	}
	return "", fmt.Errorf("%s: no world in frame %s", fn, frame)
}

func (x *explorer) href() string {
	h, _ := x.evalString(x.main, "href")
	if u, err := url.Parse(h); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return h
}

// onePixelPNG is a 1×1 transparent PNG, for file inputs that take images.
var onePixelPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
	0x42, 0x60, 0x82,
}

// sampleDICOM is a minimal Part-10 DICOM file (128-byte preamble, "DICM",
// Explicit-VR Little-Endian Transfer Syntax UID 1.2.840.10008.1.2) placed
// without an extension as IM000001 for webkitdirectory viewers that skip
// .txt/.png files (ENH-07).
func sampleDICOM() []byte {
	b := make([]byte, 128, 170)
	b = append(b, "DICM"...)
	// (0002,0000) FileMetaInformationGroupLength UL 4 = 26
	b = append(b, 0x02, 0x00, 0x00, 0x00, 'U', 'L', 0x04, 0x00, 26, 0x00, 0x00, 0x00)
	// (0002,0010) TransferSyntaxUID UI 18 = "1.2.840.10008.1.2\x00"
	b = append(b, 0x02, 0x00, 0x10, 0x00, 'U', 'I', 18, 0x00)
	b = append(b, "1.2.840.10008.1.2\x00"...)
	return b
}
