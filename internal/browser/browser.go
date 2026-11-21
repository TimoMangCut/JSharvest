// Package browser gives the rest of jsharvest a chromedp context bound to one
// tab, without caring whether Chrome was launched by us or is already running.
package browser

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
)

type Options struct {
	// Attach is the CDP endpoint of a Chrome that is already running, such as
	// http://127.0.0.1:9222. When set, the launch options below are ignored.
	Attach string
	// TabID, with Attach, is a tab that is already open to use instead of a
	// new one. It is left open, and only detached from, at the end.
	TabID target.ID

	ChromePath string
	// ProfileDir is the Chrome user data dir. Empty means a throwaway profile.
	ProfileDir string
	Headful    bool
	NoSandbox  bool
	UserAgent  string
	Proxy      string
	// HostRules maps host names, as Chrome's --host-resolver-rules: to reach
	// a staging host by name, or to test locally under real-looking names.
	HostRules string
	// NoPrediction turns off speculative loading (speculation-rules prefetch
	// and prerender), which bypasses request interception; the guard needs
	// it. It is a profile preference, so it applies to launched browsers.
	NoPrediction bool
	// Insecure accepts any TLS certificate (-insecure).
	Insecure bool
}

// Session is a browser with one tab of ours.
type Session struct {
	Tab context.Context
	// CloseTab closes our tab and leaves the connection to the browser up,
	// so that browser-level work (the guard's last answers) can still run.
	CloseTab func()
	// Close closes the tab, then the browser if we launched it, or the
	// connection if we attached to it.
	Close func()
	// LNAReset undoes the Local Network Access denial in an attached
	// Chrome (nil when launched: the browser dies with the run).
	LNAReset func()
}

// New starts or attaches to a browser and opens a tab.
func New(parent context.Context, o Options) (*Session, error) {
	var allocCtx context.Context
	var allocCancel context.CancelFunc
	var cleanup func()

	if o.Attach != "" {
		allocCtx, allocCancel = remote.NewAllocator(parent, o.Attach)
	} else {
		sweepStaleProfiles(os.TempDir(), time.Now())
		opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
		opts = append(opts, processOptions()...)
		if o.Headful {
			opts = append(opts, chromedp.Flag("headless", false), chromedp.Flag("hide-scrollbars", false))
		}
		// navigator.webdriver stays false: the flag, not the protocol, is
		// what tells a page it is automated (CF-06).
		opts = append(opts, chromedp.Flag("disable-blink-features", "AutomationControlled"))
		// --enable-automation (in chromedp's defaults) is what a browser
		// under remote control says of itself: the infobar, and switches a
		// page can tell from a person's browser. The tool drives Chrome over
		// its pipe all the same (round 25I, N0).
		opts = append(opts, chromedp.Flag("enable-automation", false))
		if o.ChromePath != "" {
			opts = append(opts, chromedp.ExecPath(o.ChromePath))
		}
		profile := o.ProfileDir
		if profile == "" && (o.NoPrediction || o.Proxy != "") {
			// The preference needs a profile to live in; make a throwaway one.
			dir, err := os.MkdirTemp("", "jsharvest-profile-")
			if err != nil {
				return nil, err
			}
			unreg := RegisterTempDir(dir)
			profile, cleanup = dir, func() {
				unreg()
				os.RemoveAll(dir)
			}
		}
		if profile != "" {
			// An error from here to the start of Chrome removes a throwaway
			// profile: nothing else would.
			drop := func() {
				if cleanup != nil {
					cleanup()
				}
			}
			if err := os.MkdirAll(profile, 0o700); err != nil {
				drop()
				return nil, fmt.Errorf("profile dir: %w", err)
			}
			if o.NoPrediction {
				if err := noPrediction(profile); err != nil {
					drop()
					return nil, fmt.Errorf("profile preferences: %w", err)
				}
			}
			// With a proxy, WebRTC must not go around it; if that cannot be
			// arranged, Chrome does not start.
			if err := webrtcPolicy(profile, o.Proxy != ""); err != nil {
				drop()
				return nil, fmt.Errorf("profile preferences (WebRTC policy): %w", err)
			}
			opts = append(opts, chromedp.UserDataDir(profile))
		}
		if o.NoSandbox {
			opts = append(opts, chromedp.NoSandbox)
		}
		if o.UserAgent != "" {
			opts = append(opts, chromedp.UserAgent(o.UserAgent))
		}
		for _, k := range slices.Sorted(maps.Keys(proxyFlags(o))) {
			opts = append(opts, chromedp.Flag(k, proxyFlags(o)[k]))
		}
		if o.HostRules != "" {
			opts = append(opts, chromedp.Flag("host-resolver-rules", o.HostRules))
		}
		if o.Insecure {
			opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
		}
		allocCtx, allocCancel = chromedp.NewExecAllocator(parent, opts...)
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if o.Attach != "" && o.TabID != "" {
		// Detach on cancel: without it chromedp closes the target, which is
		// the user's tab.
		ctx, cancel = chromedp.NewContext(allocCtx, chromedp.WithTargetID(o.TabID), chromedp.WithDetachOnCancel())
	} else {
		ctx, cancel = chromedp.NewContext(allocCtx)
	}
	closeAll := func() {
		cancel()
		allocCancel()
		if cleanup != nil {
			cleanup()
		}
	}
	// Start the browser (or connect) with a context that has no deadline, so
	// that per-action timeouts later do not take the browser down with them.
	if err := chromedp.Do(ctx); err != nil {
		closeAll()
		return nil, fmt.Errorf("start browser: %w", err)
	}
	if o.Attach == "" {
		// Not HeadlessChrome (CF-06): the tabs' captures set it on every
		// session they attach, the first tab's here, before it navigates.
		if ua := cleanUA(ctx, o); ua != nil {
			actx, acancel := context.WithTimeout(ctx, 10*time.Second)
			if err := ua.Apply(actx, true); err != nil {
				slog.Debug("user agent", "err", err)
			}
			acancel()
			ctx = context.WithValue(ctx, uaKey{}, ua)
		}
	}
	return &Session{Tab: ctx, CloseTab: cancel, Close: closeAll}, nil
}

// noPrediction sets net.network_prediction_options to 2 ("never") in the
// profile's preferences, keeping whatever else is there.
func noPrediction(profile string) error {
	path := filepath.Join(profile, "Default", "Preferences")
	prefs, err := readPrefs(path) // a file of JSON null is an empty one
	if err != nil {
		return err
	}
	netPrefs, _ := prefs["net"].(map[string]any)
	if netPrefs == nil {
		netPrefs = map[string]any{}
	}
	netPrefs["network_prediction_options"] = 2
	prefs["net"] = netPrefs
	return writePrefs(path, prefs)
}

var (
	tempCleanupsMu sync.Mutex
	tempCleanups   = map[string]func(){}
)

// RegisterTempDir registers a temporary directory to be removed if a third
// interrupt forces immediate process exit. Calling the returned function
// unregisters it once normal cleanup completes.
func RegisterTempDir(dir string) func() {
	if dir == "" {
		return func() {}
	}
	tempCleanupsMu.Lock()
	tempCleanups[dir] = func() { _ = os.RemoveAll(dir) }
	tempCleanupsMu.Unlock()
	return func() {
		tempCleanupsMu.Lock()
		delete(tempCleanups, dir)
		tempCleanupsMu.Unlock()
	}
}

// RunTempCleanups removes all currently registered temporary directories.
func RunTempCleanups() {
	tempCleanupsMu.Lock()
	fns := make([]func(), 0, len(tempCleanups))
	for k, fn := range tempCleanups {
		fns = append(fns, fn)
		delete(tempCleanups, k)
	}
	tempCleanupsMu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

const staleProfileMaxAge = 24 * time.Hour

// sweepStaleProfiles removes orphaned jsharvest-profile-* directories in
// tempDir whose mtime is older than 24h and whose SingletonLock does not
// reference a live process.
func sweepStaleProfiles(tempDir string, now time.Time) {
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "jsharvest-profile-") {
			continue
		}
		dir := filepath.Join(tempDir, name)
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() || now.Sub(fi.ModTime()) <= staleProfileMaxAge {
			continue
		}
		lockPath := filepath.Join(dir, "SingletonLock")
		if target, err := os.Readlink(lockPath); err == nil {
			if i := strings.LastIndexByte(target, '-'); i >= 0 {
				if pid, err := strconv.Atoi(target[i+1:]); err == nil && pidAlive(pid) {
					continue
				}
			}
		} else if lfi, err := os.Lstat(lockPath); err == nil && now.Sub(lfi.ModTime()) <= staleProfileMaxAge {
			continue
		}
		_ = os.RemoveAll(dir)
	}
}
