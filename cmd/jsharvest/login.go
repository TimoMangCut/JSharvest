package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/browser"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// sessionNameRe names cookies that usually carry a session, for a login
// whose cookies cannot be compared with those before (-attach).
var sessionNameRe = regexp.MustCompile(`(?i)sess|sid|auth|token|jwt|login|remember|identity`)

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	start := fs.String("u", "", "the page to log in from (the login page, or one that leads to it)")
	role := fs.String("role", "user", "role the login is for; crawl -role uses it")
	profiles := fs.String("profiles", env("JSHARVEST_PROFILES", "profiles"), "profiles root: the login goes to <profiles>/<host>/<role> (env JSHARVEST_PROFILES)")
	profile := fs.String("profile", "", "Chrome user data dir to keep the login in, instead of <profiles>/<host>/<role>")
	steps := fs.String("steps", "", `login script (JSON: goto, type, click, wait; "${NAME}" is the environment variable NAME); runs headless, and lets crawl log in again when the session is lost`)
	attach := fs.String("attach", "", "take the login from a running Chrome where you are logged in already (its CDP endpoint)")
	checkURL := fs.String("check-url", "", "a URL that answers 2xx only when logged in (e.g. /api/me); default: the page the login ends on")
	checkText := fs.String("check-text", "", "text a logged-in page shows")
	scopeMode := fs.String("scope", "rdn", "rdn or fqdn: whose cookies belong to the target")
	chrome := fs.String("chrome", env("JSHARVEST_CHROME", ""), "Chrome binary (env JSHARVEST_CHROME)")
	noSandbox := fs.Bool("no-sandbox", envBool("JSHARVEST_NO_SANDBOX"), "pass --no-sandbox to Chrome (containers)")
	hostRules := fs.String("host-resolver-rules", env("JSHARVEST_HOST_RESOLVER_RULES", ""), "Chrome host resolver rules")
	insecure := fs.Bool("insecure", false, "accept any TLS certificate (a self-signed lab or staging target), as crawl -insecure")
	var guardAllow multiFlag
	fs.Var(&guardAllow, "guard-allow", "regexp of a URL crawl -role lets through the guard (a BFF refresh call), saved with the login; repeatable. Must begin ^https?://<host of the target>/ with the host escaped")
	verbose := fs.Bool("v", false, "debug logging")
	waitLock := waitLockFlag(fs)
	fs.Parse(args)
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	if *start == "" {
		return errors.New("login: -u is required")
	}
	u, err := parseTarget(*start)
	if err != nil {
		return err
	}
	if !roleRe.MatchString(*role) || strings.Contains(*role, "..") {
		return fmt.Errorf("bad role %q", *role)
	}
	in, err := scope.New(u.Hostname(), *scopeMode)
	if err != nil {
		return err
	}
	// Fail closed: a rule that is not anchored to the target's origin is
	// refused, and nothing is saved.
	for _, re := range guardAllow {
		if err := guard.AnchoredAllow(re, in); err != nil {
			return fmt.Errorf("login: -guard-allow refused, nothing saved: %w", err)
		}
	}
	dir := *profile
	if dir == "" {
		dir = filepath.Join(*profiles, scope.TargetDir(u), *role)
	}
	// The profile is the login's: one login writes it at a time.
	unlock, err := lockDirs("login", *waitLock, dir)
	if err != nil {
		return err
	}
	defer unlock()
	var script []session.Step
	if *steps != "" {
		if script, err = session.ReadSteps(*steps); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bo := browser.Options{ChromePath: *chrome, NoSandbox: *noSandbox, HostRules: *hostRules, Insecure: *insecure}
	switch {
	case *attach != "":
		bo.Attach = *attach
	default:
		// The login is kept in the profile crawl will use; a person logs
		// in in a window, a script headless.
		bo.ProfileDir, bo.Headful = dir, script == nil
	}
	sess, err := browser.New(ctx, bo)
	if err != nil {
		return err
	}
	defer sess.Close()
	tab := sess.Tab

	cookies := func() []*network.Cookie {
		c, cancel := context.WithTimeout(tab, 15*time.Second)
		defer cancel()
		res, err := chromedp.CallBrowser(c, storage.GetCookies, storage.GetCookiesParams{})
		if err != nil {
			slog.Warn("read cookies", "err", err)
			return nil
		}
		return session.InScope(res.Cookies, in)
	}
	snap := &session.Snapshot{Target: u.String(), Role: *role, LoginURL: u.String(), Storage: map[string]session.Storage{}, GuardAllow: []string(guardAllow)}
	keep := func() { // the storage of the page the tab is on, by origin
		c, cancel := context.WithTimeout(tab, 10*time.Second)
		defer cancel()
		v, err := chromedp.Run(c, chromedp.Evaluate[json.RawMessage](session.StorageScript))
		if err != nil {
			return
		}
		var st struct {
			Origin  string            `json:"origin"`
			Local   map[string]string `json:"local"`
			Session map[string]string `json:"session"`
		}
		if json.Unmarshal(v, &st) == nil && strings.HasPrefix(st.Origin, "http") {
			if su, err := url.Parse(st.Origin); err == nil && in(su.Hostname()) {
				snap.Storage[st.Origin] = session.Storage{Local: st.Local, Session: st.Session}
			}
		}
		if loc, err := chromedp.Run(c, chromedp.Location()); err == nil && strings.HasPrefix(loc, "http") {
			snap.FinalURL = loc
		}
		if ua, err := chromedp.Run(c, chromedp.Evaluate[string]("navigator.userAgent")); err == nil && ua != "" {
			snap.UserAgent = ua
		}
	}

	var before []*network.Cookie
	navigate := func(to string) error {
		c, cancel := context.WithTimeout(tab, 30*time.Second)
		defer cancel()
		return chromedp.Do(c, chromedp.Navigate(to))
	}
	switch {
	case *attach != "":
		// Logged in already: open the target in a tab of its own to read
		// its storage; the cookies are the browser's.
		if err := navigate(u.String()); err != nil {
			return fmt.Errorf("open %s: %w", u, err)
		}
		time.Sleep(time.Second)
		keep()
	case script != nil:
		before = cookies()
		if script[0].Do != "goto" {
			if err := navigate(u.String()); err != nil {
				return fmt.Errorf("open %s: %w", u, err)
			}
		}
		if err := session.Run(tab, script, 30*time.Second); err != nil {
			return err
		}
		time.Sleep(time.Second) // what the login's last page stores on load
		keep()
		if abs, err := filepath.Abs(*steps); err == nil {
			snap.Steps = abs
		}
	default:
		before = cookies()
		if err := navigate(u.String()); err != nil {
			return fmt.Errorf("open %s: %w", u, err)
		}
		fmt.Fprintf(os.Stderr, "Log in as %s in the browser window, then press Enter here.\n", *role)
		// Enter on stdin, or the tab closed. A stdin already at its end
		// (docker run without -i, -d, a pipe) is no Enter: nobody logged in.
		done := make(chan struct{})
		eof := make(chan struct{})
		go func() {
			if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
				close(eof)
				return
			}
			close(done)
		}()
		closed := make(chan struct{})
		go func() {
			for ev, err := range chromedp.BrowserEvents(tab, target.TargetDestroyed) {
				if err != nil || ev.TargetID == chromedp.FromContext(tab).Target.TargetID {
					close(closed)
					return
				}
			}
		}()
		tick := time.NewTicker(2 * time.Second)
	wait:
		for {
			select {
			case <-done:
				keep()
				break wait
			case <-eof:
				fmt.Fprintln(os.Stderr, "stdin is closed, so no Enter can come (docker run needs -it): close the browser tab when you are logged in")
				eof = nil
			case <-closed:
				break wait // the last snapshot of the storage is what there is
			case <-ctx.Done():
				return ctx.Err()
			case <-tick.C:
				keep()
			}
		}
		tick.Stop()
	}

	after := cookies()
	snap.Cookies, snap.Saved = after, time.Now().UTC()
	if *attach != "" {
		for _, c := range after {
			if sessionNameRe.MatchString(c.Name) && c.Value != "" {
				snap.Signs.Cookies = append(snap.Signs.Cookies, c.Name)
				snap.Signs.Keys = append(snap.Signs.Keys, c.Domain+"|"+c.Name)
			}
		}
	} else {
		snap.Signs.Cookies = session.NewCookies(before, after)
		snap.Signs.Keys = session.NewCookieKeys(before, after)
	}
	snap.Signs.CheckURL, snap.Signs.CheckText = *checkURL, *checkText
	if snap.Signs.CheckURL == "" && snap.FinalURL != "" && strings.TrimRight(urlPath(snap.FinalURL), "/") != strings.TrimRight(u.Path, "/") {
		snap.Signs.CheckURL = snap.FinalURL
	}
	if c := snap.Signs.CheckURL; c != "" && !strings.HasPrefix(c, "http") {
		if ref, err := u.Parse(c); err == nil {
			snap.Signs.CheckURL = ref.String()
		}
	}
	if len(snap.Signs.Cookies) == 0 && snap.Signs.CheckURL == "" {
		return errors.New("login: no cookie changed and no page to check: nothing tells a logged-in browser; give -check-url")
	}
	if err := snap.Save(dir); err != nil {
		return err
	}
	origins := make([]string, 0, len(snap.Storage))
	for o := range snap.Storage {
		origins = append(origins, o)
	}
	slog.Info("login saved", "profile", dir, "cookies", len(after), "signs", snap.Signs.Cookies, "check_url", traffic.LogURL(snap.Signs.CheckURL),
		"storage", origins, "script", snap.Steps != "")
	return nil
}

func urlPath(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Path
	}
	return ""
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
