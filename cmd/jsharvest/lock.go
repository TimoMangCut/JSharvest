package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/lock"
)

// waitLockFlag is -wait-lock, on the commands that write a directory.
func waitLockFlag(fs *flag.FlagSet) *time.Duration {
	return fs.Duration("wait-lock", 0, "when another jsharvest command is writing the same output directory (or profile), wait this long for it instead of failing at once")
}

// lockDirs takes the write lock of the directories a command is about to
// write, and returns what releases it. Only the commands that write take it
// (crawl, watch, login, archive, endpoints); mcp, diff and export read, and
// a watch writes while they do. Only the command takes it, never a library
// function it calls (endpoints.Analyze at the end of a crawl).
func lockDirs(cmd string, wait time.Duration, dirs ...string) (func(), error) {
	l, err := lock.Acquire(cmd, wait, dirs...)
	if err != nil {
		return nil, err
	}
	return l.Release, nil
}

// watchTabURL is the URL of the one open tab -tab matches, as the browser at
// attach lists them: the host whose directory a watch will write.
func watchTabURL(attach, tabRe string) (*url.URL, error) {
	base := strings.TrimRight(attach, "/")
	if strings.HasPrefix(base, "ws") {
		return nil, errors.New("watch: give -attach as the http:// endpoint, which lists the tabs")
	}
	re, err := regexp.Compile(tabRe)
	if err != nil {
		return nil, fmt.Errorf("-tab: %w", err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(base + "/json/list")
	if err != nil {
		return nil, fmt.Errorf("list tabs: %w", err)
	}
	defer resp.Body.Close()
	var list []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("list tabs: %w", err)
	}
	var urls []string
	for _, t := range list {
		if t.Type == "page" && re.MatchString(t.URL) {
			urls = append(urls, t.URL)
		}
	}
	if len(urls) != 1 {
		return nil, fmt.Errorf("-tab %q matches %d tabs %v; it must match exactly one", tabRe, len(urls), urls)
	}
	u, err := url.Parse(urls[0])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("watch: the tab is on %q; open the target first, or use -open URL", urls[0])
	}
	return u, nil
}
