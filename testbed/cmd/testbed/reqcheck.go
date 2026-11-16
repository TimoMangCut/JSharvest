package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
)

// reqcheck compares the testbed's request log with jsharvest's
// requests.jsonl, both ways:
//
//   - complete: every request the server saw is in requests.jsonl as one
//     that went over the network (in api mode, static files are left out,
//     as jsharvest leaves them out); this also catches a held-back request
//     that reached the server;
//
//   - true: every request requests.jsonl says reached the server over the
//     network is in the server's log.
//
//     testbed reqcheck -log server.log -requests out/127.0.0.1/anon/requests.jsonl [-all]
func reqcheck(args []string) error {
	fset := flag.NewFlagSet("reqcheck", flag.ExitOnError)
	logPath := fset.String("log", "", "the server log lines of this run")
	reqPath := fset.String("requests", "", "requests.jsonl")
	all := fset.Bool("all", false, "jsharvest ran with -record all: static files count too")
	hosts := fset.String("host", "127.0.0.1:8770,localhost:8770", "the testbed's host:port as the browser saw it, comma-separated (localhost is the cross-site alias)")
	run := fset.String("run", "", "only the lines of this run id (default: the last run in the file)")
	fset.Parse(args)
	if *logPath == "" || *reqPath == "" {
		return fmt.Errorf("-log and -requests are required")
	}

	server := map[string]int{}
	f, err := os.Open(*logPath)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// 2026/11/03 10:00:00 200 GET /path?q
		fields := strings.Fields(sc.Text())
		if len(fields) != 5 {
			continue // the startup line, the websocket note
		}
		key := fields[3] + " " + fields[4]
		if !*all && static(fields[4]) {
			continue
		}
		server[key]++
	}
	f.Close()

	type entry struct {
		Run      string `json:"run"`
		CDPID    string `json:"cdp_id"`
		Hop      int    `json:"hop"`
		Target   string `json:"target"`
		Method   string `json:"method"`
		URL      string `json:"url"`
		Outcome  string `json:"outcome"`
		Response *struct {
			Source string `json:"source"`
		} `json:"response"`
	}
	var entries []entry
	f, err = os.Open(*reqPath)
	if err != nil {
		return err
	}
	sc = bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	last := ""
	for sc.Scan() {
		var e entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			f.Close()
			return fmt.Errorf("requests.jsonl: %w", err)
		}
		entries = append(entries, e)
		last = e.Run
	}
	f.Close()
	if err := sc.Err(); err != nil {
		return err
	}
	if *run == "" {
		*run = last
	}

	logged := map[string]int{}  // may have reached the server, as far as the log can tell
	network := map[string]int{} // answered by the server over the network
	outcomes := map[string]int{}
	ids := map[string]int{} // a request is one line, even when two sources saw it
	for _, e := range entries {
		if e.Run != *run {
			continue
		}
		if e.CDPID != "" {
			ids[fmt.Sprintf("%s#%d %s %s", e.CDPID, e.Hop, e.Method, e.URL)]++
		}
		outcomes[strings.SplitN(e.Outcome, ":", 2)[0]]++
		u, err := url.Parse(e.URL)
		if err != nil || !slices.Contains(strings.Split(*hosts, ","), u.Host) {
			continue
		}
		key := e.Method + " " + u.RequestURI()
		// What may have reached the server: not held back, and not answered
		// by a cache or a service worker (which would hide a request that
		// the service worker's own session missed). A held-back request that
		// still reached the server has no line here, so it shows as missing.
		if !strings.HasPrefix(e.Outcome, "held_back") && (e.Response == nil || e.Response.Source == "network") {
			logged[key]++
		}
		if (e.Outcome == "ok" || e.Outcome == "redirect") && e.Response != nil && e.Response.Source == "network" {
			network[key]++
		}
	}

	var missing, invented []string
	for k, n := range server {
		if logged[k] < n {
			missing = append(missing, fmt.Sprintf("%s (server %d, log %d)", k, n, logged[k]))
		}
	}
	for k, n := range network {
		if !*all && static(strings.SplitN(k, " ", 2)[1]) {
			// Left out of the server count above; compare against the raw log.
			continue
		}
		if server[k] < n {
			invented = append(invented, fmt.Sprintf("%s (log %d, server %d)", k, n, server[k]))
		}
	}
	var dups []string
	for k, n := range ids {
		if n > 1 {
			dups = append(dups, fmt.Sprintf("%s (%d lines)", k, n))
		}
	}
	sort.Strings(missing)
	sort.Strings(invented)
	sort.Strings(dups)
	total := 0
	for _, n := range server {
		total += n
	}
	fmt.Printf("run %s: server %d requests, log %d lines %v\n", *run, total, len(entries), outcomes)
	for _, m := range missing {
		fmt.Println("MISSING", m)
	}
	for _, m := range invented {
		fmt.Println("NOT ON SERVER", m)
	}
	for _, m := range dups {
		fmt.Println("DUPLICATE", m)
	}
	if len(missing) > 0 || len(invented) > 0 || len(dups) > 0 {
		return fmt.Errorf("reqcheck failed: %d missing, %d not on the server, %d duplicated", len(missing), len(invented), len(dups))
	}
	fmt.Println("reqcheck: ok")
	return nil
}

// static reports whether a request URI is a static file that api mode
// leaves out.
func static(uri string) bool {
	p, _, _ := strings.Cut(uri, "?")
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".mjs", ".cjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
		".woff", ".woff2", ".ttf", ".otf", ".mp4", ".webm", ".mp3", ".vtt":
		return true
	}
	return false
}
