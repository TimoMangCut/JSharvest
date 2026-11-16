package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// verifycheck is gate 18's checker (testbed/verify-check.sh) on a verify
// of verify-app: each route's verdict, what reached the server (-log, the
// server's lines of the run), and the drafts.
//
//	-mode read   the default run: no write reaches the server
//	-mode write  -allow-write: the POST sent, its missing field read
//	-mode dry    -dry-run: nothing reaches the server, every draft planned
func verifycheck(args []string) error {
	fs := flag.NewFlagSet("verifycheck", flag.ExitOnError)
	dir := fs.String("dir", "", "the role's verify directory (…/127.0.0.1/anon/verify)")
	logPath := fs.String("log", "", "the server's log lines of the run")
	mode := fs.String("mode", "read", "read, write or dry")
	fs.Parse(args)
	failed := 0
	check := func(name string, ok bool, detail string) {
		if ok {
			fmt.Printf("  pass  %s\n", name)
			return
		}
		failed++
		fmt.Printf("  FAIL  %s: %s\n", name, detail)
	}
	var rep struct {
		Results []struct {
			Path           string   `json:"path"`
			Verdict        string   `json:"verdict"`
			Reason         string   `json:"reason"`
			Sent           string   `json:"sent"`
			URL            string   `json:"url"`
			VerifiedMethod string   `json:"verified_method"`
			Missing        []string `json:"server_missing_params"`
		} `json:"results"`
		Canaries []struct {
			URL string `json:"url"`
		} `json:"canaries"`
	}
	b, err := os.ReadFile(filepath.Join(*dir, "verify.json"))
	if err == nil {
		err = json.Unmarshal(b, &rep)
	}
	if err != nil {
		return err
	}
	byPath := map[string]int{}
	for i, r := range rep.Results {
		byPath[r.Path] = i
	}
	verdict := func(p string) (string, int) {
		i, ok := byPath[p]
		if !ok {
			return "(none)", -1
		}
		return rep.Results[i].Verdict, i
	}
	logb, _ := os.ReadFile(*logPath)
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(logb))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	reached := func(sub string) int {
		n := 0
		for _, l := range lines {
			if strings.Contains(l, sub) {
				n++
			}
		}
		return n
	}
	if *mode == "dry" {
		check("dry run: no request reached the server", reached(" GET ")+reached(" POST ")+reached(" OPTIONS ")+reached(" DELETE ") == 0,
			strings.Join(lines, "; "))
		for _, r := range rep.Results {
			if r.Verdict != "planned" && r.Verdict != "skipped" {
				check("dry run: "+r.Path+" planned", false, r.Verdict)
			}
		}
	} else {
		want := map[string]string{
			"/opaque/profile":         "auth_wall_opaque",
			"/walled/admin":           "verified_alive",
			"/spa/settings":           "dead_or_fp",
			"/api/v1/ghost":           "dead_or_fp",
			"/api/v1/tenants/{}":      "resource_404",
			"/api/v1/orders":          "verified_alive",
			"/api/v1/items":           "verified_alive",
			"/api/v1/boom":            "server_error",
			"/docs-only/ping":         "verified_alive",
			"/api/third":              "skipped",
			"/api/steal":              "skipped",
			"/api/v1/logout":          "skipped",
			"/api/v1/orders/{}/purge": "skipped",
		}
		for p, w := range want {
			got, i := verdict(p)
			detail := got
			if i >= 0 {
				detail += " (" + rep.Results[i].Reason + ")"
			}
			check(fmt.Sprintf("%-26s %s", p, w), got == w, detail)
		}
		if _, i := verdict("/api/v1/tenants/{}"); i >= 0 {
			check("the tenant's sample id is a UUID", strings.Contains(rep.Results[i].URL, "00000000-0000-0000-0000-000000000001"), rep.Results[i].URL)
		}
		check("no third party, logout or destructive URL reached the server",
			reached("/api/third")+reached("/api/steal")+reached("/logout")+reached("/purge") == 0, "")
		// Canaries are random route-like slugs (round 25I): the ones
		// verify.json lists, as the server saw them.
		canaries := 0
		for _, c := range rep.Canaries {
			if u, err := url.Parse(c.URL); err == nil && reached(" "+u.Path) > 0 {
				canaries++
			}
		}
		check("canaries asked", canaries >= 5, fmt.Sprint(canaries))
		check("no request names the tool", reached("jsharvest") == 0, "")
		_, i := verdict("/api/v1/orders")
		switch *mode {
		case "read":
			check("read-only: no write reached the server", reached(" POST ")+reached(" PUT ")+reached(" PATCH ")+reached(" DELETE ") == 0, "")
			check("orders: probed with a GET, its method from Allow", i >= 0 && rep.Results[i].Sent == "GET" && rep.Results[i].VerifiedMethod == "POST",
				fmt.Sprintf("%+v", rep.Results[i]))
		case "write":
			check("-allow-write: the one POST sent", reached(" POST /api/v1/orders") == 1 && reached(" DELETE ") == 0, fmt.Sprint(reached(" POST ")))
			check("orders: the server's missing field read", i >= 0 && slices.Equal(rep.Results[i].Missing, []string{"warehouse_id"}),
				fmt.Sprintf("%+v", rep.Results[i]))
		}
	}
	// The drafts: each file reads as a request.
	files, _ := filepath.Glob(filepath.Join(*dir, "drafts", "*.http"))
	bad := 0
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw))); err != nil {
			bad++
		}
		if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o600 {
			bad++
		}
	}
	check("drafts read as requests, 0600", len(files) > 0 && bad == 0, fmt.Sprintf("%d files, %d bad", len(files), bad))
	if failed > 0 {
		return errors.New("verifycheck: failed")
	}
	fmt.Println("verifycheck: all pass")
	return nil
}
