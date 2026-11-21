package mdsafe_test

import (
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/mdsafe"
	"github.com/TimoMangCut/JSharvest/internal/monitor"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/roles"
	"github.com/TimoMangCut/JSharvest/internal/verify"
)

func countUnescapedPipes(line string) int {
	n := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '|' {
			bs := 0
			for j := i - 1; j >= 0 && line[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 0 {
				n++
			}
		}
	}
	return n
}

func TestRound41MarkdownEscapingAndControlStrip(t *testing.T) {
	// 1. StripControls strips C0 (<0x20 except \t and \n), DEL (0x7f), and C1 (\u0080..\u009f including CSI \u009b).
	rawLog := "archive: fetched https://evil.example/\x1b[31mred\x07\x7f\u009b2Jclear\tok\nnext"
	cleanLog := mdsafe.StripControls(rawLog)
	if strings.ContainsAny(cleanLog, "\x1b\x07\x7f") || strings.ContainsRune(cleanLog, '\u009b') {
		t.Fatalf("control characters survived StripControls: %q", cleanLog)
	}
	if !strings.Contains(cleanLog, "\tok\nnext") {
		t.Fatalf("expected tab and newline preserved: %q", cleanLog)
	}

	// 2. InlineCode vs TableCode pipe handling and multi-backtick fences.
	if got := mdsafe.InlineCode("GET /a|b"); got != "`GET /a|b`" {
		t.Fatalf("InlineCode should not escape pipes outside tables: %q", got)
	}
	if got := mdsafe.TableCode("GET /a`b|c\r\nd"); got != "``GET /a`b\\|c␤d``" {
		t.Fatalf("TableCode unexpected output: %q", got)
	}

	hostileKey := "GET /api/x`y``z|col\r\n<img src=x>\x1b[31m\u009b2J"
	hostileVal := "val|injected\r\n|extra|<script>alert(1)</script>[click](javascript:1)\x1b[31m\u009b2J"

	// 3. Verify all 5 report Markdown generators keep exact table column counts and strip raw HTML / controls.
	roleMD := (&roles.Report{
		Host:      "app.example",
		Roles:     []string{"anon", "admin"},
		Generated: time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC),
		Items: []roles.Item{{
			Layer:    "endpoint",
			Class:    roles.HigherOnly,
			Key:      hostileKey,
			Lowest:   "admin",
			States:   map[string]roles.State{"anon": "none", "admin": "ok"},
			Evidence: map[string]*roles.Evidence{"admin": {Label: hostileVal}},
		}},
	}).Markdown()

	authzMD := (&replay.AuthzReport{
		Host:  "app.example",
		Roles: []string{"anon", "admin"},
		Items: []replay.AuthzItem{{
			Key:    hostileKey,
			Class:  "higher_only",
			Sample: hostileVal,
			Trials: []replay.Trial{{Role: "anon", Judgement: replay.Judgement{Verdict: replay.Bypass, Reason: hostileVal}, Status: 200, Size: 10}},
		}},
	}).Markdown()

	bolaMD := (&replay.BolaReport{
		Host:     "app.example",
		Peers:    [2]string{"alice", "bob"},
		Relation: "same-org",
		Redacted: false, // -reveal mode puts raw target e.Value in bola.md!
		Items: []replay.PeerItem{{
			Key:       hostileKey,
			Direction: "alice->bob",
			Mode:      "direct",
			Judgement: replay.Judgement{Verdict: replay.Bypass, Reason: hostileVal},
			Evidence:  []replay.EvidencePair{{Path: "$.note", Value: hostileVal}},
		}},
	}).Markdown()

	verifyMD := verify.Markdown(&verify.Report{
		Target: "app.example",
		Role:   "anon",
		Results: []verify.Result{{
			Verdict: verify.Alive,
			Method:  "GET",
			URL:     hostileKey,
			Reason:  hostileVal,
		}},
	})

	monMD := (&monitor.Result{
		Snapshot: &monitor.Snapshot{ID: "snap`1", Taken: time.Now().UTC()},
		Changes: []monitor.Change{{
			Severity: "high",
			Kind:     "endpoint_added",
			Key:      hostileKey,
			Roles:    []string{"anon"},
			Before:   hostileVal,
			After:    hostileVal,
			Reason:   hostileVal,
		}},
	}).Markdown("app.example")

	for name, md := range map[string]string{
		"roles":   roleMD,
		"authz":   authzMD,
		"bola":    bolaMD,
		"verify":  verifyMD,
		"monitor": monMD,
	} {
		if strings.Contains(md, "<script>") || strings.ContainsAny(md, "\x1b") || strings.ContainsRune(md, '\u009b') {
			t.Fatalf("%s Markdown leaked raw HTML or control chars:\n%s", name, md)
		}
		if name != "verify" && !strings.Contains(md, "```GET /api/x`y``z") {
			t.Fatalf("%s Markdown did not fence multi-backtick key with N+1 backticks:\n%s", name, md)
		}
		// Check every table row keeps a consistent unescaped pipe count with its header.
		lines := strings.Split(md, "\n")
		wantPipes := 0
		for _, ln := range lines {
			if strings.HasPrefix(ln, "|") {
				p := countUnescapedPipes(ln)
				if wantPipes == 0 {
					wantPipes = p
				} else if p != wantPipes {
					t.Fatalf("%s table row broke column count (got %d pipes, want %d): %q", name, p, wantPipes, ln)
				}
			} else {
				wantPipes = 0
			}
		}
	}
}

func TestRound41MarkdownBackslashParityAndLinks(t *testing.T) {
	// 1. InlineText must escape backslashes first so \[x\](...) and \`code\` cannot survive as live Markdown.
	if got := mdsafe.InlineText(`\[evil\](https://example.test)`); got != `\\\[evil\\\](https://example.test)` {
		t.Fatalf("InlineText unexpected link escape: %q", got)
	}
	if got := mdsafe.InlineText("`code` and \\`code\\`"); got != "\\`code\\` and \\\\\\`code\\\\\\`" {
		t.Fatalf("InlineText unexpected backtick escape: %q", got)
	}
	// Exact check: `\` -> `\\`, `[` -> `\[`, `` ` `` -> `` \` ``.
	if got := mdsafe.InlineText(`\[x\](\` + "`a`" + `)`); got != `\\\[x\\\](\\`+"\\`a\\`"+`)` {
		t.Fatalf("InlineText unexpected output: %q", got)
	}

	// 2. TableCode keeps odd backslash count before every pipe while preserving standalone backslashes.
	for _, tc := range []struct {
		in   string
		want string
	}{
		{`a|b`, "`a\\|b`"},
		{`a\|b`, "`a\\\\\\|b`"},
		{`a\\|b`, "`a\\\\\\\\\\|b`"},
		{`a\\\|b`, "`a\\\\\\\\\\\\\\|b`"},
		{`C:\Users\foo|bar`, "`C:\\Users\\foo\\|bar`"},
	} {
		if got := mdsafe.TableCode(tc.in); got != tc.want {
			t.Errorf("TableCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if p := countUnescapedPipes(mdsafe.TableCode(tc.in)); p != 0 {
			t.Errorf("TableCode(%q) produced %d unescaped pipe(s): %q", tc.in, p, mdsafe.TableCode(tc.in))
		}
	}

	// 3. All 5 report generators keep exact table column counts for backslash+pipe parity attacks (k=0..5).
	for k := 0; k <= 5; k++ {
		hostile := "pre" + strings.Repeat(`\`, k) + `|col \[evil\](https://example.test) ` + "\\`code\\`"
		roleMD := (&roles.Report{
			Host:      "app.example",
			Roles:     []string{"anon", "admin"},
			Generated: time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC),
			Items: []roles.Item{{
				Layer:    "endpoint",
				Class:    roles.HigherOnly,
				Key:      hostile,
				Lowest:   "admin",
				States:   map[string]roles.State{"anon": "none", "admin": "ok"},
				Evidence: map[string]*roles.Evidence{"admin": {Label: hostile}},
			}},
		}).Markdown()
		authzMD := (&replay.AuthzReport{
			Host:  "app.example",
			Roles: []string{"anon", "admin"},
			Items: []replay.AuthzItem{{
				Key:    hostile,
				Class:  "higher_only",
				Sample: hostile,
				Trials: []replay.Trial{{Role: "anon", Judgement: replay.Judgement{Verdict: replay.Bypass, Reason: hostile}, Status: 200, Size: 10}},
			}},
		}).Markdown()
		bolaMD := (&replay.BolaReport{
			Host:     "app.example",
			Peers:    [2]string{"alice", "bob"},
			Relation: "same-org",
			Redacted: false,
			Items: []replay.PeerItem{{
				Key:       hostile,
				Direction: "alice->bob",
				Mode:      "direct",
				Judgement: replay.Judgement{Verdict: replay.Bypass, Reason: hostile},
				Evidence:  []replay.EvidencePair{{Path: "$.note", Value: hostile}},
			}},
		}).Markdown()
		verifyMD := verify.Markdown(&verify.Report{
			Target: "app.example",
			Role:   "anon",
			Results: []verify.Result{{
				Verdict: verify.Alive,
				Method:  "GET",
				URL:     hostile,
				Reason:  hostile,
			}},
		})
		monMD := (&monitor.Result{
			Snapshot: &monitor.Snapshot{ID: "snap1", Taken: time.Now().UTC()},
			Changes: []monitor.Change{{
				Severity: "high",
				Kind:     "endpoint_added",
				Key:      hostile,
				Roles:    []string{"anon"},
				Before:   hostile,
				After:    hostile,
				Reason:   hostile,
			}},
		}).Markdown("app.example")

		for name, md := range map[string]string{
			"roles":   roleMD,
			"authz":   authzMD,
			"bola":    bolaMD,
			"verify":  verifyMD,
			"monitor": monMD,
		} {
			wantPipes := 0
			for _, ln := range strings.Split(md, "\n") {
				if strings.HasPrefix(ln, "|") {
					p := countUnescapedPipes(ln)
					if wantPipes == 0 {
						wantPipes = p
					} else if p != wantPipes {
						t.Fatalf("k=%d %s table row broke column count (got %d pipes, want %d): %q", k, name, p, wantPipes, ln)
					}
				} else {
					wantPipes = 0
				}
			}
		}
	}
}
