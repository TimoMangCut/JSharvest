package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// peerscore checks jsharvest authz -peers' bola.json against peer.truth.json
// (docs/gd7-bola-design.md 6.3 step 1):
//
//   - one to one: every (key without host, direction, mode) of the scenario is
//     in bola.json once with the verdict the truth says, and nothing else is
//     (an item of the truth's "excluded" list is an EXTRA the more);
//
//   - every bypass and shared item has evidence; without -reveal the report
//     says redacted, every evidence value starts with REDACTED_, and no string
//     of -secrets is in bola.json or bola.md;
//
//   - no request of bola.sent.jsonl or trials/*.http, sent as one identity,
//     carries a cookie, token or CSRF value of another person (-creds: lines
//     "user<TAB>value"), nor of anyone when sent as no identity.
//
//     testbed peerscore -truth peer.truth.json -bola <out>/<host>/authz -scenario NAME [-secrets FILE] [-creds FILE] [-reveal]
func peerscore(args []string) error {
	fset := flag.NewFlagSet("peerscore", flag.ExitOnError)
	truth := fset.String("truth", "", "peer.truth.json")
	dir := fset.String("bola", "", "the authz directory (bola.json, bola.md, bola.sent.jsonl, trials/)")
	scenario := fset.String("scenario", "", "the scenario of the truth")
	secrets := fset.String("secrets", "", "a file of secret strings, one a line: none may be in bola.json or bola.md without -reveal")
	creds := fset.String("creds", "", "a file of credentials, user<TAB>value a line: none may be sent as another identity")
	reveal := fset.Bool("reveal", false, "the run had -reveal")
	fset.Parse(args)
	r, err := peerScore(*truth, *dir, *scenario, *secrets, *creds, *reveal, os.Stdout)
	if err != nil {
		return err
	}
	if r.bad > 0 {
		return fmt.Errorf("peerscore: %d failure(s)", r.bad)
	}
	return nil
}

type peerResult struct{ ok, bad int }

type peerTruth struct {
	Excluded  []string `json:"excluded"`
	Scenarios map[string]struct {
		Peers    []string `json:"peers"`
		Relation string   `json:"relation"`
		Items    []struct {
			Key       string `json:"key"`
			Direction string `json:"direction"`
			Mode      string `json:"mode"`
			Verdict   string `json:"verdict"`
			Stopped   bool   `json:"stopped"`
		} `json:"items"`
	} `json:"scenarios"`
}

type bolaFile struct {
	Peers            []string          `json:"peers"`
	Relation         string            `json:"relation"`
	Redacted         bool              `json:"redacted"`
	StoppedEndpoints map[string]string `json:"stopped_endpoints"`
	Items            []struct {
		Key       string `json:"key"`
		Direction string `json:"direction"`
		Mode      string `json:"mode"`
		Verdict   string `json:"verdict"`
		Reason    string `json:"reason"`
		Evidence  []struct {
			Path   string `json:"path"`
			Value  string `json:"value"`
			RefVal string `json:"ref_value"`
		} `json:"evidence"`
	} `json:"items"`
}

var peerBraceRe = regexp.MustCompile(`\{[^}]*\}`)

// peerCanon is a key as the truth writes it: no host, every placeholder {}.
func peerCanon(k string) string {
	return peerBraceRe.ReplaceAllString(stripHost(k), "{}")
}

func peerLines(path string, minLen int) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); len(l) >= minLen && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

func peerScore(truthPath, dir, scenario, secretsPath, credsPath string, reveal bool, w io.Writer) (peerResult, error) {
	var res peerResult
	fail := func(f string, a ...any) {
		fmt.Fprintf(w, f+"\n", a...)
		res.bad++
	}
	var truth peerTruth
	if err := readJSON(truthPath, &truth); err != nil {
		return res, err
	}
	sc, ok := truth.Scenarios[scenario]
	if !ok {
		return res, fmt.Errorf("peerscore: no scenario %q in %s", scenario, truthPath)
	}
	var rep bolaFile
	if err := readJSON(filepath.Join(dir, "bola.json"), &rep); err != nil {
		return res, err
	}
	excluded := map[string]bool{}
	for _, k := range truth.Excluded {
		excluded[peerCanon(k)] = true
	}

	if sc.Relation != "" && rep.Relation != sc.Relation {
		fail("WRONG relation %q, want %q", rep.Relation, sc.Relation)
	}
	if len(sc.Peers) == 2 && (len(rep.Peers) != 2 || rep.Peers[0] != sc.Peers[0] || rep.Peers[1] != sc.Peers[1]) {
		fail("WRONG peers %v, want %v", rep.Peers, sc.Peers)
	}

	type id struct{ key, dir, mode string }
	want := map[id]string{}
	stopped := map[id]bool{}
	for _, it := range sc.Items {
		i := id{peerCanon(it.Key), it.Direction, it.Mode}
		want[i] = it.Verdict
		stopped[i] = it.Stopped
	}
	seen := map[id]bool{}
	for _, it := range rep.Items {
		i := id{peerCanon(it.Key), it.Direction, it.Mode}
		label := fmt.Sprintf("%s %s (%s)", i.key, i.dir, i.mode)
		switch {
		case excluded[i.key]:
			fail("EXTRA %s: an excluded endpoint was tried (%s)", label, it.Verdict)
			continue
		case seen[i]:
			fail("DUPLICATE %s", label)
			continue
		}
		seen[i] = true
		v, in := want[i]
		switch {
		case !in:
			fail("EXTRA %s: %s (%s)", label, it.Verdict, it.Reason)
		case v != it.Verdict:
			fail("WRONG %s: %s (%s), want %s", label, it.Verdict, it.Reason, v)
		default:
			res.ok++
		}
		if it.Verdict == "bypass" || it.Verdict == "shared" {
			if len(it.Evidence) == 0 {
				fail("NO EVIDENCE %s: %s without evidence", label, it.Verdict)
			}
			if !reveal {
				for _, e := range it.Evidence {
					for _, x := range []string{e.Value, e.RefVal} {
						if x != "" && !strings.HasPrefix(x, "REDACTED_") {
							fail("UNREDACTED %s: evidence %s is not REDACTED_", label, e.Path)
						}
					}
				}
			}
		}
	}
	for i := range want {
		if !seen[i] {
			fail("MISSING %s %s (%s), want %s", i.key, i.dir, i.mode, want[i])
		}
	}
	for i, st := range stopped {
		if !st {
			continue
		}
		found := false
		for k := range rep.StoppedEndpoints {
			if strings.Contains(peerCanon(k), i.key) {
				found = true
			}
		}
		if !found {
			fail("NOT STOPPED %s: not in stopped_endpoints", i.key)
		}
	}

	// The redaction.
	if !reveal && !rep.Redacted {
		fail("UNREDACTED bola.json says redacted: false without -reveal")
	}
	if reveal && rep.Redacted {
		fail("WRONG bola.json says redacted: true under -reveal")
	}
	if !reveal && secretsPath != "" {
		secret, err := peerLines(secretsPath, 8)
		if err != nil {
			return res, err
		}
		for _, f := range []string{"bola.json", "bola.md"} {
			b, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				return res, err
			}
			for _, s := range secret {
				if strings.Contains(string(b), s) {
					fail("LEAK %s carries the secret %q…", f, s[:min(len(s), 12)])
				}
			}
		}
		fmt.Fprintf(w, "peerscore: bola.json and bola.md checked for %d secrets\n", len(secret))
	}

	// Credentials: nobody sends another's.
	if credsPath != "" {
		lines, err := peerLines(credsPath, 3)
		if err != nil {
			return res, err
		}
		type cred struct{ user, val string }
		var cs []cred
		for _, l := range lines {
			if u, v, ok := strings.Cut(l, "\t"); ok && len(v) >= 8 {
				cs = append(cs, cred{u, v})
			}
		}
		scan := func(where, role, text string) {
			for _, c := range cs {
				if c.user != role && strings.Contains(text, c.val) {
					fail("LEAK %s, sent as %s, carries %s's credential %s…", where, role, c.user, c.val[:6])
				}
			}
		}
		n := 0
		if f, err := os.Open(filepath.Join(dir, "bola.sent.jsonl")); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 64<<20)
			for line := 1; sc.Scan(); line++ {
				var s struct{ Role, Purpose string }
				if json.Unmarshal(sc.Bytes(), &s) != nil {
					fail("BAD bola.sent.jsonl line %d is not JSON", line)
					continue
				}
				n++
				scan(fmt.Sprintf("bola.sent.jsonl line %d (%s)", line, s.Purpose), s.Role, sc.Text())
			}
			f.Close()
		} else {
			return res, err
		}
		files, _ := filepath.Glob(filepath.Join(dir, "trials", "*.http"))
		asRe := regexp.MustCompile(`-as-([^.]+)\.http$`)
		for _, p := range files {
			b, err := os.ReadFile(p)
			if err != nil {
				return res, err
			}
			role := "(none)"
			if m := asRe.FindStringSubmatch(p); m != nil {
				role = m[1]
			}
			n++
			scan("trials/"+filepath.Base(p), role, string(b))
		}
		fmt.Fprintf(w, "peerscore: %d sent requests checked for %d credentials\n", n, len(cs))
	}
	fmt.Fprintf(w, "peerscore %s: %d right, %d wrong\n", scenario, res.ok, res.bad)
	return res, nil
}
