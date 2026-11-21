package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type scriptsFx struct {
	root, dir string
	opts      Options
}

func newScriptsFx(t *testing.T) *scriptsFx {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "app.test", "anon")
	if err := os.MkdirAll(filepath.Join(dir, "js"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &scriptsFx{root: root, dir: dir, opts: Options{Root: root, Target: "app.test", Role: "anon"}}
}

// add writes js/<sha>.js and, when indexed, its index line.
func (f *scriptsFx) add(t *testing.T, body []byte, url string, indexed bool) string {
	t.Helper()
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(f.dir, "js", sha+".js"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if indexed {
		line, _ := json.Marshal(map[string]any{"sha256": sha, "urls": []string{url}, "size": len(body), "source": "live"})
		fh, err := os.OpenFile(filepath.Join(f.dir, "index.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		fh.Write(append(line, '\n'))
		fh.Close()
	}
	return sha
}

type readReply struct {
	Untrusted  string   `json:"untrusted"`
	SHA256     string   `json:"sha256"`
	URLs       []string `json:"urls"`
	Size       int64    `json:"size"`
	Offset     int64    `json:"offset"`
	Length     int      `json:"length"`
	NextOffset *int64   `json:"next_offset"`
	Content    string   `json:"content"`
}

type searchReply struct {
	Untrusted      string `json:"untrusted"`
	Matches        []searchHit
	TotalMatches   int `json:"total_matches"`
	ScriptsScanned int `json:"scripts_scanned"`
	Truncated      bool
	Skipped        []skippedScript
}

func callErr(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return err.Error()
	}
	if !res.IsError {
		t.Fatalf("%s %v: expected an error, got %s", name, args, res.Content[0].(*mcp.TextContent).Text)
	}
	return res.Content[0].(*mcp.TextContent).Text
}

func TestScriptToolsListed(t *testing.T) {
	cs := connect(t, Options{Root: t.TempDir()})
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]*mcp.Tool{}
	for _, tool := range list.Tools {
		found[tool.Name] = tool
	}
	for _, n := range []string{"search_scripts", "read_script"} {
		tool := found[n]
		if tool == nil {
			t.Fatalf("%s not listed", n)
		}
		if !strings.Contains(tool.Description, untrustedNote) || !strings.Contains(tool.Description, "fence:") {
			t.Errorf("%s: description lacks the untrusted/fence note: %q", n, tool.Description)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: not read-only", n)
		}
	}
}

func TestReadScriptRejectsBadSHA(t *testing.T) {
	fx := newScriptsFx(t)
	sha := fx.add(t, []byte("var a=1;"), "https://app.test/a.js", true)
	hidden := fx.add(t, []byte("var secret=1;"), "", false) // on disk, not in the index
	if err := os.WriteFile(filepath.Join(fx.root, "app.test", "passwd"), []byte("root:x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := connect(t, fx.opts)
	for _, bad := range []string{
		"../../etc/passwd",
		"../js/" + sha,
		"../../../anon/js/" + sha,
		strings.ToUpper(sha),
		sha[:63],
		sha + "0",
		sha + ".js",
		"",
		strings.Repeat("0", 64), // well-formed, not indexed
		hidden,                  // on disk but not in the index
	} {
		msg := callErr(t, cs, "read_script", map[string]any{"sha256": bad})
		if strings.Contains(msg, "root:x") || strings.Contains(msg, "var secret") || strings.Contains(msg, "var a=1") {
			t.Errorf("sha %q leaked content: %s", bad, msg)
		}
	}
	if got := call[readReply](t, cs, "read_script", map[string]any{"sha256": sha}); got.Content != "var a=1;" || got.NextOffset != nil || got.Untrusted != "target" {
		t.Fatalf("good sha: %+v", got)
	}
}

func TestReadScriptPagesByBytes(t *testing.T) {
	fx := newScriptsFx(t)
	// 5 MB on one line, with multibyte characters everywhere, so that some
	// sit on every page edge.
	var b strings.Builder
	for i := 0; b.Len() < 5<<20; i++ {
		fmt.Fprintf(&b, "var v%d=\"é€😀\";", i)
	}
	want := b.String()
	sha := fx.add(t, []byte(want), "https://app.test/big.js", true)
	cs := connect(t, Options{Root: fx.root, Target: "app.test", Role: "anon", Reveal: true})

	for _, length := range []int{0, 1, 3, 4, 7, 20000, 56 << 10} {
		if length > 0 && length < 8 && len(want) > 0 {
			// tiny pages: just the first few, then compare the prefix
			var got strings.Builder
			var off int64
			for i := 0; i < 400; i++ {
				r := call[readReply](t, cs, "read_script", map[string]any{"sha256": sha, "offset": off, "length": length})
				if r.Offset != off {
					t.Fatalf("length %d: offset %d, want %d", length, r.Offset, off)
				}
				got.WriteString(r.Content)
				off += int64(len(r.Content))
				if r.NextOffset == nil || *r.NextOffset != off {
					t.Fatalf("length %d: next_offset %v, want %d", length, r.NextOffset, off)
				}
				if r.Length != len(r.Content) {
					t.Fatalf("length field %d != %d", r.Length, len(r.Content))
				}
			}
			if !strings.HasPrefix(want, got.String()) {
				t.Fatalf("length %d: pages are not a prefix of the file", length)
			}
			continue
		}
		var got strings.Builder
		var off int64
		pages := 0
		for {
			args := map[string]any{"sha256": sha, "offset": off}
			if length > 0 {
				args["length"] = length
			}
			r := call[readReply](t, cs, "read_script", args)
			if r.Size != int64(len(want)) || r.Offset != off {
				t.Fatalf("size/offset: %+v", r)
			}
			if length > 0 && r.Length > length {
				t.Fatalf("page of %d bytes over length %d", r.Length, length)
			}
			got.WriteString(r.Content)
			pages++
			if r.NextOffset == nil {
				break
			}
			off = *r.NextOffset
			if length == 20000 && pages > 600 {
				t.Fatal("too many pages")
			}
		}
		if got.String() != want {
			t.Fatalf("length %d: pages (%d) do not rebuild the file", length, pages)
		}
	}
	// An offset in the middle of a character starts at the next one.
	i := strings.Index(want, "é") + 1
	r := call[readReply](t, cs, "read_script", map[string]any{"sha256": sha, "offset": i, "length": 10})
	if r.Offset != int64(i+1) || !strings.HasPrefix(r.Content, "€") {
		t.Fatalf("mid-character offset: %+v", r)
	}
	if msg := callErr(t, cs, "read_script", map[string]any{"sha256": sha, "offset": len(want)}); !strings.Contains(msg, "past the end") {
		t.Fatalf("offset at end: %s", msg)
	}
}

func TestScriptSecretsRedacted(t *testing.T) {
	fx := newScriptsFx(t)
	const (
		jwt       = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
		stripePub = "pk_live_51N1A2B3C4D5E6F7G8H9I0J1K"
		// Split synthetic prefix in source to avoid false positives from repo secret scanners.
		sgKey     = "SG" + ".a1B2c3D4e5F6g7H8i9J0k1." + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V"
		ghPat     = "github_pat_11ABCDEFG0a1B2c3D4e5F6_g7H8i9J0k1L2m3N4"
		mapboxTok = "pk.eyJ1IjoiZGVtb3VzZXIiLCJhIjoiY2x4MTIzNDUifQ.a1B2c3D4e5F6g7H8i9J0k1"
		sentryDSN = "https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o450123.ingest.sentry.io/450999"
	)
	body := `var k="AKIAIOSFODNN7EXAMPLE";var h="Bearer ` + jwt + `";var g="Bearer abcdefghij0123456789";` +
		`var st="` + stripePub + `";var sg="` + sgKey + `";var gh="` + ghPat + `";var mb="` + mapboxTok + `";var sn="` + sentryDSN + `";var ok="plain";`
	sha := fx.add(t, []byte(body), "https://app.test/k.js", true)
	secrets := []string{"AKIAIOSFODNN7EXAMPLE", jwt, "abcdefghij0123456789", stripePub, sgKey, ghPat, mapboxTok, "a1b2c3d4e5f60718293a4b5c6d7e8f90"}

	cs := connect(t, fx.opts)
	r := call[readReply](t, cs, "read_script", map[string]any{"sha256": sha})
	for _, sec := range secrets {
		if strings.Contains(r.Content, sec) {
			t.Errorf("read_script leaks %q: %s", sec, r.Content)
		}
	}
	if !strings.Contains(r.Content, "REDACTED_") || !strings.Contains(r.Content, `"plain"`) {
		t.Errorf("content: %s", r.Content)
	}
	for _, q := range []string{"AKIA", "Bearer", "pk_live_", "SG.", "github_pat_", "sentry.io"} {
		s := call[searchReply](t, cs, "search_scripts", map[string]any{"query": q})
		if len(s.Matches) == 0 {
			t.Fatalf("no match for %s", q)
		}
		for _, m := range s.Matches {
			for _, sec := range secrets {
				if strings.Contains(m.Snippet, sec) {
					t.Errorf("search %q leaks %q: %s", q, sec, m.Snippet)
				}
			}
		}
	}

	o := fx.opts
	o.Reveal = true
	cs2 := connect(t, o)
	if r := call[readReply](t, cs2, "read_script", map[string]any{"sha256": sha}); r.Content != body {
		t.Fatalf("reveal: %s", r.Content)
	}
	if s := call[searchReply](t, cs2, "search_scripts", map[string]any{"query": "AKIA"}); !strings.Contains(s.Matches[0].Snippet, secrets[0]) {
		t.Fatalf("reveal search: %+v", s.Matches)
	}
}

func TestSearchScripts(t *testing.T) {
	fx := newScriptsFx(t)
	a := fx.add(t, []byte(`fetch("/api/users");fetch("/api/orders");`), "https://app.test/a.js", true)
	fx.add(t, []byte(`x="/api/other"`), "https://cdn.test/b.js", true)
	fx.add(t, []byte(`"/api/hidden"`), "", false)
	cs := connect(t, fx.opts)

	s := call[searchReply](t, cs, "search_scripts", map[string]any{"query": "/api/"})
	if s.TotalMatches != 3 || s.ScriptsScanned != 2 || s.Truncated {
		t.Fatalf("%+v", s)
	}
	if m := s.Matches[0]; m.SHA256 != a || m.URL != "https://app.test/a.js" || m.Offset != 7 || !strings.Contains(m.Snippet, "/api/users") {
		t.Fatalf("match: %+v", m)
	}
	s = call[searchReply](t, cs, "search_scripts", map[string]any{"query": "/api/", "url_contains": "cdn.test"})
	if s.TotalMatches != 1 || s.ScriptsScanned != 1 {
		t.Fatalf("url_contains: %+v", s)
	}
	s = call[searchReply](t, cs, "search_scripts", map[string]any{"query": "/api/", "limit": 2})
	if len(s.Matches) != 2 || !s.Truncated {
		t.Fatalf("limit: %+v", s)
	}
	s = call[searchReply](t, cs, "search_scripts", map[string]any{"query": `/api/(users|orders)`, "regex": true, "context": 5})
	if s.TotalMatches != 2 || len(s.Matches[0].Snippet) > 20+len("/api/users") {
		t.Fatalf("regex: %+v", s)
	}
	for _, bad := range []map[string]any{{"query": "a"}, {"query": strings.Repeat("a", 201)}, {"query": "(", "regex": true}, {}} {
		callErr(t, cs, "search_scripts", bad)
	}
}

func TestSearchScriptsHostileRegex(t *testing.T) {
	fx := newScriptsFx(t)
	fx.add(t, []byte(strings.Repeat("a", 2<<20)+"!"), "https://app.test/a.js", true)
	cs := connect(t, fx.opts)
	done := make(chan searchReply, 1)
	go func() {
		done <- call[searchReply](t, cs, "search_scripts", map[string]any{"query": "(a+)+$", "regex": true})
	}()
	select {
	case s := <-done:
		if s.ScriptsScanned != 1 {
			t.Fatalf("%+v", s)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the regular expression hung the search")
	}
}
