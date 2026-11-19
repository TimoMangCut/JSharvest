package archive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeReqs(t *testing.T, dir string, lines ...map[string]any) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, l := range lines {
		j, _ := json.Marshal(l)
		b.Write(j)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func req(ua string, tags ...string) map[string]any {
	return map[string]any{"url": "https://example.com/x", "headers": map[string]string{"user-agent": ua}, "tags": tags,
		"response": map[string]any{"status": 200}}
}

// F1: the UA order CrawlHostsWithUA documents.
func TestRound371CrawlHostsUAOrder(t *testing.T) {
	const (
		chrome   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
		engine   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
		other    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
		portUA   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
		headless = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36"
	)
	in := func(h string) bool { return strings.HasSuffix(h, "example.com") }
	root := t.TempDir()
	role := filepath.Join(root, "example.com", "anon")
	// The role: the engine's UA many times, a browser's once: the browser wins.
	writeReqs(t, role, req(engine, "http"), req(engine, "http"), req(engine, "http"), req(chrome), req(other, "challenge"), req(headless))
	// Another role of the target: not the role's.
	writeReqs(t, filepath.Join(root, "example.com", "admin"), req(other), req(other))
	if _, _, ua := CrawlHostsWithUA(root, "example.com", role, in); ua != chrome {
		t.Errorf("role's UA = %q, want the browser's %q", ua, chrome)
	}
	// No role given: every role of the target and its host_port siblings;
	// a browser's UA before the engine's.
	writeReqs(t, filepath.Join(root, "example.com_8443", "anon"), req(portUA), req(portUA), req(portUA))
	if _, _, ua := CrawlHostsWithUA(root, "example.com", "", in); ua != portUA {
		t.Errorf("target's UA = %q, want the most sent browser UA %q (host_port sibling counted)", ua, portUA)
	}
	// A role with nothing usable falls back to the target's.
	empty := filepath.Join(root, "example.com", "user")
	writeReqs(t, empty, req(headless), req(other, "jsharvest"))
	if _, _, ua := CrawlHostsWithUA(root, "example.com", empty, in); ua == "" || ua == headless {
		t.Errorf("fallback UA = %q", ua)
	}
}
