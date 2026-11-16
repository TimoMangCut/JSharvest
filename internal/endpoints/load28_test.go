package endpoints

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// Round 28 (plan-28 2.1): the catalog read from the cache alone (export,
// the MCP tool) joins deferred URLs as the analysing catalog does: Load
// gives each script its source, for the builder another chunk exports.
func TestCatalogFromCacheJoinsDeferred(t *testing.T) {
	shared := "var tbl={app_tokens:`/auth/tokens`};var SYS=[{name:`app_users`},{name:`app_roles`}].map(e=>e.name);" +
		"function isSys(e){return e.startsWith(`app_`)?SYS.includes(e):!1}" +
		"function endpointFor(e){return e in tbl?tbl[e]:isSys(e)?`/${e.substring(4)}`:`/records/${e}`}" +
		"export{endpointFor as eF};"
	page := "import{eF as ep}from\"./shared-1a2b.js\";var api=axios.create({baseURL:`/`});" +
		"export const loadRole=id=>api.get(`${ep(`app_roles`)}/${id}`);"
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "js"), 0o700)
	os.WriteFile(filepath.Join(dir, "js", "aa.js"), []byte(shared), 0o600)
	os.WriteFile(filepath.Join(dir, "js", "bb.js"), []byte(page), 0o600)
	os.WriteFile(filepath.Join(dir, "index.jsonl"), []byte(`{"sha256":"aa","urls":["http://app.test/assets/shared-1a2b.js"]}
{"sha256":"bb","urls":["http://app.test/assets/page-9z.js"]}
`), 0o600)
	has := func(eps []Endpoint, want string) bool {
		for _, e := range eps {
			if e.Method+" "+e.Path == want {
				return true
			}
		}
		return false
	}
	analysed, err := Catalog(dir, inApp, true)
	if err != nil || !has(analysed, "GET /roles/{}") {
		t.Fatalf("analysing catalog: %v %+v", err, analysed)
	}
	cached, err := Catalog(dir, inApp, false)
	if err != nil {
		t.Fatal(err)
	}
	if !has(cached, "GET /roles/{}") {
		t.Errorf("the catalog read from the cache lost the deferred URL: %+v", cached)
	}
	ss, _ := Load(dir)
	for _, s := range ss {
		if s.Load == nil || len(s.Load()) == 0 {
			t.Errorf("%s: no source", s.SHA256)
		}
	}
}

// A cache of another extractor version is still read by Load (a reader
// cannot analyse again), and counted, so a reader can say so.
func TestLoadCountsStaleCache(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "js"), 0o700)
	os.WriteFile(filepath.Join(dir, "js", "aa.js"), []byte(`fetch("/api/x",{method:"PUT"})`), 0o600)
	os.WriteFile(filepath.Join(dir, "index.jsonl"), []byte(`{"sha256":"aa","urls":["http://app.test/a.js"]}`+"\n"), 0o600)
	if _, err := Analyze(dir, 1); err != nil {
		t.Fatal(err)
	}
	ss, _ := Load(dir)
	if st := SummarizeScripts(ss); len(ss) != 1 || st.StaleCache != 0 {
		t.Fatalf("fresh: %d scripts, %+v", len(ss), st)
	}
	old := strings.Replace(string(mustRead(t, filepath.Join(dir, CacheDir, "aa.json"))),
		`"version":`+strconv.Itoa(jsapi.Version), `"version":`+strconv.Itoa(jsapi.Version-1), 1)
	os.WriteFile(filepath.Join(dir, CacheDir, "aa.json"), []byte(old), 0o600)
	ss, _ = Load(dir)
	if st := SummarizeScripts(ss); len(ss) != 1 || st.StaleCache != 1 || len(ss[0].Endpoints) != 1 {
		t.Fatalf("stale: %d scripts, %+v", len(ss), st)
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
