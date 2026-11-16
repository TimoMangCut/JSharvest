package archive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

func counting(n *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(n, 1)
		w.Write([]byte("ok"))
	}))
}

// P2.3: the archive client goes where -proxy says, not where HTTPS_PROXY does.
func TestClientIgnoresEnvProxy(t *testing.T) {
	var envHits, chosenHits int32
	env, chosen := counting(&envHits), counting(&chosenHits)
	defer env.Close()
	defer chosen.Close()
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(k, env.URL)
	}
	t.Setenv("NO_PROXY", "")
	cu, _ := url.Parse(chosen.URL)
	c := newClientWith(cu, nil)
	if _, err := c.Get(context.Background(), &Budget{}, "http://archive.example.invalid/x", 1<<10); err != nil {
		t.Fatal(err)
	}
	if chosenHits != 1 || envHits != 0 {
		t.Fatalf("chosen %d, env %d", chosenHits, envHits)
	}
	// With no proxy chosen the client goes direct: the env is not read.
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("direct")) }))
	defer direct.Close()
	if a, err := newClient().Get(context.Background(), &Budget{}, direct.URL+"/x", 1<<10); err != nil || string(a.Body) != "direct" {
		t.Fatalf("%v %v", a, err)
	}
	if envHits != 0 {
		t.Fatalf("newClient followed the env proxy: %d", envHits)
	}
	// A host in the host rules does not go through the proxy.
	rules, _ := netsafe.ParseHostRules("MAP *.jsh.test 127.0.0.1")
	c = newClientWith(cu, rules)
	_, port, _ := splitHost(direct.URL)
	if a, err := c.Get(context.Background(), &Budget{}, "http://wb.jsh.test:"+port+"/x", 1<<10); err != nil || string(a.Body) != "direct" || chosenHits != 1 {
		t.Fatalf("host rules: %v %v hits %d", a, err, chosenHits)
	}
}

func splitHost(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	return u.Hostname(), u.Port(), err
}
