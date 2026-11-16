package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func connectProxy(n *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			atomic.AddInt32(n, 1)
		}
		http.Error(w, "no", http.StatusBadGateway)
	}))
}

// The webhook goes where the run's one proxy says (-proxy, JSHARVEST_PROXY,
// the environment, in netsafe.ProxyFrom's order), not where Go's own
// reading of the environment would send it.
func TestWebhookDoesNotReadTheEnvironmentItself(t *testing.T) {
	var env int32
	px := connectProxy(&env)
	defer px.Close()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(k, px.URL)
	}
	Send(context.Background(), "https://hook.example/T0/secret", &Payload{ID: "x"})
	if env != 0 {
		t.Fatalf("Send followed the environment's proxy (%d CONNECTs)", env)
	}
}

func TestWebhookThroughTheChosenProxy(t *testing.T) {
	var env, chosen int32
	pe, pc := connectProxy(&env), connectProxy(&chosen)
	defer pe.Close()
	defer pc.Close()
	t.Setenv("HTTPS_PROXY", pe.URL)
	u, _ := url.Parse(pc.URL)
	SendWith(context.Background(), "https://hook.example/T0/secret", &Payload{ID: "x"}, u)
	if chosen == 0 || env != 0 {
		t.Fatalf("chosen %d, env %d", chosen, env)
	}
}
