package capture

import (
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestAPIStatusOf(t *testing.T) {
	resp := func(status int64, h network.Headers) *network.Response {
		return &network.Response{URL: "http://a.test/api/x", Status: status, Headers: h}
	}
	for _, c := range []struct {
		name      string
		ev        *network.EventResponseReceived
		ok, guard bool
		status    int
	}{
		{"xhr", &network.EventResponseReceived{Type: network.ResourceTypeXHR, Response: resp(401, nil)}, true, false, 401},
		{"fetch guard", &network.EventResponseReceived{Type: network.ResourceTypeFetch, Response: resp(200, network.Headers{"x-jsharvest-guard": "write"})}, true, true, 200},
		{"document", &network.EventResponseReceived{Type: network.ResourceTypeDocument, Response: resp(401, nil)}, false, false, 0},
		{"script", &network.EventResponseReceived{Type: network.ResourceTypeScript, Response: resp(200, nil)}, false, false, 0},
		{"sw", &network.EventResponseReceived{Type: network.ResourceTypeFetch, Response: func() *network.Response { r := resp(200, nil); r.FromServiceWorker = true; return r }()}, false, false, 0},
		{"cache", &network.EventResponseReceived{Type: network.ResourceTypeXHR, Response: func() *network.Response { r := resp(200, nil); r.FromDiskCache = true; return r }()}, false, false, 0},
		{"nil", nil, false, false, 0},
	} {
		_, st, g, ok := apiStatusOf(c.ev)
		if ok != c.ok || g != c.guard || st != c.status {
			t.Errorf("%s: got status=%d guard=%v ok=%v", c.name, st, g, ok)
		}
	}
}
