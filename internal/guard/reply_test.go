package guard

import (
	"testing"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
)

func hdr(p fetch.FulfillRequestParams, name string) string {
	for _, h := range p.ResponseHeaders {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}

func TestFakeReply(t *testing.T) {
	xhr := &fetch.EventRequestPaused{RequestID: "1", ResourceType: network.ResourceTypeXHR}
	hs := map[string]string{"origin": "http://a.test"}
	p := fake(xhr, hs, "write")
	if p.ResponseCode != 200 || string(p.Body) != "{}" {
		t.Errorf("got %d %q, want 200 {}", p.ResponseCode, p.Body)
	}
	if hdr(p, "X-Jsharvest-Guard") != "write" || hdr(p, "Access-Control-Allow-Origin") != "http://a.test" ||
		hdr(p, "Content-Type") != "application/json" {
		t.Errorf("headers %v", p.ResponseHeaders)
	}
	doc := &fetch.EventRequestPaused{RequestID: "2", ResourceType: network.ResourceTypeDocument}
	if dp := fake(doc, nil, "write"); dp.ResponseCode != 204 || hdr(dp, "X-Jsharvest-Guard") == "" {
		t.Errorf("document: %d", dp.ResponseCode)
	}
	nav := fake(xhr, map[string]string{"sec-fetch-mode": "navigate"}, "write")
	if nav.ResponseCode != 204 {
		t.Errorf("navigation: %d", nav.ResponseCode)
	}
}
