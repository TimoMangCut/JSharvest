package capture

import (
	"strings"
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestLNADenied(t *testing.T) {
	denied := &network.EventLoadingFailed{CorsErrorStatus: &network.CorsErrorStatus{CorsError: network.CorsErrorLocalNetworkAccessPermissionDenied}}
	if d, i := lnaRefused(denied); !d || i {
		t.Error("LNA denial not recognised")
	}
	insecure := &network.EventLoadingFailed{CorsErrorStatus: &network.CorsErrorStatus{CorsError: network.CorsErrorInsecureLocalNetwork}}
	if d, i := lnaRefused(insecure); d || !i {
		t.Error("an insecure page's LNA refusal not recognised")
	}
	for _, ev := range []*network.EventLoadingFailed{
		{ErrorText: "net::ERR_BLOCKED_BY_CLIENT"},
		{CorsErrorStatus: &network.CorsErrorStatus{CorsError: network.CorsErrorInvalidLocalNetworkAccess}},
	} {
		if d, i := lnaRefused(ev); d || i {
			t.Errorf("%+v is not an LNA denial", ev)
		}
	}
}

func TestNoteLNADenied(t *testing.T) {
	c := &Capture{}
	for i := 0; i < 8; i++ {
		c.noteLNADenied("http://127.0.0.1:8771/lan/"+string(rune('a'+i)), false)
	}
	c.noteLNADenied("http://127.0.0.1:8771/lan/a", true)
	c.noteLNADenied("http://x/"+strings.Repeat("z", 500), false)
	s := c.Stats()
	if s.LNADenied != 9 || s.LNAInsecure != 1 || len(s.LNASamples) != maxLNASamples {
		t.Fatalf("denied %d insecure %d samples %d", s.LNADenied, s.LNAInsecure, len(s.LNASamples))
	}
	// A long URL is cut when it is kept.
	c2 := &Capture{}
	c2.noteLNADenied("http://x/"+strings.Repeat("z", 500), false)
	if got := c2.Stats().LNASamples[0]; len([]rune(got)) > maxLNAURL+1 {
		t.Errorf("not cut: %d", len(got))
	}
}
