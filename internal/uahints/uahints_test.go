package uahints

import "testing"

func TestHints(t *testing.T) {
	linux := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
	win := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
	h := Hints(linux)
	if h["sec-ch-ua"] != `"Google Chrome";v="156", "Chromium";v="156", "Not)A;Brand";v="24"` || h["sec-ch-ua-mobile"] != "?0" || h["sec-ch-ua-platform"] != `"Linux"` {
		t.Errorf("linux: %v", h)
	}
	// The hints follow the User-Agent actually sent: a role's login on
	// Windows says Windows and its own version.
	if w := Hints(win); w["sec-ch-ua-platform"] != `"Windows"` || w["sec-ch-ua"] != `"Google Chrome";v="155", "Chromium";v="155", "Not)A;Brand";v="24"` {
		t.Errorf("windows: %v", w)
	}
	for _, ua := range []string{
		"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36",
		"Go-http-client/1.1",
	} {
		if Hints(ua) != nil {
			t.Errorf("hints for %q", ua)
		}
	}
	if got := ChromeUA("156"); ChromeMajor(got) != "156" {
		t.Errorf("ChromeUA: %q", got)
	}
}
