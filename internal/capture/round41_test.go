package capture

import (
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestRound41ReloginBodyAndDelayedSweepRedacted(t *testing.T) {
	const opPass = "OperatorS3cretPass!42"
	const opToken = "OperatorBearerTok99"

	var inWindow atomic.Bool
	var got []traffic.Entry
	clk := &clock{t: time.Unix(2000, 0)}
	r := newRecorder(&session{c: &Capture{}, kind: "page"}, RecordOptions{
		Mode:            traffic.All,
		MaxBody:         4096,
		Sink:            func(e traffic.Entry) { got = append(got, e) },
		SensitiveWindow: inWindow.Load,
	})
	r.now = clk.now

	// Request 1: RequestWillBeSentExtraInfo arrives BEFORE RequestWillBeSent while
	// SensitiveWindow is active; response + sweep happen AFTER SensitiveWindow closes.
	inWindow.Store(true)
	r.onSentExtra(&network.EventRequestWillBeSentExtraInfo{
		RequestID: "login-1",
		Headers:   network.Headers{"Authorization": "Bearer " + opToken, "Cookie": "sid=" + opToken, "Content-Type": "application/json"},
	})
	r.onSent(&network.EventRequestWillBeSent{
		RequestID: "login-1",
		Type:      "Fetch",
		Timestamp: 1,
		Request: &network.Request{
			Method:          "POST",
			URL:             "https://app.example.test/api/login?client_secret=" + opPass,
			HasPostData:     true,
			PostDataEntries: []*network.PostDataEntry{{Bytes: []byte(`{"username":"alice","password":"` + opPass + `"}`)}},
		},
	})

	// Close relogin window BEFORE response finishes and BEFORE sweep runs!
	inWindow.Store(false)
	r.onResponseExtra(&network.EventResponseReceivedExtraInfo{
		RequestID:  "login-1",
		StatusCode: 200,
		Headers:    network.Headers{"Content-Type": "image/png"},
	})
	r.onResponse(&network.EventResponseReceived{
		RequestID:    "login-1",
		Type:         "Fetch",
		HasExtraInfo: true,
		Response:     &network.Response{URL: "https://app.example.test/api/login", Status: 200, MimeType: "image/png"},
	})
	r.onFinished(&network.EventLoadingFinished{RequestID: "login-1", Timestamp: 2})

	// Request 2: Sent outside SensitiveWindow -> remains unredacted and untagged.
	r.onSent(&network.EventRequestWillBeSent{
		RequestID: "normal-2",
		Type:      "Fetch",
		Timestamp: 3,
		Request: &network.Request{
			Method:          "POST",
			URL:             "https://app.example.test/api/items",
			Headers:         network.Headers{"Authorization": "Bearer target-session-tok"},
			HasPostData:     true,
			PostDataEntries: []*network.PostDataEntry{{Bytes: []byte(`{"password":"target-field-kept-when-not-redact"}`)}},
		},
	})
	r.onResponse(&network.EventResponseReceived{
		RequestID: "normal-2",
		Type:      "Fetch",
		Response:  &network.Response{URL: "https://app.example.test/api/items", Status: 200, MimeType: "image/png"},
	})
	r.onFinished(&network.EventLoadingFinished{RequestID: "normal-2", Timestamp: 4})

	clk.t = clk.t.Add(settle + time.Millisecond)
	r.sweep(false)

	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	var loginEntry, normalEntry traffic.Entry
	for _, e := range got {
		switch e.CDPID {
		case "login-1":
			loginEntry = e
		case "normal-2":
			normalEntry = e
		}
	}

	if !slices.Contains(loginEntry.Tags, "relogin") {
		t.Fatalf("login entry missing relogin tag: %+v", loginEntry.Tags)
	}
	for _, leak := range []string{opPass, opToken} {
		if strings.Contains(loginEntry.URL, leak) ||
			strings.Contains(loginEntry.Body.Body, leak) ||
			strings.Contains(loginEntry.Headers["authorization"], leak) ||
			strings.Contains(loginEntry.Headers["cookie"], leak) {
			t.Fatalf("login entry leaked %q: url=%q hdr=%v body=%q", leak, loginEntry.URL, loginEntry.Headers, loginEntry.Body.Body)
		}
	}
	if !strings.Contains(loginEntry.Body.Body, "REDACTED_") {
		t.Fatalf("expected REDACTED_ in login body, got %q", loginEntry.Body.Body)
	}
	if slices.Contains(normalEntry.Tags, "relogin") || !strings.Contains(normalEntry.Body.Body, "target-field-kept-when-not-redact") {
		t.Fatalf("normal entry outside relogin window was altered: tags=%v body=%q", normalEntry.Tags, normalEntry.Body.Body)
	}
}

func TestRound41SensitiveWindowRedactsResponseAndSharesHMAC(t *testing.T) {
	const respTok = "secret-jwt-value"
	const sidCookie = "secret-sid-42"
	const oauthCode = "oauth_secret_code_99"

	// 1. Default -redact=false (Redactor: nil), only SensitiveWindow active:
	// response body, Set-Cookie, Location, and Page are all redacted.
	var inWindow atomic.Bool
	inWindow.Store(true)
	var got []traffic.Entry
	clk := &clock{t: time.Unix(3000, 0)}
	r := newRecorder(&session{c: &Capture{}, kind: "page", targetURL: "https://idp.example.test/cb?code=" + oauthCode}, RecordOptions{
		Mode:            traffic.All,
		MaxBody:         4096,
		Sink:            func(e traffic.Entry) { got = append(got, e) },
		SensitiveWindow: inWindow.Load,
	})
	r.now = clk.now

	r.onSentExtra(&network.EventRequestWillBeSentExtraInfo{
		RequestID: "auth-1",
		Headers:   network.Headers{"cookie": "sid=" + sidCookie},
	})
	r.onSent(&network.EventRequestWillBeSent{
		RequestID:   "auth-1",
		Type:        "Fetch",
		Timestamp:   1,
		DocumentURL: "https://idp.example.test/cb?code=" + oauthCode,
		Request: &network.Request{
			Method: "POST",
			URL:    "https://app.example.test/auth/login",
		},
	})
	r.onResponseExtra(&network.EventResponseReceivedExtraInfo{
		RequestID:  "auth-1",
		StatusCode: 200,
		Headers: network.Headers{
			"content-type": "image/png",
			"set-cookie":   "sid=" + sidCookie + "; HttpOnly; Path=/",
			"location":     "https://app.example.test/done?code=" + oauthCode,
		},
	})
	r.onResponse(&network.EventResponseReceived{
		RequestID:    "auth-1",
		Type:         "Fetch",
		HasExtraInfo: true,
		Response:     &network.Response{URL: "https://app.example.test/auth/login", Status: 200, MimeType: "image/png"},
	})
	// Simulate fetched response body already stored on exchange.
	r.mu.Lock()
	r.xs["auth-1"].body = &traffic.Body{Body: `{"access_token":"` + respTok + `"}`}
	r.mu.Unlock()
	r.onFinished(&network.EventLoadingFinished{RequestID: "auth-1", Timestamp: 2})

	clk.t = clk.t.Add(settle + time.Millisecond)
	r.sweep(false)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Response == nil {
		t.Fatal("expected Response on recorded entry")
	}
	for _, secret := range []string{respTok, sidCookie, oauthCode} {
		if strings.Contains(e.Page, secret) ||
			strings.Contains(e.Response.Body.Body, secret) ||
			strings.Contains(e.Response.Headers["set-cookie"], secret) ||
			strings.Contains(e.Response.Headers["location"], secret) {
			t.Fatalf("SensitiveWindow leaked %q: page=%q respHdr=%v respBody=%q",
				secret, e.Page, e.Response.Headers, e.Response.Body.Body)
		}
	}

	// 2. Shared Redactor passed in RecordOptions produces identical HMAC tokens.
	shared := traffic.NewRedactor()
	var gotShared []traffic.Entry
	r2 := newRecorder(&session{c: &Capture{}, kind: "page"}, RecordOptions{
		Mode:            traffic.All,
		MaxBody:         4096,
		Sink:            func(e traffic.Entry) { gotShared = append(gotShared, e) },
		SensitiveWindow: inWindow.Load,
		Redactor:        shared,
	})
	r2.now = clk.now
	r2.onSent(&network.EventRequestWillBeSent{
		RequestID: "auth-2",
		Type:      "Fetch",
		Timestamp: 1,
		Request:   &network.Request{Method: "POST", URL: "https://app.example.test/auth/login?token=" + respTok},
	})
	r2.onResponse(&network.EventResponseReceived{
		RequestID: "auth-2",
		Type:      "Fetch",
		Response:  &network.Response{URL: "https://app.example.test/auth/login", Status: 200, MimeType: "image/png"},
	})
	r2.onFinished(&network.EventLoadingFinished{RequestID: "auth-2", Timestamp: 2})
	clk.t = clk.t.Add(settle + time.Millisecond)
	r2.sweep(false)
	if len(gotShared) != 1 {
		t.Fatalf("shared got %d entries, want 1", len(gotShared))
	}
	wantURL := shared.URL("https://app.example.test/auth/login?token=" + respTok)
	if gotShared[0].URL != wantURL {
		t.Fatalf("shared Redactor HMAC mismatch: got %q, want %q", gotShared[0].URL, wantURL)
	}
}
