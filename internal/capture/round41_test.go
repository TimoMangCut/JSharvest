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
