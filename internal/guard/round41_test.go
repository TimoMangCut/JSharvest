package guard

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
)

func TestRound41GuardAndSessionLogsMaskTokens(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	g := &Guard{
		pending: map[fetch.RequestID]*held{},
		stats:   Stats{ByReason: map[string]int{}},
	}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	rawHeld := "https://admin:s3cr3tPass@idp.example/logout?id_token_hint=" + jwt + "&post_logout_redirect_uri=/bye#access_token=" + jwt
	g.record(&fetch.EventRequestPaused{
		RequestID: "req-1",
		Request: &network.Request{
			Method: "GET",
			URL:    rawHeld,
		},
	}, nil, "", Decision{Action: Fake, Reason: "destructive-path"})

	rawWS := "wss://user:wsPass123@ws.example/stream?access_token=" + jwt + "#fragSecret"
	g.NoteWebSocket(rawWS)

	logs := buf.String()
	for _, secret := range []string{"s3cr3tPass", "wsPass123", "eyJhbGci", "fragSecret", "admin:"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("guard slog leaked %q:\n%s", secret, logs)
		}
	}
	if !strings.Contains(logs, "post_logout_redirect_uri=/bye") {
		t.Fatalf("expected non-sensitive param preserved in guard log:\n%s", logs)
	}
	// Disk record keeps full URL until explicit Redact() when -redact is on.
	if len(g.records) != 1 || g.records[0].URL != rawHeld {
		t.Fatalf("expected raw record URL preserved before Redact, got %+v", g.records)
	}
}

func TestRound41LANOnlyRulesPassEverythingElse(t *testing.T) {
	r := Rules{
		LANOnly: true,
		Deny:    regexp.MustCompile(`.*`),
	}
	for _, req := range []Request{
		{Method: "POST", URL: "https://app.example/api/orders"},
		{Method: "DELETE", URL: "https://app.example/api/account/delete"},
		{Method: "GET", URL: "https://app.example/logout"},
	} {
		if d := r.Classify(req); d.Action != Pass {
			t.Fatalf("LANOnly Classify(%s %s) = %+v, want Pass", req.Method, req.URL, d)
		}
	}

	var answered []any
	g := &Guard{
		opts:     Options{Rules: Rules{LANOnly: true}},
		pending:  map[fetch.RequestID]*held{},
		stats:    Stats{ByReason: map[string]int{}},
		tops:     map[string]string{},
		answerFn: func(_ context.Context, p any) error { answered = append(answered, p); return nil },
	}
	// 1. Public main document passes and populates g.tops so Layer 1 knows the origin.
	g.handle(&fetch.EventRequestPaused{
		RequestID:    "doc-1",
		FrameID:      "frame-main",
		ResourceType: network.ResourceTypeDocument,
		Request:      &network.Request{Method: "GET", URL: "http://198.51.100.10:8770/"},
	}, nil)
	// 2. Public POST /delete passes immediately in LANOnly mode (ContinueRequest, not Fake!).
	g.handle(&fetch.EventRequestPaused{
		RequestID:    "write-1",
		FrameID:      "frame-main",
		ResourceType: network.ResourceTypeXHR,
		Request:      &network.Request{Method: "DELETE", URL: "http://198.51.100.10:8770/api/wipe"},
	}, nil)
	// 3. Private literal http://127.0.0.1:8771/lan AND ftp://127.0.0.1/file are BOTH failed by Layer 1!
	g.handle(&fetch.EventRequestPaused{
		RequestID:    "lan-http",
		FrameID:      "frame-main",
		ResourceType: network.ResourceTypeFetch,
		Request:      &network.Request{Method: "GET", URL: "http://127.0.0.1:8771/lan"},
	}, nil)
	g.handle(&fetch.EventRequestPaused{
		RequestID:    "lan-ftp",
		FrameID:      "frame-main",
		ResourceType: network.ResourceTypeImage,
		Request:      &network.Request{Method: "GET", URL: "ftp://127.0.0.1/secret"},
	}, nil)

	if len(answered) != 4 {
		t.Fatalf("expected 4 answered events, got %d", len(answered))
	}
	if _, ok := answered[0].(fetch.ContinueRequestParams); !ok {
		t.Fatalf("doc-1 want ContinueRequestParams, got %T", answered[0])
	}
	if _, ok := answered[1].(fetch.ContinueRequestParams); !ok {
		t.Fatalf("write-1 in LANOnly want ContinueRequestParams, got %T", answered[1])
	}
	if _, ok := answered[2].(fetch.FailRequestParams); !ok {
		t.Fatalf("lan-http want FailRequestParams, got %T", answered[2])
	}
	if _, ok := answered[3].(fetch.FailRequestParams); !ok {
		t.Fatalf("lan-ftp want FailRequestParams, got %T", answered[3])
	}
	if len(g.records) != 2 || g.records[0].Reason != ReasonPrivate || g.records[1].Reason != ReasonPrivate {
		t.Fatalf("expected 2 private-address records, got %+v", g.records)
	}
}
