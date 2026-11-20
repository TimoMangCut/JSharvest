package guard

import (
	"bytes"
	"log/slog"
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
