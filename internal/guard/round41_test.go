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

func TestRound41BodyAndGraphQLDeleteHeld(t *testing.T) {
	// Even with AllowWrite=true and Explore=false, body operationParams and GraphQL destructive mutations are held as "destructive".
	r := Rules{AllowWrite: true, Explore: false}
	destructiveReqs := []Request{
		{
			Method:      "POST",
			URL:         "https://app.example/rpc",
			ContentType: "application/json",
			Body:        `{"jsonrpc":"2.0","method":"user.delete","id":1}`,
		},
		{
			Method:      "POST",
			URL:         "https://app.example/rpc/batch",
			ContentType: "application/json",
			Body:        `[{"jsonrpc":"2.0","method":"user.get","id":1},{"jsonrpc":"2.0","command":"wipeAccount","id":2}]`,
		},
		{
			Method:      "POST",
			URL:         "https://app.example/form",
			ContentType: "application/x-www-form-urlencoded",
			Body:        "id=42&command=deactivateUser",
		},
		{
			Method:      "POST",
			URL:         "https://app.example/graphql",
			ContentType: "application/json",
			Body:        `{"query":"mutation { deleteUser(id: 7) { ok } }"}`,
		},
	}
	for _, req := range destructiveReqs {
		d := r.Classify(req)
		if d.Action != Fake || d.Reason != "destructive" {
			t.Fatalf("Classify(%s %s %s) = %+v, want {Fake, destructive}", req.Method, req.URL, req.Body, d)
		}
	}

	// Non-destructive writes and GraphQL read queries mentioning "delete" still pass under AllowWrite=true.
	benignReqs := []Request{
		{
			Method:      "POST",
			URL:         "https://app.example/rpc",
			ContentType: "application/json",
			Body:        `{"method":"user.update","bio":"never delete notes"}`,
		},
		{
			Method:      "POST",
			URL:         "https://app.example/graphql",
			ContentType: "application/json",
			Body:        `{"query":"query Search { docs(q: \"delete\") { id } }"}`,
		},
	}
	for _, req := range benignReqs {
		d := r.Classify(req)
		if d.Action != Pass {
			t.Fatalf("Classify(%s %s) = %+v, want Pass", req.URL, req.Body, d)
		}
	}

	// Verify AllowWrites window (re-login) still holds back body/GraphQL destructive requests because Reason == "destructive".
	var answered []any
	g := &Guard{
		opts:     Options{Rules: Rules{}},
		pending:  map[fetch.RequestID]*held{},
		stats:    Stats{ByReason: map[string]int{}},
		tops:     map[string]string{},
		writers:  map[string]int{"frame-login": 1},
		passedBy: map[string]int{},
		answerFn: func(_ context.Context, p any) error { answered = append(answered, p); return nil },
	}
	g.handle(&fetch.EventRequestPaused{
		RequestID:    "relogin-rpc-del",
		FrameID:      "frame-login",
		ResourceType: network.ResourceTypeFetch,
		Request: &network.Request{
			Method:          "POST",
			URL:             "https://app.example/rpc",
			Headers:         network.Headers{"content-type": "application/json"},
			PostDataEntries: []*network.PostDataEntry{{Bytes: []byte(`{"method":"session.logout"}`)}},
		},
	}, nil)
	g.handle(&fetch.EventRequestPaused{
		RequestID:    "relogin-gql-del",
		FrameID:      "frame-login",
		ResourceType: network.ResourceTypeFetch,
		Request: &network.Request{
			Method:          "POST",
			URL:             "https://app.example/graphql",
			Headers:         network.Headers{"content-type": "application/json"},
			PostDataEntries: []*network.PostDataEntry{{Bytes: []byte(`{"query":"mutation { deleteAccount }"}`)}},
		},
	}, nil)
	if len(answered) != 2 {
		t.Fatalf("expected 2 answered events, got %d", len(answered))
	}
	for i, a := range answered {
		if _, ok := a.(fetch.FulfillRequestParams); !ok {
			t.Fatalf("event %d during AllowWrites should be held (FulfillRequestParams), got %T", i, a)
		}
	}
	if g.stats.PassedLogin != 0 || len(g.records) != 2 || g.records[0].Reason != "destructive" || g.records[1].Reason != "destructive" {
		t.Fatalf("unexpected relogin guard stats/records: stats=%+v records=%+v", g.stats, g.records)
	}
}

func TestRound41FormSemicolonAndBadPercent(t *testing.T) {
	r := Rules{AllowWrite: true}
	for _, req := range []Request{
		{Method: "POST", URL: "https://app.example/form", ContentType: "application/x-www-form-urlencoded", Body: "note=a;b&action=delete"},
		{Method: "POST", URL: "https://app.example/form", ContentType: "application/x-www-form-urlencoded", Body: "bad=%ZZ&action=logout"},
		{Method: "POST", URL: "https://app.example/form", ContentType: "application/x-www-form-urlencoded", Body: "_method=DELETE;x=1"},
		{Method: "POST", URL: "https://app.example/form?_method=DELETE;x=1", ContentType: "application/x-www-form-urlencoded", Body: "ok=1"},
	} {
		d := r.Classify(req)
		if d.Action != Fake || d.Reason != "destructive" {
			t.Errorf("Classify(%s %s %s) = %+v, want {Fake, destructive}", req.Method, req.URL, req.Body, d)
		}
	}

	exp := Rules{Explore: true}
	if d := exp.Classify(Request{Method: "GET", URL: "https://app.example/rpc?note=%ZZ&action=approve", ResourceType: "Fetch"}); d.Action != Fake || d.Reason != "explore-verb" {
		t.Errorf("Explore GET with bad percent query = %+v, want {Fake, explore-verb}", d)
	}
}

func TestRound41MultipartDestructiveAndLogout(t *testing.T) {
	r := Rules{AllowWrite: true}
	fullDestroy := "--b1\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\ndestroy\r\n--b1--\r\n"
	fullLogout := "--b2\r\nContent-Disposition: form-data; name=\"op\"\r\n\r\nsign_out\r\n--b2--\r\n"
	truncDestroy := "--b3\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n--b3\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\ndestroy"
	noBoundaryHeader := "--b4\r\nContent-Disposition: form-data; name=\"op\"\r\n\r\nlogout\r\n"
	methodDelete := "--b5\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nDELETE\r\n--b5--\r\n"

	for _, req := range []Request{
		{Method: "POST", URL: "https://app.example/up", ContentType: "multipart/form-data; boundary=b1", Body: fullDestroy},
		{Method: "POST", URL: "https://app.example/up", ContentType: "multipart/form-data; boundary=b2", Body: fullLogout},
		{Method: "POST", URL: "https://app.example/up", ContentType: "multipart/form-data; boundary=b3", Body: truncDestroy},
		{Method: "POST", URL: "https://app.example/up", ContentType: "multipart/form-data", Body: noBoundaryHeader},
		{Method: "POST", URL: "https://app.example/up", ContentType: "multipart/form-data; boundary=b5", Body: methodDelete},
	} {
		d := r.Classify(req)
		if d.Action != Fake || d.Reason != "destructive" {
			t.Errorf("Classify(multipart %q) = %+v, want {Fake, destructive}", req.Body, d)
		}
	}

	// File upload filename containing "delete" must not trigger BodyActionFields,
	// and _method=GET with no destructive fields is read.
	safeFile := "--b6\r\nContent-Disposition: form-data; name=\"file\"; filename=\"delete.txt\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b6--\r\n"
	if d := (Rules{AllowWrite: true}).Classify(Request{Method: "POST", URL: "https://app.example/up", ContentType: "multipart/form-data; boundary=b6", Body: safeFile}); d.Action != Pass {
		t.Errorf("safe multipart file upload = %+v, want Pass", d)
	}
	methodGet := "--b7\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nGET\r\n--b7--\r\n"
	if d := (Rules{AllowWrite: false}).Classify(Request{Method: "POST", URL: "https://app.example/search", ContentType: "multipart/form-data; boundary=b7", Body: methodGet}); d.Action != Pass || d.Reason != "read" {
		t.Errorf("multipart _method=GET = %+v, want {Pass, read}", d)
	}
}

func TestRound41JSONRPCBatch65thDestructive(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 1; i <= 70; i++ {
		if i > 1 {
			b.WriteByte(',')
		}
		if i == 68 {
			b.WriteString(`{"jsonrpc":"2.0","method":"user.delete","id":68}`)
		} else {
			b.WriteString(`{"jsonrpc":"2.0","method":"ping","id":1}`)
		}
	}
	b.WriteByte(']')

	d := (Rules{AllowWrite: true}).Classify(Request{
		Method:      "POST",
		URL:         "https://app.example/rpc",
		ContentType: "application/json",
		Body:        b.String(),
	})
	if d.Action != Fake || d.Reason != "destructive" {
		t.Fatalf("70-item JSON-RPC batch with 68th delete = %+v, want {Fake, destructive}", d)
	}
}

func TestRound41GraphQLReadQueryWithFilterAction(t *testing.T) {
	r := Rules{AllowWrite: false}
	readReq := Request{
		Method:      "POST",
		URL:         "https://app.example/graphql",
		ContentType: "application/json",
		Body:        `{"query":"query ListAudit($f: Filter){ logs(filter: $f){ id } }","variables":{"f":{"action":"delete"}}}`,
	}
	if d := r.Classify(readReq); d.Action != Pass || d.Reason != "read" {
		t.Fatalf("GraphQL read query with filter.action=delete got %+v, want {Pass, read}", d)
	}

	mutReq := Request{
		Method:      "POST",
		URL:         "https://app.example/graphql",
		ContentType: "application/json",
		Body:        `{"query":"mutation RunAudit($f: Filter){ run(filter: $f){ id } }","variables":{"f":{"action":"delete"}}}`,
	}
	if d := (Rules{AllowWrite: true}).Classify(mutReq); d.Action != Fake || d.Reason != "destructive" {
		t.Fatalf("GraphQL mutation with filter.action=delete got %+v, want {Fake, destructive}", d)
	}
}
