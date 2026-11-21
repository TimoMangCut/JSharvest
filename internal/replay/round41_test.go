package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/roles"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestRound41KeptSuccessAndRefusalAreUnclear(t *testing.T) {
	ctl := Answer{Status: 200, Header: map[string]string{"content-type": "application/json"}, Body: []byte(`{"secret":"admin-data"}`)}
	login := func(l string) bool { return strings.Contains(l, "/login") }

	cases := []struct {
		name string
		c    Case
	}{
		{
			name: "200_same_body_kept",
			c:    Case{Trial: ctl, Controls: []Answer{ctl, ctl}, Kept: true},
		},
		{
			name: "200_body_error_kept",
			c: Case{
				Trial:    Answer{Status: 200, Header: map[string]string{"content-type": "application/json"}, Body: []byte(`{"errors":[{"message":"UNAUTHENTICATED"}],"data":null}`)},
				Controls: []Answer{ctl, ctl},
				Kept:     true,
			},
		},
		{
			name: "200_write_no_control_kept",
			c:    Case{Write: true, Trial: Answer{Status: 200}, Kept: true},
		},
		{
			name: "302_login_kept",
			c:    Case{Trial: Answer{Status: 302, Header: map[string]string{"location": "/login"}}, Controls: []Answer{ctl}, Kept: true, IsLogin: login},
		},
		{
			name: "302_login_stale",
			c:    Case{Trial: Answer{Status: 302, Header: map[string]string{"location": "/login"}}, Controls: []Answer{ctl}, Stale: true, IsLogin: login},
		},
		{
			name: "404_kept",
			c:    Case{Trial: Answer{Status: 404}, Controls: []Answer{ctl}, Kept: true},
		},
		{
			name: "404_stale",
			c:    Case{Trial: Answer{Status: 404}, Controls: []Answer{ctl}, Stale: true},
		},
	}
	for _, tc := range cases {
		j := Judge(tc.c)
		if j.Verdict != Unclear {
			t.Errorf("%s: got verdict=%s (%s), want %s", tc.name, j.Verdict, j.Reason, Unclear)
		}
	}
}

func TestRound41KeptCredentialStrippedOrHeld(t *testing.T) {
	const adminSecret = "ADMIN_SUPER_SECRET_TOKEN"
	const adminPin = "987654"

	var mu sync.Mutex
	var userHits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ck := r.Header.Get("Cookie")
		mu.Lock()
		if strings.Contains(ck, "role=user") {
			userHits = append(userHits, r.Method+" "+r.URL.RequestURI()+" "+string(body))
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/me":
			if strings.Contains(ck, "role=admin") {
				io.WriteString(w, `{"user":"admin"}`)
				return
			}
			if strings.Contains(ck, "role=user") {
				io.WriteString(w, `{"user":"user"}`)
				return
			}
			w.WriteHeader(401)
		default:
			io.WriteString(w, `{"secret":"only-admin"}`)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	root := t.TempDir()
	now := time.Now().UTC()
	writeRole := func(name, cookie string, extra ...traffic.Entry) {
		rdir := filepath.Join(root, name)
		if err := os.MkdirAll(rdir, 0o700); err != nil {
			t.Fatal(err)
		}
		entries := append([]traffic.Entry{{
			Run: "R1", ID: 1, Method: "GET", URL: srv.URL + "/api/me", ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers:  map[string]string{"host": host, "cookie": cookie},
			Response: &traffic.Response{Status: 200, MIME: "application/json", Headers: map[string]string{"content-type": "application/json"}, Body: traffic.Body{Body: `{"ok":true}`}},
		}}, extra...)
		var buf bytes.Buffer
		var refs []flow.Ref
		for _, e := range entries {
			b, _ := json.Marshal(e)
			buf.Write(append(b, '\n'))
			refs = append(refs, flow.Ref{ID: e.ID})
		}
		if err := os.WriteFile(filepath.Join(rdir, "requests.jsonl"), buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		fl := flow.Flow{Run: "R1", Action: "a1", Kind: "load", Started: now, Ended: now, Requests: refs}
		fb, _ := json.Marshal(fl)
		if err := os.WriteFile(filepath.Join(rdir, "flows.jsonl"), append(fb, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	mpBoundary := "----jshbound"
	mpBody := "--" + mpBoundary + "\r\nContent-Disposition: form-data; name=\"access_token\"\r\n\r\n" + adminSecret + "\r\n--" + mpBoundary + "--\r\n"

	writeRole("user", "role=user")
	writeRole("admin", "role=admin",
		// 1. Removable query + JSON string + JSON numeric credential -> stripped and sent without secret.
		traffic.Entry{
			Run: "R1", ID: 2, Method: "POST", URL: srv.URL + "/api/report?access_token=" + adminSecret + "&keep=1",
			ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers:  map[string]string{"host": host, "cookie": "role=admin", "content-type": "application/json", "x-user-id": "admin-1"},
			Body:     traffic.Body{Body: `{"api_key":"` + adminSecret + `","secret":` + adminPin + `,"filter":"all"}`},
			Response: &traffic.Response{Status: 200, MIME: "application/json", Headers: map[string]string{"content-type": "application/json"}, Body: traffic.Body{Body: `{"secret":"only-admin"}`}},
		},
		// 2. Unremovable multipart credential -> NOT sent, NO trial file written, Unclear.
		traffic.Entry{
			Run: "R1", ID: 3, Method: "POST", URL: srv.URL + "/api/upload",
			ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers:  map[string]string{"host": host, "cookie": "role=admin", "content-type": "multipart/form-data; boundary=" + mpBoundary},
			Body:     traffic.Body{Body: mpBody},
			Response: &traffic.Response{Status: 200, MIME: "application/json", Headers: map[string]string{"content-type": "application/json"}, Body: traffic.Body{Body: `{"secret":"only-admin"}`}},
		},
		// 3. Unremovable duplicate query credential -> NOT sent, Unclear.
		traffic.Entry{
			Run: "R1", ID: 4, Method: "GET", URL: srv.URL + "/api/dup?access_token=" + adminSecret + "&access_token=" + adminSecret,
			ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers:  map[string]string{"host": host, "cookie": "role=admin"},
			Response: &traffic.Response{Status: 200, MIME: "application/json", Headers: map[string]string{"content-type": "application/json"}, Body: traffic.Body{Body: `{"secret":"only-admin"}`}},
		},
	)

	diff := roles.Report{
		Host:  host,
		Roles: []string{"user", "admin"},
		Items: []roles.Item{
			{Layer: "endpoint", Key: "POST " + host + "/api/report", Class: roles.HigherOnly, States: map[string]roles.State{"admin": roles.Used}},
			{Layer: "endpoint", Key: "POST " + host + "/api/upload", Class: roles.HigherOnly, States: map[string]roles.State{"admin": roles.Used}},
			{Layer: "endpoint", Key: "GET " + host + "/api/dup", Class: roles.HigherOnly, States: map[string]roles.State{"admin": roles.Used}},
		},
	}
	db, _ := json.Marshal(diff)
	if err := os.WriteFile(filepath.Join(root, "diff.json"), db, 0o600); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(root, "authz")
	sender, err := NewSender(SenderOptions{AllowPrivate: true, Max: 50, Log: filepath.Join(outDir, "sent.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	rep, err := Authz(context.Background(), AuthzOptions{
		Root:       root,
		AllowWrite: true,
		Sender:     sender,
		InScope:    func(string) bool { return true },
		Out:        outDir,
		Now:        now,
	})
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	gotHits := append([]string(nil), userHits...)
	mu.Unlock()
	for _, h := range gotHits {
		if strings.Contains(h, adminSecret) || strings.Contains(h, adminPin) {
			t.Fatalf("user request leaked admin credential: %s", h)
		}
		if strings.Contains(h, "/api/upload") || strings.Contains(h, "/api/dup") {
			t.Fatalf("unstrippable trial should not have been sent: %s", h)
		}
	}

	byKey := map[string]Trial{}
	for _, it := range rep.Items {
		if len(it.Trials) > 0 {
			byKey[it.Key] = it.Trials[0]
		}
	}
	tReport := byKey["POST "+host+"/api/report"]
	if len(tReport.Stale) == 0 || len(tReport.KeptHeaders) == 0 {
		t.Fatalf("report trial missing stale/kept_headers: %+v", tReport)
	}
	for _, k := range []string{"POST " + host + "/api/upload", "GET " + host + "/api/dup"} {
		tr := byKey[k]
		if tr.Verdict != Unclear || tr.File != "" {
			t.Fatalf("%s: got verdict=%s file=%q, want Unclear and empty trial file", k, tr.Verdict, tr.File)
		}
	}
	// Verify no trial file on disk contains adminSecret.
	files, _ := filepath.Glob(filepath.Join(outDir, "trials", "*.http"))
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		if bytes.Contains(raw, []byte(adminSecret)) {
			t.Fatalf("trial file %s leaked adminSecret", f)
		}
	}
}

func TestRound41PatchFailureAndReplayAsDropOwnerCredentials(t *testing.T) {
	const ownerTok = "OWNER_API_SECRET_99"
	const ownerHdr = "OWNER_CSRF_HEADER_88"

	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.URL.RequestURI()+"|hdr="+r.Header.Get("X-Csrf-Token")+"|body="+string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/csrf" {
			// Newline in refreshed token forces Patch("header:x-csrf-token", v) to fail!
			io.WriteString(w, `{"csrf":"bad\r\ninject"}`)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	dir := t.TempDir()
	now := time.Now().UTC()
	mpBoundary := "----b2"
	mpBody := "--" + mpBoundary + "\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\n" + ownerTok + "\r\n--" + mpBoundary + "--\r\n"

	reqs := []traffic.Entry{
		{
			Run: "R1", ID: 1, Method: "GET", URL: srv.URL + "/api/csrf", ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers:  map[string]string{"host": host},
			Response: &traffic.Response{Status: 200, MIME: "application/json", Headers: map[string]string{"content-type": "application/json"}, Body: traffic.Body{Body: `{"csrf":"` + ownerHdr + `"}`}},
		},
		{
			Run: "R1", ID: 2, Method: "POST", URL: srv.URL + "/api/save?api_key=" + ownerTok + "&id=7", ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers:  map[string]string{"host": host, "x-csrf-token": ownerHdr, "content-type": "application/json"},
			Body:     traffic.Body{Body: `{"name":"x"}`},
			Response: &traffic.Response{Status: 200, MIME: "application/json", Body: traffic.Body{Body: `{"ok":true}`}},
		},
		{
			Run: "R1", ID: 3, Method: "POST", URL: srv.URL + "/api/mp", ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers:  map[string]string{"host": host, "content-type": "multipart/form-data; boundary=" + mpBoundary},
			Body:     traffic.Body{Body: mpBody},
			Response: &traffic.Response{Status: 200, MIME: "application/json", Body: traffic.Body{Body: `{"ok":true}`}},
		},
	}
	var rbuf bytes.Buffer
	for _, e := range reqs {
		b, _ := json.Marshal(e)
		rbuf.Write(append(b, '\n'))
	}
	os.WriteFile(filepath.Join(dir, "requests.jsonl"), rbuf.Bytes(), 0o600)

	fl := flow.Flow{
		Run: "R1", Action: "a1", Kind: "click", Label: "save", Started: now, Ended: now,
		Requests:  []flow.Ref{{ID: 1}, {ID: 2}, {ID: 3}},
		DependsOn: []flow.Link{{Request: 2, At: "header:x-csrf-token", From: flow.LinkEnd{Request: 1, At: "body:$.csrf"}}},
	}
	fb, _ := json.Marshal(fl)
	os.WriteFile(filepath.Join(dir, "flows.jsonl"), append(fb, '\n'), 0o600)

	m, err := export.Load(export.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	asID := NoIdentity()
	asID.Role = "user"
	u, _ := url.Parse(srv.URL + "/")
	asID.Jar.SetCookies(u, []*http.Cookie{{Name: "sid", Value: "user-cookie"}})

	s, err := NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 10, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	res, err := ReplayFlow(context.Background(), FlowOptions{
		Model:      m,
		Action:     "a1",
		As:         asID,
		Owner:      "admin",
		AllowWrite: true,
		Sender:     s,
		InScope:    func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	gotSeen := append([]string(nil), seen...)
	mu.Unlock()
	for _, line := range gotSeen {
		if strings.Contains(line, ownerTok) || strings.Contains(line, ownerHdr) {
			t.Fatalf("replay -as leaked owner credential: %s", line)
		}
		if strings.HasPrefix(line, "/api/mp") {
			t.Fatalf("replay -as sent unstrippable multipart step: %s", line)
		}
	}
	if len(res.Steps) != 3 || !res.Steps[1].Sent || res.Steps[2].Sent || res.Steps[2].Skipped == "" {
		t.Fatalf("unexpected replay steps: %+v", res.Steps)
	}
}

func TestRound41SentAndTrialsRedacted(t *testing.T) {
	r := traffic.NewRedactor()

	// 1. RedactRaw handles proxy-form userinfo, query token, headers, body, and Content-Length.
	rawWire := "POST http://bob:hunter22pass@app.test/api/v1/login?access_token=qtok_999 HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"Authorization: Bearer bearer_secret_123\r\n" +
		"Cookie: sid=cookie_secret_456\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 39\r\n\r\n" +
		`{"password":"very_long_password_value"}`
	scrubbed := RedactRaw(r, rawWire)
	for _, leak := range []string{"hunter22pass", "qtok_999", "bearer_secret_123", "cookie_secret_456", "very_long_password_value"} {
		if strings.Contains(scrubbed, leak) {
			t.Fatalf("RedactRaw leaked %q:\n%s", leak, scrubbed)
		}
	}
	parsedReq, err := http.ReadRequest(bufio.NewReader(strings.NewReader(scrubbed)))
	if err != nil {
		t.Fatalf("http.ReadRequest failed after RedactRaw: %v\n%s", err, scrubbed)
	}
	parsedBody, err := io.ReadAll(parsedReq.Body)
	if err != nil || int64(len(parsedBody)) != parsedReq.ContentLength {
		t.Fatalf("redacted body length mismatch: read=%d cl=%d err=%v", len(parsedBody), parsedReq.ContentLength, err)
	}

	// 2. Sender with Redactor scrubs Request, Set-Cookie, 64KB response body, Sent.Err, and HostsBlocked,
	// while returning the unredacted Answer in memory to callers.
	const respSecret = "resp_token_secret_7890"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Set-Cookie", "sid=new_server_cookie_abc; Path=/; HttpOnly")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"pad":%q}`, respSecret, strings.Repeat("p", 40_000))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	sentPath := filepath.Join(t.TempDir(), "sent.jsonl")
	sender, err := NewSender(SenderOptions{
		Hosts:        map[string]bool{u.Host: true, "127.0.0.1:1": true},
		AllowPrivate: true,
		Log:          sentPath,
		Redactor:     r,
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	wireOK := fmt.Sprintf("GET /api/me?api_key=live_key_xyz HTTP/1.1\r\nHost: %s\r\nCookie: sid=client_cookie_xyz\r\n\r\n", u.Host)
	ans, err := sender.Send(context.Background(), []byte(wireOK), "http", "trial", "user", "GET /api/me", nil)
	if err != nil {
		t.Fatalf("Send OK: %v", err)
	}
	// In-memory answer stays intact so Judge / CSRF extraction still sees real bytes.
	if !strings.Contains(string(ans.Body), respSecret) {
		t.Fatalf("expected unredacted in-memory Answer.Body")
	}

	// Trigger 5 consecutive errors on dead port 127.0.0.1:1 with a query secret to test Sent.Err & HostsBlocked.
	wireDead := "GET /cb?access_token=err_url_secret_321 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
	for range 5 {
		_, _ = sender.Send(context.Background(), []byte(wireDead), "http", "trial", "user", "GET /cb", nil)
	}
	if err := sender.Close(); err != nil {
		t.Fatal(err)
	}

	// Also verify authz trialFile writes redacted .http parseable by http.ReadRequest.
	azOut := t.TempDir()
	az := &authz{o: AuthzOptions{Out: azOut, Sender: sender}}
	tf := az.trialFile("GET " + u.Host + "/api/me", "user", []byte(wireOK))
	if tf == "" {
		t.Fatal("expected trialFile written")
	}
	trialBytes, err := os.ReadFile(filepath.Join(azOut, tf))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(trialBytes))); err != nil {
		t.Fatalf("trial .http invalid HTTP: %v", err)
	}

	sentDisk, err := os.ReadFile(sentPath)
	if err != nil {
		t.Fatal(err)
	}
	blockedJSON, _ := json.Marshal(sender.BlockedHosts())
	combined := string(sentDisk) + "\n" + string(trialBytes) + "\n" + string(blockedJSON) + "\n" + sender.Stopped()
	for _, leak := range []string{"live_key_xyz", "client_cookie_xyz", "new_server_cookie_abc", respSecret, "err_url_secret_321"} {
		if strings.Contains(combined, leak) {
			t.Fatalf("disk/blocked output leaked %q:\n%s", leak, combined[:min(len(combined), 1000)])
		}
	}
	if !strings.Contains(string(sentDisk), "REDACTED_") || !strings.Contains(string(trialBytes), "REDACTED_") {
		t.Fatalf("expected REDACTED_ markers in sent.jsonl and trial .http")
	}
}
