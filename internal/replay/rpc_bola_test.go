package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/roles"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestNextServerActionsExportDiffAndBola(t *testing.T) {
	const (
		actGetInvoice = "4011111111111111111111111111111111111111"
		actSetPref    = "4022222222222222222222222222222222222222"
		invAlice      = "8a11ce00-1111-4111-8111-000000000001"
		invBob        = "8b0b0000-2222-4222-8222-000000000002"
		prefAlice     = "9a11ce00-3333-4333-8333-000000000003"
		prefBob       = "9b0b0000-4444-4444-8444-000000000004"
	)

	invoices := map[string][3]string{
		invAlice: {"alice", "alice@acme.test", "Alice private tax wire ref WIRE-ALICE-99812"},
		invBob:   {"bob", "bob@acme.test", "Bob private tax wire ref WIRE-BOB-44109"},
	}
	prefOwners := map[string]string{
		prefAlice: "alice",
		prefBob:   "bob",
	}
	sessions := map[string]string{
		"tok-alice-server-action-0001": "alice",
		"tok-bob-server-action-000002": "bob",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sess")
		user := ""
		if err == nil {
			user = sessions[c.Value]
		}
		if r.Method == "GET" && r.URL.Path == "/api/me" {
			if user == "" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"user": user})
			return
		}
		if r.Method != "POST" || r.URL.Path != "/dashboard/settings" {
			w.WriteHeader(404)
			return
		}
		if user == "" {
			w.WriteHeader(401)
			return
		}
		act := strings.ToLower(r.Header.Get("Next-Action"))
		body, _ := io.ReadAll(r.Body)
		var args []string
		_ = json.Unmarshal(body, &args)

		w.Header().Set("Content-Type", "text/x-component")
		w.Header().Set("Cache-Control", "no-store")
		switch act {
		case actGetInvoice:
			// Deliberate authorization flaw: accepts peer's object ID without checking owner!
			if len(args) == 0 {
				w.WriteHeader(400)
				return
			}
			inv, ok := invoices[args[0]]
			if !ok {
				fmt.Fprintf(w, "0:[\"$@1\",[\"b\",null]]\n1:null\n")
				return
			}
			row, _ := json.Marshal(map[string]any{
				"id":     args[0],
				"email":  inv[1],
				"secret": inv[2],
			})
			fmt.Fprintf(w, "0:[\"$@1\",[\"b\",null]]\n1:%s\n", row)
		case actSetPref:
			// Properly enforced: 403 when caller does not own prefID.
			if len(args) == 0 || prefOwners[args[0]] != user {
				w.WriteHeader(403)
				fmt.Fprintf(w, "0:E{\"message\":\"forbidden\"}\n")
				return
			}
			row, _ := json.Marshal(map[string]any{
				"id":    args[0],
				"user":  user,
				"theme": "dark",
			})
			fmt.Fprintf(w, "0:[\"$@1\",[\"b\",null]]\n1:%s\n", row)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	root := t.TempDir()
	host := strings.TrimPrefix(srv.URL, "http://")

	recordNextRole := func(role, tok, invID, prefID string) {
		dir := filepath.Join(root, role)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		t0 := time.Now().UTC().Add(-10 * time.Minute)
		type spec struct {
			method, path, ct, body string
			hdr                    map[string]string
		}
		specs := []spec{
			{method: "GET", path: "/api/me"},
			{
				method: "POST", path: "/dashboard/settings",
				ct:   "text/plain;charset=UTF-8",
				body: fmt.Sprintf(`[%q]`, invID),
				hdr: map[string]string{
					"next-action":            actGetInvoice,
					"next-router-state-tree": "%5B%22%22%2C%7B%7D%5D",
				},
			},
			{
				method: "POST", path: "/dashboard/settings",
				ct:   "text/plain;charset=UTF-8",
				body: fmt.Sprintf(`[%q]`, prefID),
				hdr: map[string]string{
					"next-action":            actSetPref,
					"next-router-state-tree": "%5B%22%22%2C%7B%7D%5D",
				},
			},
		}
		var lines []string
		var refs []flow.Ref
		for i, sp := range specs {
			id := i + 1
			req, _ := http.NewRequest(sp.method, srv.URL+sp.path, strings.NewReader(sp.body))
			req.AddCookie(&http.Cookie{Name: "sess", Value: tok})
			h := map[string]string{"host": host, "accept": "text/x-component, */*", "cookie": "sess=" + tok}
			if sp.ct != "" {
				req.Header.Set("Content-Type", sp.ct)
				h["content-type"] = sp.ct
			}
			for k, v := range sp.hdr {
				req.Header.Set(k, v)
				h[k] = v
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			rb, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			respCT := resp.Header.Get("Content-Type")
			e := traffic.Entry{
				Run: "R1", ID: id, Time: t0.Add(time.Duration(i) * time.Second),
				Target: "page", ResourceType: "Fetch", Method: sp.method,
				URL: srv.URL + sp.path, Headers: h, Body: traffic.Body{Body: sp.body}, Outcome: "ok",
				Response: &traffic.Response{
					Status: int64(resp.StatusCode), MIME: respCT, Source: "network",
					Headers: map[string]string{"content-type": respCT},
					Body:    traffic.Body{Body: string(rb)},
				},
			}
			b, _ := json.Marshal(e)
			lines = append(lines, string(b))
			refs = append(refs, flow.Ref{ID: id})
		}
		if err := os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		fl := flow.Flow{Run: "R1", Action: "a1", Kind: "click", Label: "settings", Started: t0, Ended: t0.Add(5 * time.Second), Requests: refs}
		fb, _ := json.Marshal(fl)
		if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), append(fb, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	recordNextRole("alice", "tok-alice-server-action-0001", invAlice, prefAlice)
	recordNextRole("bob", "tok-bob-server-action-000002", invBob, prefBob)

	// 1. Export separates the 2 Server Actions on POST /dashboard/settings into 2 distinct endpoint keys.
	mod, err := export.Load(export.Options{Dir: filepath.Join(root, "alice")})
	if err != nil {
		t.Fatal(err)
	}
	wantKey1 := "POST " + host + "/dashboard/settings next-action=" + actGetInvoice
	wantKey2 := "POST " + host + "/dashboard/settings next-action=" + actSetPref
	seenKeys := map[string]bool{}
	for _, rq := range mod.Requests {
		seenKeys[rq.Key] = true
	}
	if !seenKeys[wantKey1] || !seenKeys[wantKey2] {
		t.Fatalf("export.Load keys = %v, want both %q and %q", seenKeys, wantKey1, wantKey2)
	}

	// 2. roles.Compare separates them into 2 distinct endpoint items as well.
	diffRep, err := roles.Compare(roles.Options{Root: root, Roles: []string{"alice", "bob"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	roleKeys := map[string]bool{}
	for _, it := range diffRep.Items {
		if it.Layer == "endpoint" {
			roleKeys[it.Key] = true
		}
	}
	if !roleKeys[wantKey1] || !roleKeys[wantKey2] {
		t.Fatalf("roles.Compare endpoint keys = %v, want both %q and %q", roleKeys, wantKey1, wantKey2)
	}

	// 3. replay.Bola evaluates each Server Action independently on POST /dashboard/settings
	// without KeptHeaders noise: actGetInvoice -> needs-review (blind write 200), actSetPref -> enforced (403).
	snd, err := NewSender(SenderOptions{AllowPrivate: true, Max: 500, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer snd.Close()
	rep, err := Bola(context.Background(), BolaOptions{
		Root:       root,
		Peers:      [2]string{"alice", "bob"},
		Relation:   RelCrossOrg,
		AllowWrite: true,
		Sender:     snd,
		InScope:    func(string) bool { return true },
		Out:        filepath.Join(root, "authz"),
		Reveal:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	gotVerdict := map[string]Verdict{}
	for _, it := range rep.Items {
		if it.Direction == "alice->bob" {
			if len(it.KeptHeaders) != 0 {
				t.Fatalf("KeptHeaders on %s = %v, want empty", it.Key, it.KeptHeaders)
			}
			gotVerdict[it.Key] = it.Verdict
		}
	}
	if gotVerdict[wantKey1] != NeedsReview {
		t.Fatalf("Bola verdict for %s = %q, want %q (items=%+v)", wantKey1, gotVerdict[wantKey1], NeedsReview, rep.Items)
	}
	if gotVerdict[wantKey2] != Enforced {
		t.Fatalf("Bola verdict for %s = %q, want %q (items=%+v)", wantKey2, gotVerdict[wantKey2], Enforced, rep.Items)
	}

	// 4. Verify React Flight (text/x-component) structured JSON evidence extraction in JudgePeer.
	flightA := []byte("0:[\"$@1\",[\"b\",null]]\n1:{\"id\":\"" + invAlice + "\",\"email\":\"alice@acme.test\",\"secret\":\"WIRE-ALICE-99812\"}\n")
	flightB := []byte("0:[\"$@1\",[\"b\",null]]\n1:{\"id\":\"" + invBob + "\",\"email\":\"bob@acme.test\",\"secret\":\"WIRE-BOB-44109\"}\n")
	seen := NewSeenSet()
	seen.AddResponse(map[string]string{"content-type": "text/x-component"}, string(flightB))
	ansA := Answer{Status: 200, Header: map[string]string{"content-type": "text/x-component"}, Body: flightA}
	ansB := Answer{Status: 200, Header: map[string]string{"content-type": "text/x-component"}, Body: flightB}
	noID := Answer{Status: 401, Header: map[string]string{"content-type": "text/plain"}, Body: []byte("unauthorized")}
	pj := JudgePeer(PeerCase{
		Relation:   RelCrossOrg,
		Mode:       "main",
		IDCount:    1,
		Trial:      ansA,
		Controls:   []Answer{ansA, ansA},
		Self:       &ansB,
		NoIdentity: &noID,
		Sent:       []string{invAlice},
		Seen:       seen,
		RecordedOK: true,
		AliveA:     true,
	})
	if pj.Verdict != Bypass || len(pj.Evidence) == 0 {
		t.Fatalf("JudgePeer on RSC Flight response = %+v, want bypass with structured evidence", pj)
	}
}

func TestTRPCBatchExportAndBola(t *testing.T) {
	const (
		invAlice = "7a11ce00-1111-4111-8111-000000000001"
		invBob   = "7b0b0000-2222-4222-8222-000000000002"
	)
	invoices := map[string][2]string{
		invAlice: {"alice@acme.test", "TRPC-ALICE-MEMO-77123"},
		invBob:   {"bob@acme.test", "TRPC-BOB-MEMO-55210"},
	}
	sessions := map[string]string{
		"tok-trpc-alice-0001": "alice",
		"tok-trpc-bob-000002": "bob",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sess")
		user := ""
		if err == nil {
			user = sessions[c.Value]
		}
		if user == "" {
			w.WriteHeader(401)
			return
		}
		const prefix = "/api/trpc/"
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(404)
			return
		}
		procs := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), ",")
		var inputs map[string]struct {
			JSON map[string]string `json:"json"`
		}
		_ = json.Unmarshal([]byte(r.URL.Query().Get("input")), &inputs)

		out := make([]any, len(procs))
		for i, proc := range procs {
			idx := fmt.Sprintf("%d", i)
			switch proc {
			case "user.me":
				out[i] = map[string]any{"result": map[string]any{"data": map[string]any{"json": map[string]any{"user": user}}}}
			case "invoice.byId":
				id := inputs[idx].JSON["id"]
				if inv, ok := invoices[id]; ok {
					// Deliberate BOLA flaw: returns invoice by ID without checking owner!
					out[i] = map[string]any{"result": map[string]any{"data": map[string]any{"json": map[string]any{
						"id":         id,
						"ownerEmail": inv[0],
						"secretMemo": inv[1],
					}}}}
				} else {
					out[i] = map[string]any{"result": map[string]any{"data": map[string]any{"json": nil}}}
				}
			default:
				w.WriteHeader(404)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	root := t.TempDir()
	host := strings.TrimPrefix(srv.URL, "http://")

	recordTRPCBatch := func(role, tok, invID string) {
		rawInput := fmt.Sprintf(`{"0":{"json":null},"1":{"json":{"id":%q}}}`, invID)
		path := "/api/trpc/user.me,invoice.byId?batch=1&input=" + strings.ReplaceAll(
			strings.ReplaceAll(strings.ReplaceAll(rawInput, `{`, `%7B`), `}`, `%7D`),
			`"`, `%22`)
		path = strings.ReplaceAll(path, `:`, `%3A`)
		path = strings.ReplaceAll(path, `,`, `%2C`)
		// Restore comma in procedure path segment!
		path = strings.Replace(path, "/api/trpc/user.me%2Cinvoice.byId", "/api/trpc/user.me,invoice.byId", 1)
		recordDir(t, srv.URL, filepath.Join(root, role), tok, []rq{{method: "GET", path: path}}, nil)
	}
	recordTRPCBatch("alice", "tok-trpc-alice-0001", invAlice)
	recordTRPCBatch("bob", "tok-trpc-bob-000002", invBob)

	// 1. Export splits the batched request into two independent procedure endpoints.
	mod, err := export.Load(export.Options{Dir: filepath.Join(root, "alice")})
	if err != nil {
		t.Fatal(err)
	}
	wantMe := "GET " + host + "/api/trpc/user.me"
	wantInv := "GET " + host + "/api/trpc/invoice.byId"
	seen := map[string]bool{}
	for _, r := range mod.Requests {
		seen[r.Key] = true
	}
	if !seen[wantMe] || !seen[wantInv] {
		t.Fatalf("export.Load keys = %v, want %q and %q", seen, wantMe, wantInv)
	}

	// 2. Bola isolates invoice.byId from user.me, patches Bogus UUID inside URL-encoded input JSON, and proves Bypass!
	snd, err := NewSender(SenderOptions{AllowPrivate: true, Max: 500, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer snd.Close()
	rep, err := Bola(context.Background(), BolaOptions{
		Root:     root,
		Peers:    [2]string{"alice", "bob"},
		Relation: RelCrossOrg,
		Sender:   snd,
		InScope:  func(string) bool { return true },
		Out:      filepath.Join(root, "authz"),
		Reveal:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	foundInv := false
	for _, it := range rep.Items {
		if it.Key == wantInv && it.Direction == "alice->bob" {
			if it.Verdict != Bypass {
				t.Fatalf("Bola verdict for %s = %s (%s), want bypass", it.Key, it.Verdict, it.Reason)
			}
			foundInv = true
		}
	}
	if !foundInv {
		t.Fatalf("did not find alice->bob trial on %q in %+v", wantInv, rep.Items)
	}
}

func TestConnectJSONBolaAndBinaryProtoFramingSafety(t *testing.T) {
	// 1. Binary 5-byte framed gRPC-Web / Connect+Proto payloads must NEVER have their body parsed or patched.
	for _, ct := range []string{"application/grpc-web+proto", "application/connect+proto", "application/proto"} {
		frame := "\x00\x00\x00\x00\x10{\"id\":\"123456\"}"
		raw := []byte(fmt.Sprintf("POST /acme.v1.UserService/GetUser HTTP/1.1\r\nHost: api.test\r\nContent-Type: %s\r\nConnect-Protocol-Version: 1\r\nContent-Length: %d\r\n\r\n%s", ct, len(frame), frame))
		for _, p := range export.Params(raw) {
			if p.In != "path" {
				t.Fatalf("Content-Type %s yielded unexpected non-path Param %+v", ct, p)
			}
		}
		if _, err := Patch(raw, "body:$.id", "999999"); err == nil {
			t.Fatalf("expected Patch on binary %s body to fail safely", ct)
		}
	}

	// 2. Connect protocol with application/connect+json runs full BOLA verification cleanly.
	const (
		docAlice = "6a11ce00-1111-4111-8111-000000000001"
		docBob   = "6b0b0000-2222-4222-8222-000000000002"
	)
	docs := map[string][2]string{
		docAlice: {"alice@acme.test", "CONNECT-ALICE-NOTE-90123"},
		docBob:   {"bob@acme.test", "CONNECT-BOB-NOTE-34567"},
	}
	sessions := map[string]string{
		"tok-connect-alice-01": "alice",
		"tok-connect-bob-0002": "bob",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sess")
		user := ""
		if err == nil {
			user = sessions[c.Value]
		}
		if user == "" {
			w.WriteHeader(401)
			return
		}
		if r.Method != "GET" || r.URL.Path != "/acme.v1.DocService/GetDoc" {
			w.WriteHeader(404)
			return
		}
		var msg struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(r.URL.Query().Get("message")), &msg)
		w.Header().Set("Content-Type", "application/connect+json")
		w.Header().Set("Cache-Control", "no-store")
		d, ok := docs[msg.ID]
		if !ok {
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(map[string]string{"code": "not_found", "message": "no such doc"})
			return
		}
		// Deliberate BOLA flaw: returns peer's document without checking ownership!
		json.NewEncoder(w).Encode(map[string]any{
			"id":          msg.ID,
			"ownerEmail":  d[0],
			"privateNote": d[1],
		})
	}))
	defer srv.Close()

	root := t.TempDir()
	host := strings.TrimPrefix(srv.URL, "http://")
	recordConnect := func(role, tok, docID string) {
		dir := filepath.Join(root, role)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		t0 := time.Now().UTC().Add(-5 * time.Minute)
		path := fmt.Sprintf("/acme.v1.DocService/GetDoc?connect=v1&encoding=json&message=%%7B%%22id%%22%%3A%%22%s%%22%%7D", docID)
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.AddCookie(&http.Cookie{Name: "sess", Value: tok})
		req.Header.Set("Connect-Protocol-Version", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		rb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		e := traffic.Entry{
			Run: "R1", ID: 1, Time: t0, Target: "page", ResourceType: "Fetch", Method: "GET",
			URL: srv.URL + path,
			Headers: map[string]string{
				"host":                     host,
				"accept":                   "application/connect+json",
				"connect-protocol-version": "1",
				"cookie":                   "sess=" + tok,
			},
			Outcome: "ok",
			Response: &traffic.Response{
				Status: int64(resp.StatusCode), MIME: "application/connect+json", Source: "network",
				Headers: map[string]string{"content-type": "application/connect+json"},
				Body:    traffic.Body{Body: string(rb)},
			},
		}
		b, _ := json.Marshal(e)
		os.WriteFile(filepath.Join(dir, "requests.jsonl"), append(b, '\n'), 0o600)
		fl := flow.Flow{Run: "R1", Action: "a1", Kind: "load", Label: "doc", Started: t0, Ended: t0.Add(time.Second), Requests: []flow.Ref{{ID: 1}}}
		fb, _ := json.Marshal(fl)
		os.WriteFile(filepath.Join(dir, "flows.jsonl"), append(fb, '\n'), 0o600)
	}
	recordConnect("alice", "tok-connect-alice-01", docAlice)
	recordConnect("bob", "tok-connect-bob-0002", docBob)

	snd, err := NewSender(SenderOptions{AllowPrivate: true, Max: 500, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer snd.Close()
	rep, err := Bola(context.Background(), BolaOptions{
		Root:     root,
		Peers:    [2]string{"alice", "bob"},
		Relation: RelCrossOrg,
		Sender:   snd,
		InScope:  func(string) bool { return true },
		Out:      filepath.Join(root, "authz"),
		Reveal:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantKey := "GET " + host + "/acme.v1.DocService/GetDoc"
	found := false
	for _, it := range rep.Items {
		if it.Key == wantKey && it.Direction == "alice->bob" {
			if len(it.KeptHeaders) != 0 {
				t.Fatalf("KeptHeaders = %v, want empty", it.KeptHeaders)
			}
			if it.Verdict != Bypass {
				t.Fatalf("ConnectRPC Bola verdict = %s (%s), want bypass", it.Verdict, it.Reason)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("missing ConnectRPC alice->bob trial in %+v", rep.Items)
	}
}
