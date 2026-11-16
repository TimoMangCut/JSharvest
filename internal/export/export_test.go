package export

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestRawRequest(t *testing.T) {
	e := traffic.Entry{Method: "POST", URL: "https://app.test/api/profile?x=1#frag",
		Headers: map[string]string{":authority": "app.test", ":method": "POST", ":path": "/api/profile?x=1", ":scheme": "https",
			"content-type": "application/json", "x-csrf-token": "cd4b", "cookie": "a=1\nb=2", "accept-encoding": "gzip, br, zstd",
			"content-length": "22", "accept": "*/*", "priority": "u=1, i"},
		Body: traffic.Body{Body: `{"display_name":"Bob"}`}}
	r, err := RawRequest(e)
	if err != nil {
		t.Fatal(err)
	}
	want := "POST /api/profile?x=1 HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nAccept: */*\r\n" +
		"X-Csrf-Token: cd4b\r\nCookie: a=1; b=2\r\nContent-Length: 22\r\n\r\n{\"display_name\":\"Bob\"}"
	if string(r.Bytes) != want {
		t.Fatalf("got\n%q\nwant\n%q", r.Bytes, want)
	}
	if r.Star || r.Incomplete != "" {
		t.Fatalf("%+v", r)
	}
	q, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(r.Bytes)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(q.Body)
	if q.Host != "app.test" || q.URL.RequestURI() != "/api/profile?x=1" || string(body) != e.Body.Body || q.Header.Get("Cookie") != "a=1; b=2" {
		t.Fatalf("%+v %q", q, body)
	}

	// A body cut by the recorder, one shorter than what was sent, a star.
	cut := traffic.Entry{Method: "POST", URL: "http://app.test/up?q=a*", Headers: map[string]string{"content-length": "900"},
		Body: traffic.Body{Body: "abc", BodyTruncated: true}}
	if r, _ := RawRequest(cut); r.Incomplete != "truncated" || !r.Star {
		t.Fatalf("%+v", r)
	}
	cut.BodyTruncated = false
	if r, _ := RawRequest(cut); r.Incomplete != "short" {
		t.Fatalf("%+v", r)
	}
	// sqlmap does not read */* or ;q= in a header as its mark, but does
	// read image/*.
	nav := traffic.Entry{Method: "GET", URL: "http://app.test/", Headers: map[string]string{"accept": "text/html,image/webp,*/*;q=0.8"}}
	if r, _ := RawRequest(nav); r.Star {
		t.Fatal("*/* taken for a mark")
	}
	nav.Headers["accept"] = "image/*"
	if r, _ := RawRequest(nav); !r.Star {
		t.Fatal("image/* not seen")
	}
	// A GET without a body has no Content-Length; binary bodies are bytes.
	if r, _ := RawRequest(traffic.Entry{Method: "GET", URL: "http://app.test/a%20b"}); strings.Contains(string(r.Bytes), "Content-Length") ||
		!strings.HasPrefix(string(r.Bytes), "GET /a%20b HTTP/1.1\r\n") {
		t.Fatalf("%q", r.Bytes)
	}
	if got := requestTarget("http://app.test:81/a/{x}|[y]?q=%20a#f"); got != "/a/{x}|[y]?q=%20a" {
		t.Fatal(got)
	}
	if got := requestTarget("http://app.test?x=1"); got != "/?x=1" {
		t.Fatal(got)
	}
	bin := traffic.MakeBody([]byte{0xff, 0x00, 0x01}, 100)
	if r, _ := RawRequest(traffic.Entry{Method: "PUT", URL: "http://app.test/u", Body: bin}); !bytes.HasSuffix(r.Bytes, []byte("Content-Length: 3\r\n\r\n\xff\x00\x01")) {
		t.Fatalf("%q", r.Bytes)
	}
}

func TestHAR(t *testing.T) {
	ok := traffic.Entry{Run: "r", ID: 1, Method: "GET", URL: "http://app.test/api/x?b=2&a=1", ResourceType: "Fetch", Outcome: "ok",
		Headers:  map[string]string{"cookie": "sid=1; t=2"},
		Response: &traffic.Response{Status: 200, Protocol: "h2", MIME: "application/json", Body: traffic.Body{Body: "{}"}}}
	held := traffic.Entry{Run: "r", ID: 2, Method: "POST", URL: "http://app.test/api/del", Outcome: "held_back:write",
		Body: traffic.Body{Body: "a=1"}, Response: &traffic.Response{Status: 200, Headers: map[string]string{traffic.GuardHeader: "write"}}}
	h := NewHAR([]HARPage{{ID: "a1", Title: "click"}}, []HAREntry{{Entry: ok, Page: "a1"}, {Entry: held, Page: "a1"}})
	b, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Log struct {
			Entries []map[string]any `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(b, &v); err != nil || len(v.Log.Entries) != 2 {
		t.Fatal(err)
	}
	for i, e := range v.Log.Entries {
		resp := e["response"].(map[string]any)
		for _, k := range []string{"status", "httpVersion", "content", "redirectURL", "headers", "cookies"} {
			if _, ok := resp[k]; !ok {
				t.Errorf("entry %d: no response.%s", i, k)
			}
		}
		for _, k := range []string{"timings", "cache", "startedDateTime", "time"} {
			if _, ok := e[k]; !ok {
				t.Errorf("entry %d: no %s", i, k)
			}
		}
	}
	r0 := v.Log.Entries[0]["response"].(map[string]any)
	if r0["httpVersion"] != "HTTP/2" || len(v.Log.Entries[0]["request"].(map[string]any)["cookies"].([]any)) != 2 {
		t.Fatalf("%v", v.Log.Entries[0])
	}
	r1 := v.Log.Entries[1]["response"].(map[string]any)
	if r1["status"].(float64) != 0 || !strings.Contains(r1["comment"].(string), "never reached the server") {
		t.Fatalf("held: %v", r1)
	}
}

func TestParams(t *testing.T) {
	e := traffic.Entry{Method: "POST", URL: "http://app.test/api/notes/note_53ec/x%20y/?q=a%20b&page=2&flag",
		Headers: map[string]string{"content-type": "application/json", "x-csrf-token": "cd4b5e777d", "cookie": "sid=s3cr3t; theme=dark",
			"user-agent": "UA", "referer": "http://app.test/"},
		Body: traffic.Body{Body: `{"user":{"name":"Bo \"B\"","tags":["a1",7]},"ok":true,"n":null,"query":"mutation X { y }","id":"abc123XYZ"}`}}
	r, _ := RawRequest(e)
	ps := Params(r.Bytes)
	got := map[string]string{}
	for _, p := range ps {
		got[p.In+" "+p.Name] = p.Value
		span := string(r.Bytes[p.Start:p.End])
		switch p.In {
		case "json":
			if strings.HasPrefix(p.Value, "Bo") && span != `Bo \"B\"` {
				t.Errorf("json span %q", span)
			}
		case "query", "path":
			if p.Name == "q" && span != "a%20b" || p.Name == "seg4" && span != "x%20y" {
				t.Errorf("%s span %q", p.Name, span)
			}
		default:
			if span != p.Value {
				t.Errorf("%s %s: span %q, value %q", p.In, p.Name, span, p.Value)
			}
		}
	}
	want := map[string]string{"path seg1": "api", "path seg3": "note_53ec", "path seg4": "x y", "query q": "a b", "query page": "2", "query flag": "",
		"header x-csrf-token": "cd4b5e777d", "cookie sid": "s3cr3t", "cookie theme": "dark",
		"json $.user.name": `Bo "B"`, "json $.user.tags[0]": "a1", "json $.user.tags[1]": "7", "json $.ok": "true", "json $.n": "null",
		"json $.query": "mutation X { y }", "path seg2": "notes", "json $.id": "abc123XYZ"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["header user-agent"]; ok || len(got) != len(want) {
		t.Errorf("extra params: %v", got)
	}
	// The places agree with flow's, so that depends_on links find them.
	at := map[string]bool{}
	for _, v := range flowValues(e) {
		at[v] = true
	}
	for _, p := range ps {
		if p.At() == "body:$.id" || p.At() == "header:x-csrf-token" || p.At() == "path:3" {
			if !at[p.At()] {
				t.Errorf("flow has no %s", p.At())
			}
		}
	}

	// A cookie header written by hand, without spaces.
	hand := []byte("GET / HTTP/1.1\r\nHost: a\r\nCookie: a=1;b=22 ;  c=333\r\n\r\n")
	for _, p := range Params(hand) {
		if p.In == "cookie" && string(hand[p.Start:p.End]) != p.Value {
			t.Errorf("cookie %s: span %q, value %q", p.Name, hand[p.Start:p.End], p.Value)
		}
	}
	if n := len(Params(hand)); n != 3 {
		t.Errorf("%d cookies", n)
	}

	form := traffic.Entry{Method: "POST", URL: "http://app.test/f", Headers: map[string]string{"content-type": "application/x-www-form-urlencoded"},
		Body: traffic.Body{Body: "a=1&b=x+y&c="}}
	r, _ = RawRequest(form)
	if ps := Params(r.Bytes)[1:]; len(ps) != 3 || ps[1].Value != "x y" || string(r.Bytes[ps[2].Start:ps[2].End]) != "" {
		t.Fatalf("%+v", ps)
	}
	mp := traffic.Entry{Method: "POST", URL: "http://app.test/u", Headers: map[string]string{"content-type": "multipart/form-data; boundary=XX"},
		Body: traffic.Body{Body: "--XX\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\r\n--XX--\r\n"}}
	r, _ = RawRequest(mp)
	ps = Params(r.Bytes)[1:]
	if len(ps) != 2 || ps[0].Name != "title" || ps[0].Value != "hello" || ps[1].Name != "f.filename" || string(r.Bytes[ps[1].Start:ps[1].End]) != "a.png" {
		t.Fatalf("%+v", ps)
	}
	// A body the recorder cut: what is whole is read.
	cut := traffic.Entry{Method: "POST", URL: "http://app.test/c", Headers: map[string]string{"content-type": "application/json"},
		Body: traffic.Body{Body: `{"a":"1","b":{"c":"lo`, BodyTruncated: true}}
	r, _ = RawRequest(cut)
	if ps := Params(r.Bytes)[1:]; len(ps) != 1 || ps[0].Name != "$.a" {
		t.Fatalf("%+v", ps)
	}
}

func flowValues(e traffic.Entry) []string {
	var out []string
	for _, v := range flow.RequestValues(e) {
		out = append(out, v.At)
	}
	return out
}

func TestFix(t *testing.T) {
	at := func(s int) time.Time { return time.Unix(1000+int64(s), 0) }
	raw := &item{e: traffic.Entry{ID: 1, Time: at(1), Method: "GET", URL: "http://app.test/a", Headers: map[string]string{"host": "app.test", "cookie": "sid=1"}}}
	later := &item{e: traffic.Entry{ID: 5, Time: at(5), Method: "GET", URL: "http://app.test/c", Headers: map[string]string{"host": "app.test", "cookie": "sid=2"}}}
	held := &item{e: traffic.Entry{ID: 3, Time: at(3), Method: "POST", URL: "http://app.test/b", Page: "http://app.test/x",
		HeadersProvisional: true, Headers: map[string]string{"content-type": "application/json"}, Outcome: "held_back:write"}}
	first := &item{e: traffic.Entry{ID: 0, Time: at(0), Method: "GET", URL: "http://app.test/w", Headers: map[string]string{"user-agent": "UA"}}}
	other := &item{e: traffic.Entry{ID: 4, Time: at(4), Method: "GET", URL: "http://cdn.test/w", HeadersProvisional: true}}
	x := &exporter{}
	x.fix([]*item{first, raw, held, other, later})
	if held.e.Headers["cookie"] != "sid=1" || held.cookieFrom != 1 || held.e.Headers["origin"] != "http://app.test" {
		t.Fatalf("held: %+v %d", held.e.Headers, held.cookieFrom)
	}
	// Before any request went out: the next one's cookie.
	if first.e.Headers["cookie"] != "sid=1" || first.e.Headers["origin"] != "" {
		t.Fatalf("first: %+v", first.e.Headers)
	}
	if _, ok := other.e.Headers["cookie"]; ok {
		t.Fatal("a cookie of another host")
	}
	if raw.cookieFrom != 0 || raw.e.Headers["cookie"] != "sid=1" {
		t.Fatal("a request of the wire changed")
	}
	if got := representative([]*item{held, raw}); got != raw {
		t.Fatalf("representative %d", got.e.ID)
	}
}

func TestFuzzFile(t *testing.T) {
	e := traffic.Entry{Method: "POST", URL: "http://app.test/api/x?q=a%20b", Headers: map[string]string{"content-type": "application/json"},
		Body: traffic.Body{Body: `{"name":"Bo \"B\"","note":"Content-Length: 9\r\n"}`}}
	r, _ := RawRequest(e)
	it := &item{e: e, raw: r, params: Params(r.Bytes), tmpl: "/api/x"}
	b, ok := fuzzFile(it, ParamLine{In: "json", Name: "$.name"}, "FUZZ")
	if !ok || !strings.Contains(string(b), `{"name":"FUZZ","note":"Content-Length: 9\r\n"}`) || strings.Contains(string(b), "Content-Length: 4") {
		t.Fatalf("%q", b)
	}
	b, _ = fuzzFile(it, ParamLine{In: "query", Name: "q"}, "FUZZ")
	if !strings.HasPrefix(string(b), "POST /api/x?q=FUZZ HTTP/1.1\r\n") {
		t.Fatalf("%q", b)
	}
	if _, ok := fuzzFile(it, ParamLine{In: "query", Name: "nope"}, "FUZZ"); ok {
		t.Fatal("a param it does not have")
	}
}

func TestCheckDest(t *testing.T) {
	d := t.TempDir()
	if err := checkDest(d + "/new/export"); err != nil {
		t.Fatal(err)
	}
	if err := checkDest(d); err == nil {
		t.Fatal("would replace a directory jsharvest did not write")
	}
	os.WriteFile(d+"/manifest.json", []byte(`{"creator":"jsharvest export"}`), 0o600)
	if err := checkDest(d); err != nil {
		t.Fatal(err)
	}
}

func TestTypes(t *testing.T) {
	for v, want := range map[string]string{"42": "int", "4.2": "float", "true": "bool", "cd4b5e777d645459a88b29ed": "hex",
		"0b4cfd27-4c3c-4a1f-8f0a-1f2e3d4c5b6a": "uuid", "a@b.co": "email", "2026-11-04": "date", "/api/x": "url",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig": "jwt", "shoes": "string", `{"a":1}`: "json", "": "empty"} {
		if got := typeOf(map[string]bool{v: true}, ParamLine{}); got != want {
			t.Errorf("%q: %s, want %s", v, got, want)
		}
	}
	if typeOf(map[string]bool{"1": true, "2.5": true}, ParamLine{}) != "float" || typeOf(map[string]bool{"1": true, "x": true}, ParamLine{}) != "string" {
		t.Error("mixed")
	}
	if typeOf(map[string]bool{"mutation X { y }": true}, ParamLine{Name: "$.query"}) != "graphql" {
		t.Error("graphql")
	}
}
