package traffic

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSensitive(t *testing.T) {
	yes := []string{"password", "Password", "user_password", "passwd", "pwd", "X-CSRF-Token", "x-xsrf-token", "accessToken",
		"refresh_token", "refreshtoken", "client_secret", "clientSecret", "session_id", "sessionId", "PHPSESSID", "JSESSIONID",
		"sid", "api_key", "apiKey", "X-Api-Key", "key", "code", "pin", "sig", "otp", "jwt", "Authorization", "auth", "x-auth-token",
		"credentials", "signature", "csrfmiddlewaretoken", "authenticity_token",
		"passcode", "newpass", "oauth_verifier", "authcode", "verification_code", "recovery_codes", "private_key", "access_key",
		"x-access-key", "x-private-key", "api_keys", "SAMLResponse", "ticket"}
	no := []string{"username", "email", "q", "page", "id", "name", "country_code", "zipcode", "keyword", "monkey", "authority",
		":authority", "author", "content-type", "accept", "sidebar", "passenger", "description", "design", "codec", "keys_count"}
	for _, n := range yes {
		if !Sensitive(n) {
			t.Errorf("Sensitive(%q) = false", n)
		}
	}
	for _, n := range no {
		if Sensitive(n) {
			t.Errorf("Sensitive(%q) = true", n)
		}
	}
}

func TestRedactText(t *testing.T) {
	r := NewRedactor()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	cases := []struct{ in, gone, kept string }{
		{`{"user":"bob","password":"hunter2"}`, "hunter2", `"user":"bob"`},
		{`{"a":{"refresh_token": "abc.def"},"n":1}`, "abc.def", `"n":1`},
		{`{"pin": 1234, "page": 2}`, "1234", `"page": 2`},
		{`{"password":"with \"quote\" inside"}`, "quote", `"password"`},
		{`user=bob&password=hunter2&next=%2F`, "hunter2", "user=bob"},
		{`csrf_token=s3cr3tval`, "s3cr3tval", "csrf_token="},
		{`{"redirect":"/cb?code=oauthcode123&state=x"}`, "oauthcode123", "state=x"},
		{"Bearer " + jwt, jwt, "Bearer"},
		{`{"data":"` + jwt + `"}`, jwt, `"data"`},
		{"--b\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nbob\r\n--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--b--", "hunter2", "bob"},
		{`<input type="hidden" name="authenticity_token" value="tok3n=="><input name="q" value="shoes">`, "tok3n==", `value="shoes"`},
		{`<input value='tok3n' name='csrf'>`, "tok3n", "name='csrf'"},
		{`{"recovery_codes":["111111","222222"],"n":1}`, "111111", `"n":1`},
		{`{"data":"{\"password\":\"hunter2\"}"}`, "hunter2", `"data"`},
		{`{"query":"mutation { login(user: \"bob\", password: \"hunter2\") { ok } }"}`, "hunter2", `user: \"bob\"`},
		{`var token = "abc123secret"; var title = "x";`, "abc123secret", `title = "x"`},
		{`{apiToken:'xyz789','password':'p4ss'}`, "xyz789", "{apiToken:"},
		{`{apiToken:'xyz789','password':'p4ss'}`, "p4ss", "'password':"},
		{"--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nline1\nline2\r\n--b--", "line2", "--b--"},
		// Truncated JSON: the open string is still hidden.
		{`{"user":"bob","password":"hunter2-cut-of`, "hunter2", `"user":"bob"`},
	}
	for _, c := range cases {
		got := r.Text(c.in)
		if strings.Contains(got, c.gone) {
			t.Errorf("Text(%q) = %q, still has %q", c.in, got, c.gone)
		}
		if !strings.Contains(got, c.kept) {
			t.Errorf("Text(%q) = %q, lost %q", c.in, got, c.kept)
		}
		if !strings.Contains(got, "REDACTED_") {
			t.Errorf("Text(%q) = %q, no marker", c.in, got)
		}
	}
	for _, keep := range []string{`{"q":"shoes","page":2}`, `{"code":200,"message":"ok"}`, `<input type="password" name="q" value="x">`,
		`{"country_code":"VN","passenger":"bob"}`} {
		if got := r.Text(keep); got != keep {
			t.Errorf("changed a body with nothing to hide: %q -> %q", keep, got)
		}
	}
}

func TestRedactStableWithinRunOnly(t *testing.T) {
	r1, r2 := NewRedactor(), NewRedactor()
	a, b := r1.Text("password=x1"), r1.Text(`{"password":"x1"}`)
	if !strings.Contains(b, strings.TrimPrefix(a, "password=")) {
		t.Errorf("same value, different marks in one run: %q %q", a, b)
	}
	if r1.Text("password=x1") == r2.Text("password=x1") {
		t.Error("two runs gave the same mark: the key is not random")
	}
	if r1.Text(r1.Text("password=x1")) != r1.Text("password=x1") {
		t.Error("redacting twice changed the mark")
	}
}

func TestRedactHeaders(t *testing.T) {
	r := NewRedactor()
	h := r.Headers(map[string]string{
		"cookie":                           "sid=abc123; theme=dark",
		"set-cookie":                       "sid=abc123; Path=/; HttpOnly\nlang=vi; Path=/",
		"authorization":                    "Bearer abc123",
		"x-csrf-token":                     "abc123",
		"referer":                          "http://app/cb?token=abc123&x=1",
		"access-control-allow-credentials": "true",
		":authority":                       "app.example",
		"content-type":                     "application/json",
	})
	for k, v := range h {
		if strings.Contains(v, "abc123") {
			t.Errorf("%s still has the secret: %q", k, v)
		}
	}
	for k, want := range map[string]string{
		"access-control-allow-credentials": "true", ":authority": "app.example", "content-type": "application/json",
	} {
		if h[k] != want {
			t.Errorf("%s = %q, want %q", k, h[k], want)
		}
	}
	if !strings.HasPrefix(h["cookie"], "sid=REDACTED_") || !strings.Contains(h["cookie"], "; theme=REDACTED_") {
		t.Errorf("cookie = %q", h["cookie"])
	}
	if !strings.Contains(h["set-cookie"], "; Path=/; HttpOnly\nlang=REDACTED_") {
		t.Errorf("set-cookie = %q", h["set-cookie"])
	}
	if !strings.HasPrefix(h["authorization"], "Bearer REDACTED_") {
		t.Errorf("authorization = %q", h["authorization"])
	}
}

func TestRedactURL(t *testing.T) {
	r := NewRedactor()
	got := r.URL("https://admin:hunter2@app.example/reset?token=abc123&lang=vi#top")
	for _, s := range []string{"hunter2", "abc123"} {
		if strings.Contains(got, s) {
			t.Errorf("URL kept %q: %s", s, got)
		}
	}
	if !strings.Contains(got, "lang=vi#top") || !strings.Contains(got, "admin:") {
		t.Errorf("URL lost too much: %s", got)
	}
}

func TestMakeBody(t *testing.T) {
	b := MakeBody([]byte("hello"), 3)
	if b.Body != "hel" || !b.BodyTruncated || b.BodyBase64 {
		t.Errorf("truncate: %+v", b)
	}
	bin := []byte{0xff, 0x00, 0x01}
	b = MakeBody(bin, 100)
	if !b.BodyBase64 || !bytes.Equal(b.Bytes(), bin) {
		t.Errorf("binary: %+v", b)
	}
	// Redaction leaves binary alone.
	if NewRedactor().Body(b) != b {
		t.Error("binary body changed")
	}
	// Text cut inside a character stays text.
	b = MakeBody([]byte(`{"access_token":"SECRET","t":"Việt"}`), 34)
	if b.BodyBase64 || !b.BodyTruncated || !strings.HasSuffix(b.Body, `"Vi`) {
		t.Errorf("cut text: %+v", b)
	}
	// A body with binary parts is still searched for credentials.
	mixed := append([]byte("password=hunter2&f="), 0xff, 0xfe)
	b = NewRedactor().Body(MakeBody(mixed, 100))
	if !b.BodyBase64 || bytes.Contains(b.Bytes(), []byte("hunter2")) {
		t.Errorf("mixed body: %q", b.Bytes())
	}
}

func TestMode(t *testing.T) {
	if API.Wants("Script") || API.Wants("Image") || !API.Wants("XHR") || !API.Wants("Document") || !API.Wants("Preflight") {
		t.Error("api mode filter")
	}
	if !All.Wants("Script") || Off.Wants("XHR") {
		t.Error("all/off")
	}
	if ok, _ := API.WantsBody("Fetch", "application/json; charset=utf-8"); !ok {
		t.Error("json fetch body")
	}
	if ok, why := API.WantsBody("Fetch", "image/png"); ok || why != "mime" {
		t.Error("png body")
	}
	if ok, why := API.WantsBody("Stylesheet", "text/css"); ok || why != "type" {
		t.Error("css body in api mode")
	}
}

func TestWriter(t *testing.T) {
	dir := t.TempDir()
	w, err := Create(dir, "run1", NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	w.Write(Entry{Method: "POST", URL: "http://a/login", Body: MakeBody([]byte("password=hunter2"), 100), Outcome: "ok"})
	w.Write(Entry{Method: "GET", URL: "http://a/", Outcome: "ok"})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "requests.jsonl")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte("hunter2")) {
		t.Error("secret written")
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	var e Entry
	json.Unmarshal(lines[1], &e)
	if e.ID != 2 || e.Run != "run1" {
		t.Errorf("second entry: id %d run %q", e.ID, e.Run)
	}
}
