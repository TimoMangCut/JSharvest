package verify

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestDraftRawSanitizesCRLFAndInvalidHeaderNames(t *testing.T) {
	d := Draft{
		ID:     "d1",
		Method: "POST",
		Headers: [][2]string{
			{"X-Tenant", "acme\r\nX-Evil: injected"},
			{"Bad Header\r\nName", "boom"},
			{"X-Clean", "ok-value"},
		},
		Body: []byte(`{"id":1}`),
	}
	rawBytes, err := d.raw("https://api.example.test/v1/items", false)
	if err != nil {
		t.Fatalf("Draft.raw failed: %v", err)
	}
	rawStr := string(rawBytes)
	if strings.Contains(rawStr, "\r\nX-Evil:") || strings.Contains(rawStr, "Bad Header") {
		t.Fatalf("CRLF header injection survived Draft.raw:\n%s", rawStr)
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawBytes)))
	if err != nil {
		t.Fatalf("sanitized Draft.raw output is not valid HTTP/1.1: %v\n%s", err, rawStr)
	}
	if req.Header.Get("X-Evil") != "" {
		t.Fatalf("injected X-Evil header parsed into request!")
	}
	if req.Header.Get("X-Clean") != "ok-value" || req.Header.Get("X-Tenant") != "acmeX-Evil: injected" {
		t.Fatalf("unexpected headers after sanitization: %+v", req.Header)
	}
}
