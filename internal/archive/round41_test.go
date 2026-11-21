package archive

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestRound41WARCBadAndTruncatedLength(t *testing.T) {
	gzipBytes := func(raw string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(raw))
		_ = zw.Close()
		return buf.Bytes()
	}

	// 1. Negative Content-Length must return an error without panicking.
	neg := "WARC/1.0\r\nWARC-Type: response\r\nContent-Length: -1\r\n\r\n"
	if _, err := ReadRecord([]byte(neg), 4096); err == nil {
		t.Fatal("expected error on negative Content-Length")
	}
	if _, err := ReadRecord(gzipBytes(neg), 4096); err == nil {
		t.Fatal("expected error on gzipped negative Content-Length")
	}

	// 2. Huge Content-Length (1 TiB) must fail fast without allocating huge slice.
	huge := fmt.Sprintf("WARC/1.0\r\nWARC-Type: response\r\nContent-Length: %d\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", int64(1)<<40)
	if _, err := ReadRecord([]byte(huge), 4096); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected out of range error on 1<<40 Content-Length, got %v", err)
	}

	// 3. Truncated WARC block (declares Content-Length: 10000, provides ~100 bytes) must return ErrUnexpectedEOF.
	shortHTTP := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + strings.Repeat("a", 43) // 100 bytes
	trunc := fmt.Sprintf("WARC/1.0\r\nWARC-Type: response\r\nContent-Length: 10000\r\n\r\n%s", shortHTTP)
	if _, err := ReadRecord([]byte(trunc), 64<<10); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF on truncated WARC record, got %v", err)
	}
	if _, err := ReadRecord(gzipBytes(trunc), 64<<10); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF on gzipped truncated WARC record, got %v", err)
	}

	// 4. Valid WARC response within limit still decodes cleanly.
	validHTTP := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nconst ok = 1;\n"
	valid := fmt.Sprintf("WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: https://app.example/a.js\r\nContent-Length: %d\r\n\r\n%s", len(validHTTP), validHTTP)
	rec, err := ReadRecord(gzipBytes(valid), 4096)
	if err != nil || rec.Status != 200 || string(rec.Body) != "const ok = 1;\n" {
		t.Fatalf("valid WARC failed: rec=%+v err=%v", rec, err)
	}
}
