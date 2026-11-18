// Package archive lists a target's history from public archives (Wayback,
// Common Crawl, OTX, URLScan), fetches its old scripts, and finds the
// endpoints only they name. See docs/gd5-archive-design.md.
package archive

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Record is a WARC response record: its WARC headers, and the HTTP
// response it holds, the body as the server meant it (no chunks, no
// content coding).
type Record struct {
	Type          string // response, revisit…
	TargetURI     string
	PayloadDigest string // sha1:<base32>
	Status        int
	Header        http.Header
	Body          []byte
}

var ErrNotResponse = errors.New("not a WARC response record")

// ReadRecord reads one record of a WARC file range: a gzip member, as
// Common Crawl stores each record, or plain bytes.
func ReadRecord(b []byte, max int) (*Record, error) {
	var r io.Reader = bytes.NewReader(b)
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		zr.Multistream(false)
		r = zr
	}
	br := bufio.NewReader(io.LimitReader(r, int64(max)+1<<20))
	tp := textproto.NewReader(br)
	version, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(version, "WARC/") {
		return nil, fmt.Errorf("no WARC record: %q", version)
	}
	wh, err := tp.ReadMIMEHeader()
	if err != nil && len(wh) == 0 {
		return nil, err
	}
	rec := &Record{Type: wh.Get("WARC-Type"), TargetURI: wh.Get("WARC-Target-URI"), PayloadDigest: wh.Get("WARC-Payload-Digest")}
	if rec.Type != "response" {
		return rec, ErrNotResponse
	}
	n, err := strconv.Atoi(wh.Get("Content-Length"))
	if err != nil {
		return nil, fmt.Errorf("WARC Content-Length: %w", err)
	}
	block := make([]byte, n)
	if _, err := io.ReadFull(br, block); err != nil {
		return nil, fmt.Errorf("WARC block: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(block)), nil)
	if err != nil {
		return nil, fmt.Errorf("HTTP response: %w", err)
	}
	defer resp.Body.Close()
	// http.ReadResponse undoes chunking; a content coding stays.
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	rec.Status, rec.Header = resp.StatusCode, resp.Header
	body, err = decode(resp.Header.Get("Content-Encoding"), body, max)
	if err != nil {
		return nil, err
	}
	if len(body) > max {
		return nil, fmt.Errorf("body over %d bytes", max)
	}
	rec.Body = body
	return rec, nil
}

// zstdMagic starts a Zstandard frame.
var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// decode undoes a content coding: gzip, deflate, zstd and br; identity as
// it is. A body that is a Zstandard frame though no coding is named (an
// archive that kept the bytes and dropped the header) is decoded too.
func decode(coding string, b []byte, max int) ([]byte, error) {
	var r io.Reader
	c := strings.ToLower(strings.TrimSpace(coding))
	if (c == "" || c == "identity") && bytes.HasPrefix(b, zstdMagic) {
		c = "zstd"
	}
	switch c {
	case "", "identity":
		return b, nil
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderMaxMemory(uint64(max)+1<<20), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, fmt.Errorf("decode zstd: %w", err)
		}
		defer zr.Close()
		r = zr
	case "br":
		r = brotli.NewReader(bytes.NewReader(b))
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			// Some archives store the body decoded but keep the header.
			return b, nil
		}
		defer zr.Close()
		r = zr
	case "deflate":
		rc := flate.NewReader(bytes.NewReader(b))
		defer rc.Close()
		r = rc
	default:
		return nil, fmt.Errorf("content coding %q not supported", coding)
	}
	out, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", coding, err)
	}
	return out, nil
}
