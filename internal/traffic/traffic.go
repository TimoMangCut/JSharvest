// Package traffic is the request log: one JSON line per request a harvest
// saw, with its response, written to requests.jsonl for grouping into
// features and for fuzzing. It holds real credentials unless redacted.
package traffic

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// GuardHeader marks a response the guard made up for a request it held
// back, so that the log does not take it for the server's. Its value is the
// guard's reason.
const GuardHeader = "X-Jsharvest-Guard"

// Entry is one request, or one hop of a redirect chain.
type Entry struct {
	Run        string    `json:"run"`
	Tab        int       `json:"tab,omitempty"` // the tab of the run it came from (crawl -tabs); 0 with one
	ID         int       `json:"id"`
	Time       time.Time `json:"ts"`
	DurationMS float64   `json:"duration_ms,omitempty"`
	Target     string    `json:"target"`
	TargetURL  string    `json:"target_url,omitempty"`
	Page       string    `json:"page,omitempty"`
	Frame      string    `json:"frame,omitempty"`
	CDPID      string    `json:"cdp_id,omitempty"`
	Hop        int       `json:"hop,omitempty"`
	Source     string    `json:"source,omitempty"` // "guard" for a held-back request no session saw

	ResourceType string            `json:"resource_type"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	// HeadersProvisional says Headers are what the page asked for, not
	// what went on the wire (no Cookie, no Host): Chrome reports the wire's
	// only for a request that reached the network, so not for one the guard
	// held back, a worker's, or one the cache answered.
	HeadersProvisional bool `json:"headers_provisional,omitempty"`
	Body
	Response  *Response  `json:"response,omitempty"`
	Initiator *Initiator `json:"initiator,omitempty"`
	// Outcome is ok, redirect, failed:<error>, held_back:<reason> or
	// incomplete (still open when the capture stopped).
	Outcome string   `json:"outcome"`
	Tags    []string `json:"tags,omitempty"`
}

type Response struct {
	Status     int64             `json:"status"`
	StatusText string            `json:"status_text,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	MIME       string            `json:"mime,omitempty"`
	// Source is network, disk-cache, service-worker, prefetch or early-hints.
	Source   string `json:"source"`
	Protocol string `json:"protocol,omitempty"`
	RemoteIP string `json:"remote_ip,omitempty"`
	// TLSIncompleteChain: the server sent an incomplete certificate chain
	// (its intermediates were fetched from the AIA).
	TLSIncompleteChain bool `json:"tls_incomplete_chain,omitempty"`
	Body
	// BodyOmitted says why there is no body: type, mime, size, or
	// lost:<reason> when Chrome no longer had it.
	BodyOmitted string `json:"body_omitted,omitempty"`
}

// Body is a request or response body. Text that is not UTF-8 is kept as
// base64.
type Body struct {
	Body          string `json:"body,omitempty"`
	BodyBase64    bool   `json:"body_base64,omitempty"`
	BodyTruncated bool   `json:"body_truncated,omitempty"`
}

// MakeBody keeps at most max bytes of b.
func MakeBody(b []byte, max int) Body {
	var out Body
	if len(b) > max {
		b, out.BodyTruncated = b[:max], true
		// Text cut inside a character would read as binary: cut before it.
		for i := 1; i < utf8.UTFMax && i < len(b) && !utf8.Valid(b); i++ {
			if utf8.Valid(b[:len(b)-i]) {
				b = b[:len(b)-i]
			}
		}
	}
	if utf8.Valid(b) {
		out.Body = string(b)
	} else {
		out.Body, out.BodyBase64 = base64.StdEncoding.EncodeToString(b), true
	}
	return out
}

// Bytes returns the body as it was sent or received.
func (b Body) Bytes() []byte {
	if b.BodyBase64 {
		out, _ := base64.StdEncoding.DecodeString(b.Body)
		return out
	}
	return []byte(b.Body)
}

type Initiator struct {
	Type  string  `json:"type"`
	URL   string  `json:"url,omitempty"`
	Line  int64   `json:"line,omitempty"`
	Col   int64   `json:"col,omitempty"`
	Stack []Frame `json:"stack,omitempty"`
	// Chain is every async boundary of the stack, nearest first ("await",
	// "setTimeout", and the action tags jsharvest's page script names
	// "jsh:…"), kept apart from Stack so that a deep stack does not cut it.
	Chain []string `json:"chain,omitempty"`
}

type Frame struct {
	Func string `json:"fn,omitempty"`
	URL  string `json:"url,omitempty"`
	Line int64  `json:"line"`
	Col  int64  `json:"col"`
	// Async names the async boundary crossed before this frame, such as
	// "Promise.then" or "setTimeout".
	Async string `json:"async,omitempty"`
}

// Mode chooses which requests get a line.
type Mode string

const (
	Off Mode = "off"
	API Mode = "api" // everything but static subresources
	All Mode = "all"
)

// static are the resource types that api mode leaves out: scripts are in
// the script store, and the rest carries no application traffic.
var static = map[string]bool{"Script": true, "Stylesheet": true, "Image": true, "Media": true, "Font": true, "TextTrack": true}

// Wants reports whether a request of the given CDP resource type is
// recorded.
func (m Mode) Wants(resourceType string) bool {
	switch m {
	case All:
		return true
	case API:
		return !static[resourceType]
	}
	return false
}

// bodyTypes are the resource types whose response body api mode keeps.
var bodyTypes = map[string]bool{"Document": true, "XHR": true, "Fetch": true, "Other": true, "EventSource": true}

// WantsBody reports whether a response body is worth fetching: application
// data in a text format.
func (m Mode) WantsBody(resourceType, mime string) (bool, string) {
	if m != All && !bodyTypes[resourceType] {
		return false, "type"
	}
	if !TextMIME(mime) {
		return false, "mime"
	}
	return true, ""
}

// TextMIME reports whether a MIME type is text worth reading.
func TextMIME(m string) bool {
	switch {
	case m == "":
		return false
	case strings.HasPrefix(m, "text/"):
		return true
	}
	for _, s := range []string{"json", "xml", "javascript", "ecmascript", "x-www-form-urlencoded", "graphql", "html"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// Writer appends entries to requests.jsonl, numbering them in the order
// written. The file is created 0600: it holds cookies and tokens.
type Writer struct {
	internal int // entries tagged jsharvest
	mu       sync.Mutex
	f        *os.File
	enc      *json.Encoder
	run      string
	next     int
	redact   *Redactor
	err      error
}

// AppendOpen opens path for appending JSONL records (0600). If a previous run
// crashed mid-line leaving a non-empty file that does not end with '\n',
// AppendOpen writes a trailing '\n' first so the next record starts on its own
// line instead of concatenating onto the truncated fragment.
func AppendOpen(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], st.Size()-1); err != nil {
			f.Close()
			return nil, err
		}
		if last[0] != '\n' {
			if _, err := f.Write([]byte{'\n'}); err != nil {
				f.Close()
				return nil, err
			}
		}
	}
	return f, nil
}

// Create opens dir/requests.jsonl for appending. A nil redactor keeps the
// values as they were.
func Create(dir, run string, redact *Redactor) (*Writer, error) {
	f, err := AppendOpen(filepath.Join(dir, "requests.jsonl"))
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, enc: json.NewEncoder(f), run: run, next: 1, redact: redact}, nil
}

// Write numbers, redacts and appends one entry. The first error sticks and
// is returned by Close.
func (w *Writer) Write(e Entry) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return
	}
	e.Run, e.ID = w.run, w.next
	w.next++
	if slices.Contains(e.Tags, "jsharvest") {
		w.internal++
	}
	if w.redact != nil {
		w.redact.Entry(&e)
	}
	w.err = w.enc.Encode(e)
}

// Internal is how many of them were the tool's own asking (tag
// jsharvest: the resolver's fetches, well-known files, source maps).
func (w *Writer) Internal() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.internal
}

// Count is how many entries were written.
func (w *Writer) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.next - 1
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.f.Close(); w.err == nil {
		w.err = err
	}
	return w.err
}
