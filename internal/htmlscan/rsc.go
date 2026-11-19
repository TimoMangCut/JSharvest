package htmlscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

const (
	minRSCCompactBytes = 16 << 10 // 16 KiB
	maxSeenRSCRows     = 65536
)

var (
	rscPushPrefix1 = []byte("self.__next_f.push(")
	rscPushPrefix2 = []byte("(self.__next_f=self.__next_f||[]).push(")
)

// RSCDeduper strips previously seen Next.js App Router Flight rows from large
// inline self.__next_f.push([tag, "..."]) scripts on the same origin while
// keeping 100% of novel rows (and 100% of the first page's payload) as valid JS.
type RSCDeduper struct {
	mu     sync.Mutex
	seen   map[string]map[[32]byte]struct{}
	total  int
	frozen bool
}

// Freeze switches RSCDeduper into read-only filter mode so concurrent multi-tab
// browser crawls strip already-learned RootLayout rows without order-dependent
// cross-tab state mutation.
func (d *RSCDeduper) Freeze() {
	d.mu.Lock()
	d.frozen = true
	d.mu.Unlock()
}

// Compact returns (compactedCode, keep). For non-RSC or small inline scripts,
// or when every row in the payload is novel, code is returned unchanged with
// keep=true. When all rows were already observed on the same origin, keep=false.
func (d *RSCDeduper) Compact(origin string, code []byte) ([]byte, bool) {
	if len(code) < minRSCCompactBytes || origin == "" {
		return code, true
	}
	trimmed := bytes.TrimSpace(code)
	trimmed = bytes.TrimRight(trimmed, "; \t\r\n")
	var argBytes []byte
	switch {
	case bytes.HasPrefix(trimmed, rscPushPrefix1) && trimmed[len(trimmed)-1] == ')':
		argBytes = bytes.TrimSpace(trimmed[len(rscPushPrefix1) : len(trimmed)-1])
	case bytes.HasPrefix(trimmed, rscPushPrefix2) && trimmed[len(trimmed)-1] == ')':
		argBytes = bytes.TrimSpace(trimmed[len(rscPushPrefix2) : len(trimmed)-1])
	default:
		return code, true
	}
	if len(argBytes) < 6 || argBytes[0] != '[' || argBytes[len(argBytes)-1] != ']' {
		return code, true
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(argBytes, &arr); err != nil || len(arr) != 2 {
		return code, true
	}
	var tag int
	if err := json.Unmarshal(arr[0], &tag); err != nil {
		return code, true
	}
	var flight string
	if err := json.Unmarshal(arr[1], &flight); err != nil || flight == "" {
		return code, true
	}

	rawRows := strings.Split(flight, "\n")
	trailingNL := strings.HasSuffix(flight, "\n")
	nonEmpty := 0
	for _, r := range rawRows {
		if r != "" {
			nonEmpty++
		}
	}
	if nonEmpty == 0 {
		return code, true
	}

	var novel []string
	d.mu.Lock()
	originMap := d.seen[origin]
	if originMap == nil && !d.frozen && d.total < maxSeenRSCRows {
		originMap = make(map[[32]byte]struct{})
		if d.seen == nil {
			d.seen = make(map[string]map[[32]byte]struct{})
		}
		d.seen[origin] = originMap
	}
	for _, row := range rawRows {
		if row == "" {
			continue
		}
		sum := sha256.Sum256([]byte(stripRSCRowID(row)))
		if originMap != nil {
			if _, ok := originMap[sum]; ok {
				continue
			}
			if !d.frozen && d.total < maxSeenRSCRows {
				originMap[sum] = struct{}{}
				d.total++
			}
		}
		novel = append(novel, row)
	}
	d.mu.Unlock()

	if len(novel) == nonEmpty {
		return code, true
	}
	if len(novel) == 0 {
		return nil, false
	}

	joined := strings.Join(novel, "\n")
	if trailingNL {
		joined += "\n"
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(joined); err != nil {
		return code, true
	}
	encodedStr := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	out := fmt.Appendf(nil, "self.__next_f.push([%d,%s])", tag, encodedStr)
	return out, true
}

// stripRSCRowID removes a leading 1..8 hex-digit Flight row identifier ("17:...")
// so identical layout/dictionary payloads renumbered across routes hash identically.
func stripRSCRowID(row string) string {
	limit := min(len(row), 9)
	colon := -1
	for i := 0; i < limit; i++ {
		c := row[i]
		if c == ':' {
			if i > 0 {
				colon = i
			}
			break
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			break
		}
	}
	if colon > 0 {
		return row[colon+1:]
	}
	return row
}
