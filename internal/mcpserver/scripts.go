package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TimoMangCut/JSharvest/internal/secretsig"
)

// Limits of search_scripts and read_script (plan-28 section 8).
const (
	scriptReadDefault = 32 << 10
	scriptReadMax     = 56 << 10  // JSON escaping can double it, and maxReply is 120 KB
	searchMaxFile     = 50 << 20  // a larger script is skipped
	searchMaxBytes    = 200 << 20 // bytes scanned in one call
	searchLimitDef    = 50
	searchLimitMax    = 200
	searchCtxDef      = 80
	searchCtxMax      = 400
	searchBudget      = 90 << 10 // bytes of snippets in one answer
	queryMin          = 2
	queryMax          = 200
	pageBackoff       = 256 // a page ends after a delimiter found this close to its end
	maxSkipped        = 20
)

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// scriptBearerRe matches hardcoded Bearer credentials in script source.
var scriptBearerRe = regexp.MustCompile(`(?i:\bBearer\s+)[A-Za-z0-9._~+/=-]{16,}`)

// scriptText hides credentials in a piece of script, unless -reveal.
func (s *server) scriptText(t string) string {
	if s.red == nil {
		return t
	}
	t = secretsig.ReplaceAllFunc(t, s.red.Value)
	t = scriptBearerRe.ReplaceAllStringFunc(t, func(m string) string {
		if i := strings.IndexAny(m, " \t\r\n"); i > 0 { // Bearer <token>
			return m[:i] + " " + s.red.Value(strings.TrimSpace(m[i:]))
		}
		return s.red.Value(m)
	})
	return s.text(t)
}

type scriptRef struct {
	SHA256 string   `json:"sha256"`
	URLs   []string `json:"urls"`
	Size   int      `json:"size"`
}

// indexed reads the script index of d: the only source of what a sha256
// may name.
func indexed(dir string) ([]scriptRef, error) {
	f, err := os.Open(filepath.Join(dir, "index.jsonl"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no index.jsonl in %s: nothing was harvested here yet", dir)
		}
		return nil, err
	}
	defer f.Close()
	var out []scriptRef
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r scriptRef
		if json.Unmarshal(sc.Bytes(), &r) != nil || !shaRe.MatchString(r.SHA256) {
			continue
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// openScript opens js/<sha>.js of dir. The path is built from the directory,
// "js" and a sha256 that matched ^[0-9a-f]{64}$: never from a name in a
// sourcemap or from the caller. Only a regular file is opened.
func openScript(dir, sha string) (*os.File, os.FileInfo, error) {
	if !shaRe.MatchString(sha) {
		return nil, nil, fmt.Errorf("sha256 must be 64 lowercase hex characters")
	}
	p := filepath.Join(dir, "js", sha+".js")
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("script %s is not a regular file", sha)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	return f, fi, nil
}

// --- search_scripts ---

type searchIn struct {
	Query       string `json:"query" jsonschema:"text to find in the scripts' code (2 to 200 characters), case-sensitive"`
	Regex       bool   `json:"regex,omitempty" jsonschema:"query is a regular expression (RE2 syntax)"`
	URLContains string `json:"url_contains,omitempty" jsonschema:"only scripts with a URL containing this text"`
	Limit       int    `json:"limit,omitempty" jsonschema:"at most this many matches (default 50, at most 200)"`
	Context     int    `json:"context,omitempty" jsonschema:"bytes of code around each match (default 80, at most 400)"`
}

type searchHit struct {
	SHA256                 string `json:"sha256"`
	URL                    string `json:"url,omitempty"`
	Offset                 int    `json:"offset"`
	Snippet                string `json:"snippet"`
	SuspiciousInstructions bool   `json:"suspicious_instructions,omitempty"`
}

type skippedScript struct {
	SHA256 string `json:"sha256"`
	Reason string `json:"reason"`
}

type searchOut struct {
	Dir                    string          `json:"dir"`
	Matches                []searchHit     `json:"matches"`
	TotalMatches           int             `json:"total_matches"`
	ScriptsScanned         int             `json:"scripts_scanned"`
	BytesScanned           int64           `json:"bytes_scanned"`
	Truncated              bool            `json:"truncated,omitempty"`
	Skipped                []skippedScript `json:"skipped,omitempty"`
	SuspiciousInstructions bool            `json:"suspicious_instructions,omitempty"`
}

func (s *server) searchScripts(ctx context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, any, error) {
	if n := utf8.RuneCountInString(in.Query); n < queryMin || n > queryMax {
		return nil, nil, fmt.Errorf("query must be %d to %d characters", queryMin, queryMax)
	}
	var re *regexp.Regexp
	if in.Regex {
		var err error
		if re, err = regexp.Compile(in.Query); err != nil {
			return nil, nil, fmt.Errorf("query is not a valid RE2 regular expression: %v", err)
		}
	}
	d, err := s.dir()
	if err != nil {
		return nil, nil, err
	}
	refs, err := indexed(d.Path)
	if err != nil {
		return nil, nil, err
	}
	limit := clamp(in.Limit, searchLimitDef, searchLimitMax)
	cx := clamp(in.Context, searchCtxDef, searchCtxMax)
	out := searchOut{Dir: d.Path, Matches: []searchHit{}}
	budget := 0
	needle := []byte(in.Query)

scan:
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			out.Truncated = true
			break
		}
		url := ""
		if len(ref.URLs) > 0 {
			url = ref.URLs[0]
		}
		if in.URLContains != "" {
			ok := false
			for _, u := range ref.URLs {
				if strings.Contains(u, in.URLContains) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		skip := func(why string) {
			if len(out.Skipped) < maxSkipped {
				out.Skipped = append(out.Skipped, skippedScript{ref.SHA256, why})
			}
		}
		f, fi, err := openScript(d.Path, ref.SHA256)
		if err != nil {
			skip("unreadable")
			continue
		}
		if fi.Size() > searchMaxFile {
			f.Close()
			skip(fmt.Sprintf("over %d MB", searchMaxFile>>20))
			continue
		}
		if out.BytesScanned+fi.Size() > searchMaxBytes {
			f.Close()
			out.Truncated = true
			break
		}
		data, err := io.ReadAll(io.LimitReader(f, searchMaxFile+1))
		f.Close()
		if err != nil {
			skip("unreadable")
			continue
		}
		out.ScriptsScanned++
		out.BytesScanned += int64(len(data))

		var locs [][]int
		if re != nil {
			locs = re.FindAllIndex(data, limit-len(out.Matches)+1)
		} else {
			for pos := 0; len(locs) <= limit-len(out.Matches); {
				i := bytes.Index(data[pos:], needle)
				if i < 0 {
					break
				}
				locs = append(locs, []int{pos + i, pos + i + len(needle)})
				pos += i + len(needle)
			}
		}
		for _, l := range locs {
			if l[1] == l[0] {
				continue // an empty match says nothing
			}
			if len(out.Matches) >= limit {
				out.Truncated = true
				break scan
			}
			snip := s.scriptText(snippet(data, l[0], l[1], cx))
			if budget+len(snip) > searchBudget {
				out.Truncated = true
				break scan
			}
			budget += len(snip) + len(ref.SHA256) + len(url) + 40
			out.TotalMatches++
			susp := hasPromptInjection(snip)
			if susp {
				out.SuspiciousInstructions = true
			}
			out.Matches = append(out.Matches, searchHit{SHA256: ref.SHA256, URL: s.url(url), Offset: l[0], Snippet: snip, SuspiciousInstructions: susp})
		}
	}
	return s.reply(out)
}

// snippet is data around [start, end), at most cx bytes on each side and the
// match itself cut to cx bytes, on UTF-8 boundaries.
func snippet(data []byte, start, end, cx int) string {
	if end-start > cx {
		end = start + cx
	}
	a := max(start-cx, 0)
	b := min(end+cx, len(data))
	for a < start && !utf8.RuneStart(data[a]) {
		a++
	}
	for b > end && b < len(data) && !utf8.RuneStart(data[b]) {
		b--
	}
	return strings.ToValidUTF8(string(data[a:b]), "\uFFFD")
}

// --- read_script ---

type readIn struct {
	SHA256 string `json:"sha256" jsonschema:"the script's sha256 (64 lowercase hex characters), as search_scripts or get_intel gives it; it must be in the harvest's index"`
	Offset int    `json:"offset,omitempty" jsonschema:"byte offset to read from (default 0); use next_offset of the previous page"`
	Length int    `json:"length,omitempty" jsonschema:"bytes to read (default 32768, at most 57344); a page ends on a character boundary and may be a little shorter"`
}

type readOut struct {
	SHA256                 string   `json:"sha256"`
	URLs                   []string `json:"urls"`
	Size                   int64    `json:"size"`
	Offset                 int64    `json:"offset"`
	Length                 int      `json:"length"`
	NextOffset             *int64   `json:"next_offset"`
	Content                string   `json:"content"`
	SuspiciousInstructions bool     `json:"suspicious_instructions,omitempty"`
}

func (s *server) readScript(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, any, error) {
	if !shaRe.MatchString(in.SHA256) {
		return nil, nil, fmt.Errorf("sha256 must be 64 lowercase hex characters")
	}
	if in.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must not be negative")
	}
	d, err := s.dir()
	if err != nil {
		return nil, nil, err
	}
	refs, err := indexed(d.Path)
	if err != nil {
		return nil, nil, err
	}
	var ref *scriptRef
	for i := range refs {
		if refs[i].SHA256 == in.SHA256 {
			ref = &refs[i]
			break
		}
	}
	if ref == nil {
		return nil, nil, fmt.Errorf("no script %s in the index of %s", in.SHA256, d.Path)
	}
	f, fi, err := openScript(d.Path, in.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("script %s is indexed but cannot be read: %v", in.SHA256, err)
	}
	defer f.Close()
	size := fi.Size()
	length := clamp(in.Length, scriptReadDefault, scriptReadMax)
	off := int64(in.Offset)
	if off > size || (off == size && size > 0) {
		return nil, nil, fmt.Errorf("offset %d is at or past the end of the script (%d bytes)", off, size)
	}
	// Read a few bytes more than asked, to see whether the page starts and
	// ends inside a character.
	buf := make([]byte, length+utf8.UTFMax)
	n, err := f.ReadAt(buf, off)
	if err != nil && err != io.EOF {
		return nil, nil, err
	}
	buf = buf[:n]
	skip := 0
	for skip < utf8.UTFMax-1 && skip < len(buf) && !utf8.RuneStart(buf[skip]) {
		skip++ // an offset in the middle of a character starts at the next one
	}
	buf = buf[skip:]
	off += int64(skip)
	if len(buf) > length {
		buf = buf[:length]
	}
	if off+int64(len(buf)) < size {
		buf = buf[:boundary(buf)]
	}
	end := off + int64(len(buf))
	out := readOut{SHA256: ref.SHA256, Size: size, Offset: off, Length: len(buf), URLs: make([]string, len(ref.URLs))}
	for i, u := range ref.URLs {
		out.URLs[i] = s.url(u)
	}
	if end < size {
		out.NextOffset = &end
	}
	out.Content = s.scriptText(strings.ToValidUTF8(string(buf), "\uFFFD"))
	out.SuspiciousInstructions = hasPromptInjection(out.Content)
	return s.reply(out)
}

// boundary is where a page that is not the last may end: not inside a
// character, and, when a delimiter is near, just after it, so that a token
// (a key or a JWT) is not cut in two where the mask could not see it whole.
func boundary(b []byte) int {
	n := len(b)
	for i := 1; i <= utf8.UTFMax-1 && i <= n; i++ {
		if utf8.RuneStart(b[n-i]) {
			if !utf8.FullRune(b[n-i:]) {
				n -= i
			}
			break
		}
	}
	lo := max(n-pageBackoff, 1)
	for j := n - 1; j >= lo; j-- {
		switch b[j] {
		case '"', '\'', '`', ';', ',', ')', '}', ']', '\n', ' ', '\t':
			return j + 1
		}
	}
	return n
}
