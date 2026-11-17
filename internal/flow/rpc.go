package flow

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	nextActionHexRe  = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)
	nextActionFormRe = regexp.MustCompile(`(?:^|[&\r\n;"'])\$ACTION_ID_([0-9a-fA-F]{32,64})\b`)
	nextActionEncRe  = regexp.MustCompile(`(?i)(?:^|&)%24ACTION_ID_([0-9a-fA-F]{32,64})(?:=|&|$)`)
	trpcProcRe       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$`)
)

// NextActionID returns the lowercase hex discriminator of a Next.js App Router
// Server Action request (from the Next-Action header or $ACTION_ID_<hex> form
// field), or "" when the request is not a Server Action.
func NextActionID(headers map[string]string, contentType, body string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "next-action") {
			if id := strings.TrimSpace(v); nextActionHexRe.MatchString(id) {
				return strings.ToLower(id)
			}
			return ""
		}
	}
	if strings.Contains(body, "$ACTION_ID_") {
		if m := nextActionFormRe.FindStringSubmatch(body); m != nil {
			return strings.ToLower(m[1])
		}
	}
	if strings.Contains(body, "%24ACTION_ID_") || strings.Contains(body, "%24action_id_") {
		if m := nextActionEncRe.FindStringSubmatch(body); m != nil {
			return strings.ToLower(m[1])
		}
	}
	return ""
}

// OperationWithHeaders names what a request does at an endpoint that serves
// many, consulting protocol routing headers (such as Next-Action) before
// falling back to Operation(u, contentType, body).
func OperationWithHeaders(u *url.URL, headers map[string]string, contentType, body string) string {
	return OperationsWithHeaders(u, headers, contentType, body)[0]
}

// OperationsWithHeaders lists every operation of a request, consulting
// protocol routing headers before delegating to Operations.
func OperationsWithHeaders(u *url.URL, headers map[string]string, contentType, body string) []string {
	if id := NextActionID(headers, contentType, body); id != "" {
		return []string{"next-action=" + id}
	}
	return Operations(u, contentType, body)
}

// SplitBatchWithURL decomposes multi-operation batch requests into one
// standalone BatchPart per distinct operation or procedure. It handles tRPC
// URL batches (/trpc/procA,procB?batch=1) and falls back to SplitBatch for
// GraphQL JSON array batches.
func SplitBatchWithURL(u *url.URL, contentType, body string) []BatchPart {
	if parts := splitTRPCBatch(u, body); parts != nil {
		return parts
	}
	return SplitBatch(body)
}

func splitTRPCBatch(u *url.URL, body string) []BatchPart {
	if u == nil {
		return nil
	}
	rawPath := u.EscapedPath()
	if !strings.Contains(rawPath, ",") {
		return nil
	}
	segs := strings.Split(strings.Trim(rawPath, "/"), "/")
	procIdx := -1
	hasTRPCSeg := false
	for i, s := range segs {
		if strings.EqualFold(s, "trpc") {
			hasTRPCSeg = true
		}
		if strings.Contains(s, ",") {
			dec, err := url.PathUnescape(s)
			if err != nil {
				dec = s
			}
			procs := strings.Split(dec, ",")
			if len(procs) >= 2 && allTRPCProcs(procs) {
				procIdx = i
			}
		}
	}
	if procIdx < 0 {
		return nil
	}
	q := u.Query()
	if !hasTRPCSeg && q.Get("batch") != "1" {
		return nil
	}
	decSeg, err := url.PathUnescape(segs[procIdx])
	if err != nil {
		decSeg = segs[procIdx]
	}
	procs := strings.Split(decSeg, ",")

	rawInput := q.Get("input")
	hasQueryInput := rawInput != ""
	queryElem := trpcInputSplitter(rawInput)
	bodyElem := trpcInputSplitter(body)

	seen := map[string]bool{}
	var parts []BatchPart
	for i, proc := range procs {
		if seen[proc] {
			continue
		}
		seen[proc] = true
		newSegs := make([]string, len(segs))
		copy(newSegs, segs)
		newSegs[procIdx] = proc

		uCopy := *u
		uCopy.Path = "/" + strings.Join(newSegs, "/")
		uCopy.RawPath = ""
		if hasQueryInput && queryElem != nil {
			qCopy := u.Query()
			qCopy.Set("input", queryElem(i))
			uCopy.RawQuery = qCopy.Encode()
		}
		partBody := body
		if strings.TrimSpace(body) != "" && bodyElem != nil {
			partBody = bodyElem(i)
		}
		parts = append(parts, BatchPart{
			Index: i,
			Body:  partBody,
			URL:   uCopy.String(),
		})
	}
	if len(parts) < 2 {
		return nil
	}
	return parts
}

func allTRPCProcs(procs []string) bool {
	for _, p := range procs {
		if !trpcProcRe.MatchString(p) {
			return false
		}
	}
	return true
}

func trpcInputSplitter(raw string) func(int) string {
	t := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(t, "{"):
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(t), &m) != nil {
			return nil
		}
		return func(i int) string {
			el, ok := m[strconv.Itoa(i)]
			if !ok {
				return `{}`
			}
			return `{"0":` + string(el) + `}`
		}
	case strings.HasPrefix(t, "["):
		var arr []json.RawMessage
		if json.Unmarshal([]byte(t), &arr) != nil {
			return nil
		}
		return func(i int) string {
			if i < 0 || i >= len(arr) {
				return `[]`
			}
			return `[` + string(arr[i]) + `]`
		}
	}
	return nil
}

// isProtectedRPCSegment reports whether varying segment pos represents RPC
// procedure names under a /trpc/ router rather than an entity parameter.
func isProtectedRPCSegment(shapes [][]string, idx []int, pos int) bool {
	first := shapes[idx[0]]
	hasTRPC := false
	for k := 0; k < pos; k++ {
		if strings.EqualFold(first[k], "trpc") {
			hasTRPC = true
			break
		}
	}
	if !hasTRPC {
		return false
	}
	for _, i := range idx {
		s := shapes[i][pos]
		if strings.HasPrefix(s, "{") || !trpcProcRe.MatchString(s) {
			return false
		}
	}
	return true
}
