package flow

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// Discriminators are the query parameters by which one URL serves many
// operations (index.php?action=, JSON-RPC over GET): their value is part
// of the endpoint.
var Discriminators = []string{"action", "method", "op", "cmd", "operation", "func", "function", "task", "do"}

// Operation names what a request does at an endpoint that serves many: a
// GraphQL operation ("op=DeleteUser"), or the value of a discriminating
// query parameter ("action=purge", digits as "#"). It is "" for the rest.
//
// A batch (a JSON array of GraphQL operations) answers with its first
// operation; use Operations to see all of them.
func Operation(u *url.URL, contentType, body string) string {
	return Operations(u, contentType, body)[0]
}

// BatchPart is one operation of a GraphQL batch: its key ("op=Name", or ""
// for an anonymous operation), the place of its element in the batch, and
// the body of a request that has only that element, still an array.
type BatchPart struct {
	Op    string
	Index int
	Body  string
	URL   string
}

// batchElements reads a body that is a JSON array. It is nil for anything
// else.
func batchElements(body string) []json.RawMessage {
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "[") {
		return nil
	}
	var els []json.RawMessage
	if json.Unmarshal([]byte(body), &els) != nil || len(els) == 0 {
		return nil
	}
	return els
}

var (
	// gqlDocRe is the head of a GraphQL document: an operation (name,
	// variables and directives optional) or a fragment, up to its body.
	gqlDocRe   = regexp.MustCompile(`^(?:(?:query|mutation|subscription)(?:\s+[_A-Za-z]\w*)?\s*(?:\([^)]*\))?\s*(?:@[^{]*)?|fragment\s+[_A-Za-z]\w*\s+on\s+[_A-Za-z]\w*\s*(?:@[^{]*)?)\{`)
	gqlComment = regexp.MustCompile(`^(?:\s+|#[^\n]*)+`)
)

// elementOp reads one element of a batch: the GraphQL operation it names
// ("" when anonymous) and whether it is GraphQL at all. An element is when
// its query is a GraphQL document (a REST body with a "query" field is
// not), or when it has no query and an Apollo persisted query with an
// operationName.
func elementOp(el json.RawMessage) (op string, gql bool) {
	var m map[string]any
	if json.Unmarshal(el, &m) != nil {
		return "", false
	}
	on, _ := m["operationName"].(string)
	gq, _ := m["query"].(string)
	if strings.TrimSpace(gq) == "" {
		ext, _ := m["extensions"].(map[string]any)
		if _, ok := ext["persistedQuery"].(map[string]any); ok && on != "" {
			return on, true
		}
		return "", false
	}
	doc := gqlComment.ReplaceAllString(gq, "")
	switch {
	case strings.HasPrefix(doc, "{"):
		return on, true // a shorthand query: anonymous unless named
	case gqlDocRe.MatchString(doc):
		return gqlOperation(on, doc), true
	}
	return "", false
}

// SplitBatch splits a GraphQL batch of two or more elements into one part
// for each distinct operation: the first element of that name (the
// representative: later ones of the same name are not kept), kept as sent,
// in an array of one (some servers require the array). When the batch also
// has anonymous operations, its first is a part with Op "". It is nil for a
// request that is not a batch, has no GraphQL element, or whose GraphQL
// elements are all anonymous.
func SplitBatch(body string) []BatchPart {
	els := batchElements(body)
	if len(els) < 2 {
		return nil
	}
	var parts []BatchPart
	seen := map[string]bool{}
	named := false
	for i, el := range els {
		o, gql := elementOp(el)
		if !gql || seen[o] {
			continue
		}
		seen[o] = true
		key := ""
		if o != "" {
			key, named = "op="+o, true
		}
		parts = append(parts, BatchPart{Op: key, Index: i, Body: "[" + string(el) + "]"})
	}
	if !named {
		return nil
	}
	return parts
}

// Operations names what a request does as Operation does, with one name
// for each distinct operation of a GraphQL batch (one request, many
// endpoints; "" for its anonymous one). A request that is not a batch gives
// exactly Operation's answer, as the only element.
func Operations(u *url.URL, contentType, body string) []string {
	if parts := SplitBatch(body); parts != nil {
		out := make([]string, len(parts))
		for i, p := range parts {
			out[i] = p.Op
		}
		return out
	}
	if els := batchElements(body); len(els) == 1 {
		if o, gql := elementOp(els[0]); gql && o != "" {
			return []string{"op=" + o}
		}
	}
	return []string{single(u, contentType, body)}
}

func single(u *url.URL, contentType, body string) string {
	if id := NextActionID(nil, contentType, body); id != "" {
		return "next-action=" + id
	}
	op := ""
	q := u.Query()
	for _, d := range Discriminators {
		if v := q.Get(d); v != "" {
			op = d + "=" + digitsRe.ReplaceAllString(v, "#")
			break
		}
	}
	if gq := q.Get("query"); gq != "" {
		if o := gqlOperation(q.Get("operationName"), gq); o != "" {
			op = "op=" + o
		}
	}
	body = strings.TrimSpace(body)
	if strings.Contains(contentType, "json") || strings.HasPrefix(body, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(body), &m) == nil {
			if gq, _ := m["query"].(string); gq != "" {
				on, _ := m["operationName"].(string)
				if o := gqlOperation(on, gq); o != "" {
					op = "op=" + o
				}
			}
		}
	}
	return op
}

var (
	gqlOpRe  = regexp.MustCompile(`\b(query|mutation|subscription)\s+([_A-Za-z]\w*)`)
	digitsRe = regexp.MustCompile(`\d+`)
)

func gqlOperation(name, query string) string {
	if name != "" {
		return name
	}
	if m := gqlOpRe.FindStringSubmatch(query); m != nil {
		return m[2]
	}
	if strings.HasPrefix(strings.TrimSpace(query), "mutation") {
		return "mutation"
	}
	return ""
}
