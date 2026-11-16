package replay

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/guard"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// replayActionRe names the verbs by which sending a request again spends
// or rotates a one-time thing: an e-mail verification link, a magic link,
// an API key's regeneration, a token's refresh. The guard does not hold
// them (a page that reads /verify-status must work in a crawl); a replay
// must not send them (docs/gd7-bola-design.md 1 and 8, point 10).
var replayActionRe = regexp.MustCompile(`(?i)verify|magic|regenerate|refresh`)

// replayWord is word for replayActionRe with the camelCase of acronyms: a
// verb that is a capitalised word after capitals (OTPVerify, JWTRefresh,
// APIRegenerate) is found too.
func replayWord(s string) bool {
	for _, m := range replayActionRe.FindAllStringIndex(s, -1) {
		before := m[0] == 0 || !isLetter(s[m[0]-1]) || (isUpper(s[m[0]]) && isLower(s[m[0]-1])) ||
			(isUpper(s[m[0]]) && isUpper(s[m[0]-1]) && m[0]+1 < len(s) && isLower(s[m[0]+1]))
		after := m[1] == len(s) || !isLetter(s[m[1]]) || (isUpper(s[m[1]]) && isLower(s[m[1]-1]))
		if before && after {
			return true
		}
	}
	return false
}

// namesReplayAction reports what the request names that a replay never
// sends as a read: the replay's verbs, and the guard's action verbs
// (approve, rotate, transfer, pay...) that Classify lets a GraphQL query
// through with.
func namesReplayAction(names []string) (string, bool) {
	for _, n := range names {
		if replayWord(n) || guard.NamesAction(n) {
			return n, true
		}
	}
	return "", false
}

// gqlWrites reports whether a GraphQL document of the request defines a
// mutation or a subscription at its top level, wherever it stands in the
// document (after a fragment too).
func gqlWrites(body string, u *url.URL) bool {
	var docs []string
	t := strings.TrimSpace(body)
	var objs []map[string]any
	switch {
	case strings.HasPrefix(t, "["):
		json.Unmarshal([]byte(t), &objs)
	case strings.HasPrefix(t, "{"):
		var o map[string]any
		if json.Unmarshal([]byte(t), &o) == nil {
			objs = append(objs, o)
		}
	}
	for _, o := range objs {
		if q, ok := o["query"].(string); ok {
			docs = append(docs, q)
		}
	}
	if q := u.Query().Get("query"); q != "" {
		docs = append(docs, q)
	}
	for _, d := range docs {
		doc := stripGQLComments(d)
		depth, paren := 0, 0
		for i := 0; i < len(doc); i++ {
			switch c := doc[i]; {
			case c == '"':
				for i++; i < len(doc) && doc[i] != '"'; i++ {
					if doc[i] == '\\' {
						i++
					}
				}
			case c == '(':
				paren++
			case c == ')':
				paren--
			case c == '{':
				depth++
			case c == '}':
				depth--
			case depth == 0 && paren == 0 && isNameByte(c) && (i == 0 || !isNameByte(doc[i-1])):
				w := gqlNameRe.FindString(doc[i:])
				if w == "mutation" || w == "subscription" {
					return true
				}
				i += len(w) - 1
			}
		}
	}
	return false
}

// ClassifyPeer is Classify for authz -peers: the same rules, with
//
//   - the replay's action verbs (replayActionRe) checked on the URL, the
//     query, the body's values and a GraphQL document's operations before a
//     GraphQL query or a POST that only reads is let through as a Read: a
//     request that names one is a Write;
//   - -read-allow not honoured: a POST is a Read only when it is a GraphQL
//     query.
func (p Policy) ClassifyPeer(e traffic.Entry, held bool) Decision {
	strict := Policy{AuthAllow: p.AuthAllow}
	d := strict.Classify(e, held)
	if d.Kind != Read {
		return d
	}
	u, err := url.Parse(e.URL)
	if err != nil {
		return Decision{Never, "bad URL"}
	}
	body := e.Body.Body
	if e.BodyBase64 {
		body = ""
	}
	ct := header(e.Headers, "content-type")
	names := []string{decode(u.EscapedPath()), decode(u.RawQuery)}
	names = append(names, graphQL(body, u).names...)
	names = append(names, bodyValues(body, ct)...)
	if gqlWrites(body, u) {
		return Decision{Write, "a GraphQL document that defines a mutation or subscription"}
	}
	if n, ok := namesReplayAction(names); ok {
		return Decision{Write, "names an action a replay does not send as a read: " + clip(n)}
	}
	return d
}
