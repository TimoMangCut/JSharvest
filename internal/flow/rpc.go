package flow

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	nextActionHexRe  = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)
	nextActionFormRe = regexp.MustCompile(`(?:^|[&\r\n;"'])\$ACTION_ID_([0-9a-fA-F]{32,64})\b`)
	nextActionEncRe  = regexp.MustCompile(`(?i)(?:^|&)%24ACTION_ID_([0-9a-fA-F]{32,64})(?:=|&|$)`)
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
