package endpoints

import (
	"cmp"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const maxAuthFlowBody = 256 << 10

// AuthFlow is an OAuth2 / OIDC / SSO authorization flow passively extracted
// from a pre-authentication response (a 3xx Location redirect or a 2xx JSON/text body).
type AuthFlow struct {
	Provider              string `json:"provider"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TenantID              string `json:"tenant_id,omitempty"`
	ClientID              string `json:"client_id,omitempty"`
	RedirectURI           string `json:"redirect_uri,omitempty"`
	ResponseType          string `json:"response_type,omitempty"`
	Scope                 string `json:"scope,omitempty"`
	SourceURL             string `json:"source_url,omitempty"`
}

// authURLCandRe matches http(s) URLs in raw or JSON-escaped text (\u0026, \/)
// in linear time without ambiguous backtracking.
var authURLCandRe = regexp.MustCompile(`(?i)https?:(?://|\\\/\\\/)(?:[^\\\s"'<>` + "`" + `]|\\/|\\u[0-9a-fA-F]{4})+`)

// ExtractAuthFlows passively extracts OAuth2/OIDC authorization flows and
// configuration note kinds from 2xx/3xx responses up to 256 KiB.
func ExtractAuthFlows(sourceURL string, status int, headers map[string]string, body []byte) ([]AuthFlow, []string) {
	if status < 200 || status >= 400 || len(body) > maxAuthFlowBody {
		return nil, nil
	}
	var cands []string
	for k, v := range headers {
		if strings.EqualFold(k, "location") {
			loc, _, _ := strings.Cut(v, "\n")
			loc = strings.TrimSpace(loc)
			if loc != "" {
				cands = append(cands, resolveAuthLocation(loc, sourceURL))
			}
		}
	}
	if len(body) > 0 {
		for _, m := range authURLCandRe.FindAllString(string(body), 64) {
			cands = append(cands, cleanAuthCandidate(m))
		}
	}
	if len(cands) == 0 {
		return nil, nil
	}

	var flows []AuthFlow
	var notes []string
	addNote := func(kind string) {
		if !slices.Contains(notes, kind) {
			notes = append(notes, kind)
		}
	}
	for _, raw := range cands {
		f, ok := parseAuthFlowURL(raw, sourceURL)
		if !ok {
			continue
		}
		flows = append(flows, f)
		if isImplicitResponseType(f.ResponseType) {
			addNote("oauth_implicit_flow")
		}
		if isNonLoopbackHTTPRedirect(f.RedirectURI) {
			addNote("oauth_http_redirect_uri")
		}
	}
	flows = dedupAuthFlows(flows)
	slices.Sort(notes)
	return flows, notes
}

func resolveAuthLocation(loc, sourceURL string) string {
	loc = cleanAuthCandidate(loc)
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") ||
		strings.HasPrefix(strings.ToLower(loc), "http://") || strings.HasPrefix(strings.ToLower(loc), "https://") {
		return loc
	}
	if sourceURL != "" {
		if base, err := url.Parse(sourceURL); err == nil && (base.Scheme == "http" || base.Scheme == "https") && base.Host != "" {
			if ref, err := base.Parse(loc); err == nil {
				return ref.String()
			}
		}
	}
	if strings.HasPrefix(loc, "//") {
		return "https:" + loc
	}
	return loc
}

func cleanAuthCandidate(s string) string {
	if strings.Contains(s, `\/`) {
		s = strings.ReplaceAll(s, `\/`, `/`)
	}
	if strings.Contains(s, `\u`) || strings.Contains(s, `\U`) {
		s = unescapeJSONHex(s)
	}
	if strings.Contains(s, "&amp;") {
		s = strings.ReplaceAll(s, "&amp;", "&")
	}
	for len(s) > 0 {
		last := s[len(s)-1]
		switch last {
		case '.', ',', ';':
			s = s[:len(s)-1]
		case ')':
			if strings.Count(s, ")") > strings.Count(s, "(") {
				s = s[:len(s)-1]
			} else {
				return s
			}
		case ']':
			if strings.Count(s, "]") > strings.Count(s, "[") {
				s = s[:len(s)-1]
			} else {
				return s
			}
		case '}':
			if strings.Count(s, "}") > strings.Count(s, "{") {
				s = s[:len(s)-1]
			} else {
				return s
			}
		default:
			return s
		}
	}
	return s
}

func unescapeJSONHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if v, err := strconv.ParseUint(s[i+2:i+6], 16, 16); err == nil && v >= 0x20 {
				b.WriteRune(rune(v))
				i += 5
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func parseAuthFlowURL(raw, sourceURL string) (AuthFlow, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery == "" {
		return AuthFlow{}, false
	}
	host := strings.ToLower(strings.TrimRight(u.Hostname(), "."))
	lp := strings.ToLower(strings.TrimRight(u.Path, "/"))
	if !isAuthAuthorizePath(host, lp) {
		return AuthFlow{}, false
	}
	q := u.Query()
	clientID := strings.TrimSpace(queryCI(q, "client_id"))
	redirectURI := strings.TrimSpace(queryCI(q, "redirect_uri"))
	responseType := strings.Join(strings.Fields(queryCI(q, "response_type")), " ")
	scope := strings.Join(strings.Fields(queryCI(q, "scope")), " ")
	if clientID == "" || (redirectURI == "" && responseType == "") {
		return AuthFlow{}, false
	}
	provider, tenantID := classifyAuthProvider(host, u.Path)
	authEp := strings.ToLower(u.Scheme) + "://" + canonAuthHost(u.Scheme, u.Host) + u.Path
	return AuthFlow{
		Provider:              provider,
		AuthorizationEndpoint: authEp,
		TenantID:              tenantID,
		ClientID:              clientID,
		RedirectURI:           redirectURI,
		ResponseType:          responseType,
		Scope:                 scope,
		SourceURL:             sourceURL,
	}, true
}

func isAuthAuthorizePath(host, lp string) bool {
	switch {
	case strings.Contains(lp, "/oauth2/") && (strings.HasSuffix(lp, "/authorize") || strings.Contains(lp, "/authorize/") || strings.HasSuffix(lp, "/auth")):
		return true
	case strings.HasSuffix(lp, "/protocol/openid-connect/auth"):
		return true
	case strings.HasSuffix(lp, "/connect/authorize"):
		return true
	case strings.HasSuffix(lp, "/authorize"):
		return true
	case strings.HasSuffix(host, ".amazoncognito.com") && lp == "/login":
		return true
	}
	return false
}

func classifyAuthProvider(host, rawPath string) (provider, tenantID string) {
	segs := nonEmptySegments(rawPath)
	for i := 0; i+3 < len(segs); i++ {
		if strings.EqualFold(segs[i], "realms") && strings.EqualFold(segs[i+2], "protocol") && strings.EqualFold(segs[i+3], "openid-connect") {
			return "keycloak", segs[i+1]
		}
	}
	switch {
	case host == "login.microsoftonline.com" || host == "login.microsoftonline.us" ||
		host == "login.partner.microsoftonline.cn" || host == "login.windows.net" ||
		strings.HasSuffix(host, ".ciamlogin.com"):
		if len(segs) > 0 && !strings.EqualFold(segs[0], "oauth2") {
			tenantID = segs[0]
		}
		return "entra_id", tenantID
	case strings.HasSuffix(host, ".b2clogin.com"):
		if len(segs) > 1 && strings.EqualFold(segs[0], "tfp") {
			tenantID = segs[1]
		} else if len(segs) > 0 && !strings.EqualFold(segs[0], "oauth2") {
			tenantID = segs[0]
		}
		return "entra_id", tenantID
	case host == "accounts.google.com" || (strings.HasSuffix(host, ".google.com") && strings.Contains(strings.ToLower(rawPath), "/o/oauth2/")):
		return "google", ""
	case strings.HasSuffix(host, ".okta.com") || strings.HasSuffix(host, ".oktapreview.com") ||
		strings.HasSuffix(host, ".okta-emea.com") || strings.HasSuffix(host, ".okta-gov.com"):
		return "okta", ""
	case strings.HasSuffix(host, ".auth0.com"):
		return "auth0", ""
	case strings.HasSuffix(host, ".amazoncognito.com"):
		return "cognito", ""
	default:
		return "oidc_generic", ""
	}
}

func nonEmptySegments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func canonAuthHost(scheme, hostport string) string {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(hostport)
	}
	if (strings.EqualFold(scheme, "https") && p == "443") || (strings.EqualFold(scheme, "http") && p == "80") {
		if strings.Contains(h, ":") {
			return "[" + strings.ToLower(h) + "]"
		}
		return strings.ToLower(h)
	}
	return net.JoinHostPort(strings.ToLower(h), p)
}

func queryCI(q url.Values, name string) string {
	if v := q.Get(name); v != "" {
		return v
	}
	for k, vs := range q {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

func isImplicitResponseType(rt string) bool {
	if rt == "" {
		return false
	}
	norm := strings.ReplaceAll(strings.ToLower(rt), ",", " ")
	toks := strings.Fields(norm)
	return slices.Contains(toks, "token") || (slices.Contains(toks, "id_token") && !slices.Contains(toks, "code"))
}

func isNonLoopbackHTTPRedirect(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	h := strings.ToLower(strings.TrimRight(u.Hostname(), "."))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil && ip.Unmap().IsLoopback() {
		return false
	}
	return true
}

func compareAuthFlow(a, b AuthFlow) int {
	return cmp.Or(
		strings.Compare(a.Provider, b.Provider),
		strings.Compare(a.AuthorizationEndpoint, b.AuthorizationEndpoint),
		strings.Compare(a.TenantID, b.TenantID),
		strings.Compare(a.ClientID, b.ClientID),
		strings.Compare(a.RedirectURI, b.RedirectURI),
		strings.Compare(a.ResponseType, b.ResponseType),
		strings.Compare(a.Scope, b.Scope),
		strings.Compare(a.SourceURL, b.SourceURL),
	)
}

func dedupAuthFlows(flows []AuthFlow) []AuthFlow {
	if len(flows) == 0 {
		return nil
	}
	slices.SortFunc(flows, compareAuthFlow)
	out := make([]AuthFlow, 0, len(flows))
	seen := map[[7]string]bool{}
	for _, f := range flows {
		k := [7]string{f.Provider, f.AuthorizationEndpoint, f.TenantID, f.ClientID, f.RedirectURI, f.ResponseType, f.Scope}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}
