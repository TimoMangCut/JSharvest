package jsapi

import (
	"encoding/json"
	"net/url"
	"strings"
)

// oidcEndpoints are the endpoints an OpenID Provider's configuration
// (/.well-known/openid-configuration, RFC 8414's metadata too) names, with
// the method each is called with.
var oidcEndpoints = []struct{ key, method string }{
	{"authorization_endpoint", "GET"},
	{"token_endpoint", "POST"},
	{"userinfo_endpoint", "GET"},
	{"jwks_uri", "GET"},
	{"end_session_endpoint", "GET"},
	{"revocation_endpoint", "POST"},
	{"introspection_endpoint", "POST"},
	{"registration_endpoint", "POST"},
	{"device_authorization_endpoint", "POST"},
	{"pushed_authorization_request_endpoint", "POST"},
	{"backchannel_authentication_endpoint", "POST"},
	{"check_session_iframe", "GET"},
}

// IsOIDC reports an OpenID Provider's configuration: a JSON object with an
// issuer and an authorization or token endpoint.
func IsOIDC(b []byte) bool {
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return false
	}
	iss, _ := doc["issuer"].(string)
	_, az := doc["authorization_endpoint"].(string)
	_, tk := doc["token_endpoint"].(string)
	return iss != "" && (az || tk)
}

// ExtractOIDC reads an OpenID Provider's configuration as Extract reads a
// script (PIP-03): each endpoint it names, absolute, with its method; the
// token endpoint's form fields as the spec gives them.
func ExtractOIDC(src []byte) (res Result) {
	res.Version = Version
	res.Endpoints = []Endpoint{}
	var doc map[string]any
	if err := json.Unmarshal(src, &doc); err != nil {
		res.Error = "oidc: " + firstLine(err.Error())
		return res
	}
	for _, e := range oidcEndpoints {
		raw, _ := doc[e.key].(string)
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			continue
		}
		ep := Endpoint{Method: e.method, URL: strings.TrimRight(raw, "?"), Kind: "openapi"}
		switch e.key {
		case "token_endpoint":
			ep.Body = []string{"client_id", "client_secret", "code", "code_verifier", "grant_type", "redirect_uri", "refresh_token"}
		case "authorization_endpoint":
			ep.Query = []string{"client_id", "code_challenge", "redirect_uri", "response_type", "scope", "state"}
		case "revocation_endpoint", "introspection_endpoint":
			ep.Body = []string{"token", "token_type_hint"}
		}
		res.Endpoints = append(res.Endpoints, ep)
	}
	return res
}
