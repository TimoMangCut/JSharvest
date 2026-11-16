// Package scope decides which hosts belong to a target.
package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Func reports whether a host belongs to the target.
type Func func(host string) bool

// New returns the scope of target for a mode:
//   - "rdn": every host under the registrable domain of the target, so that
//     www.example.com, example.com and api.example.com are one target;
//   - "fqdn": the target host and its subdomains only.
//
// An IP address or a single-label host such as localhost is only itself.
func New(target, mode string) (Func, error) {
	target = strings.ToLower(target)
	if net.ParseIP(target) != nil || !strings.Contains(target, ".") {
		return func(h string) bool { return strings.EqualFold(h, target) }, nil
	}
	base := target
	switch mode {
	case "rdn":
		rdn, err := publicsuffix.EffectiveTLDPlusOne(target)
		if err != nil {
			return nil, fmt.Errorf("scope: %w", err)
		}
		base = rdn
	case "fqdn":
	default:
		return nil, fmt.Errorf("scope: unknown mode %q (want rdn or fqdn)", mode)
	}
	return func(h string) bool {
		h = strings.ToLower(h)
		return h == base || strings.HasSuffix(h, "."+base)
	}, nil
}

// PageScope decides which hosts' pages a crawl visits (-page-scope).
// Scripts, API calls and spec probes still use New(target, scopeMode).
//   - "auto" (or ""): on a subdomain (sub.example.com) when scopeMode is
//     "rdn", visit pages of that host and its subdomains ("fqdn") so the
//     crawl does not spill onto the parent site (example.com); on the
//     registrable domain itself or www.<rdn>, follow scopeMode;
//   - "fqdn" or "rdn": use that mode for pages.
func PageScope(target, scopeMode, pageMode string) (Func, error) {
	if _, err := New(target, scopeMode); err != nil {
		return nil, err
	}
	switch pageMode {
	case "", "auto":
		if scopeMode == "rdn" {
			h := strings.ToLower(target)
			if net.ParseIP(h) == nil && strings.Contains(h, ".") {
				rdn, err := publicsuffix.EffectiveTLDPlusOne(h)
				if err == nil && h != rdn && h != "www."+rdn {
					return New(target, "fqdn")
				}
			}
		}
		return New(target, scopeMode)
	case "fqdn", "rdn":
		return New(target, pageMode)
	default:
		return nil, fmt.Errorf("page-scope: unknown mode %q (want auto, fqdn or rdn)", pageMode)
	}
}

// IsLoopback reports a loopback host: localhost (and its subdomains), or
// a loopback address.
func IsLoopback(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// TargetDir is the name of a target's output (and profile) directory: its
// host, or host_port when it is on a port that is not its scheme's own, so
// two apps on one host (https://x.com and https://x.com:3016) never share
// one. A loopback host keeps its bare name whatever the port: the
// testbed's servers move from port to port.
func TargetDir(u *url.URL) string {
	h := strings.ToLower(u.Hostname())
	p := u.Port()
	if p == "" || (u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443") || IsLoopback(h) {
		return h
	}
	return h + "_" + p
}

// NormalizeTargetArg turns what -target is given (app.example.com_3016,
// app.example.com:3016, https://app.example.com:3016, app.example.com) into the output
// directory's name.
func NormalizeTargetArg(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return TargetDir(u)
		}
		return raw
	}
	if h, p, ok := splitDirPort(raw); ok {
		return TargetDir(&url.URL{Host: net.JoinHostPort(h, p)})
	}
	if h, p, err := net.SplitHostPort(raw); err == nil && p != "" {
		if p == "80" || p == "443" {
			return strings.ToLower(h) // no scheme: either default port is the host's own (POL-22B-1)
		}
		return TargetDir(&url.URL{Host: net.JoinHostPort(h, p)})
	}
	return strings.ToLower(raw)
}

// TargetHost is the host name of what -target is given, in any of the
// forms NormalizeTargetArg takes: what the scope is made from.
func TargetHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	if h, _, ok := splitDirPort(raw); ok {
		return strings.ToLower(h)
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(raw)
}

// splitDirPort reads a directory's name host_port.
func splitDirPort(s string) (host, port string, ok bool) {
	i := strings.LastIndexByte(s, '_')
	if i <= 0 || i == len(s)-1 || strings.ContainsAny(s, ":/") {
		return "", "", false
	}
	for _, c := range s[i+1:] {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}
	return s[:i], s[i+1:], true
}
