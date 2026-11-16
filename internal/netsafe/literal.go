package netsafe

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ErrLiteral: the request's host is a literal address or a name that is
// the machine itself, which a public target's run does not ask. Behind a
// proxy this is the only check there is: the dialler sees the proxy.
var ErrLiteral = errors.New("private or loopback host refused")

// LiteralHost reads a host as a URL parser does (WHATWG): an IPv6 in
// brackets (or bare), or an IPv4 in any of its number forms (2130706433,
// 0x7f.1, 0177.0.0.1, 127.1). isLiteral is false for a name; when the host
// is a literal that does not read (256.0.0.1, 1.2.3.4.5, 09.1) isLiteral is
// true and err says why: it cannot be normalised, so it is not trusted.
func LiteralHost(host string) (addr netip.Addr, isLiteral bool, err error) {
	if strings.HasPrefix(host, "[") || strings.Contains(host, ":") {
		h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if strings.Contains(h, "%") {
			// A zone names an interface of this machine: never a target.
			return netip.Addr{}, true, fmt.Errorf("host %q: an address with a zone", host)
		}
		a, perr := netip.ParseAddr(h)
		if perr != nil || !a.Is6() {
			return netip.Addr{}, true, fmt.Errorf("host %q: not an IPv6 address", host)
		}
		return a, true, nil
	}
	if !endsInNumber(host) {
		return netip.Addr{}, false, nil
	}
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return netip.Addr{}, true, fmt.Errorf("host %q: more than four parts", host)
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := ipv4Number(p)
		if !ok {
			return netip.Addr{}, true, fmt.Errorf("host %q: %q is not an IPv4 number", host, p)
		}
		nums[i] = n
	}
	for _, n := range nums[:len(nums)-1] {
		if n > 255 {
			return netip.Addr{}, true, fmt.Errorf("host %q: a part over 255", host)
		}
	}
	last := nums[len(nums)-1]
	limit := uint64(1) << (8 * uint(5-len(nums)))
	if last >= limit {
		return netip.Addr{}, true, fmt.Errorf("host %q: the last part is out of range", host)
	}
	v := last
	for i, n := range nums[:len(nums)-1] {
		v += n << (8 * uint(3-i))
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true, nil
}

// endsInNumber is the WHATWG test that a host is read as IPv4: its last
// label is all digits, or a 0x number.
func endsInNumber(host string) bool {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last == "" {
		return false
	}
	if strings.Trim(last, "0123456789") == "" {
		return true
	}
	if len(last) >= 2 && (last[:2] == "0x" || last[:2] == "0X") && strings.Trim(last[2:], "0123456789abcdefABCDEF") == "" {
		return true
	}
	return false
}

func ipv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		s, base = s[2:], 16
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// RefuseHost is the request-layer check for a public target: the host
// (as the URL names it, brackets or not) is refused when it is localhost
// or *.localhost (RFC 6761), a private/loopback/link-local/CGNAT/
// unspecified literal in any number form or IPv4-mapped IPv6, or a literal
// that cannot be normalised. It looks nothing up. A target that is itself
// internal (targetPublic false) refuses nothing.
func RefuseHost(host string, targetPublic bool) error {
	if strings.Contains(host, "%") {
		return fmt.Errorf("%w: %s has a zone", ErrLiteral, host)
	}
	if !targetPublic {
		return nil
	}
	if strings.HasSuffix(host, "..") {
		return fmt.Errorf("%w: %s ends in more than one dot", ErrLiteral, host)
	}
	h := strings.ToLower(strings.TrimRight(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%w: %s", ErrLiteral, host)
	}
	a, lit, err := LiteralHost(host)
	if lit && err != nil {
		return fmt.Errorf("%w: %v", ErrLiteral, err)
	}
	if lit && PrivateAddr(a) {
		return fmt.Errorf("%w: %s is %s", ErrLiteral, host, a.Unmap())
	}
	return nil
}

// Guard is a RoundTripper that applies RefuseHost to every request before
// the transport sees it (a redirect's too: the client sends it through
// here). Hosts the user's rules map are trusted.
type Guard struct {
	Next         http.RoundTripper
	AllowPrivate bool
	// AllowHost names the host:port (lower case, the scheme's default port
	// when the URL has none) that are let through whatever they are: the
	// archive services the user or a test declared. Used by RoundTrip.
	AllowHost func(hostport string) bool
	Rules     Rules
}

func (g Guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if g.AllowHost != nil && g.AllowHost(CanonHostPort(req.URL.Scheme, req.URL.Host)) && !strings.Contains(req.URL.Host, "%") {
		return g.Next.RoundTrip(req)
	}
	if err := g.Check(req.URL.Hostname()); err != nil {
		return nil, err
	}
	return g.Next.RoundTrip(req)
}

// Check is RefuseHost for this guard's target and rules.
func (g Guard) Check(host string) error {
	if strings.Contains(host, "%") {
		return fmt.Errorf("%w: %s has a zone", ErrLiteral, host)
	}
	if g.AllowPrivate {
		return nil
	}
	if probe := net.JoinHostPort(host, "0"); len(g.Rules) > 0 && g.Rules.MapAddr(probe) != probe {
		return nil
	}
	return RefuseHost(host, true)
}

// CanonHostPort is host:port as a lower-case key: the port the URL names, or
// its scheme's default (80, 443).
func CanonHostPort(scheme, hostport string) string {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		h, p = strings.Trim(hostport, "[]"), ""
	}
	if p == "" {
		p = "80"
		if strings.EqualFold(scheme, "https") {
			p = "443"
		}
	}
	return net.JoinHostPort(strings.ToLower(h), p)
}

// SplitURL reads the scheme and host of a URL, also when Go's url.Parse
// refuses it and Chrome sends it all the same (`http://%zz@127.0.0.1/x`, a
// path of `/%zz`): the authority is cut by hand, scheme "://" [userinfo "@"]
// host [":" port], up to the first of / \ ? #. ok is false when the text
// has no "scheme://" at all (data:, about:, a relative URL). host may be ""
// (an authority without one): the caller closes on it.
func SplitURL(raw string) (scheme, host string, ok bool) {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), true
	}
	i := strings.Index(raw, "://")
	if i <= 0 {
		return "", "", false
	}
	scheme = strings.ToLower(raw[:i])
	auth := raw[i+3:]
	if j := strings.IndexAny(auth, "/\\?#"); j >= 0 {
		auth = auth[:j]
	}
	if j := strings.LastIndex(auth, "@"); j >= 0 {
		auth = auth[j+1:]
	}
	if strings.HasPrefix(auth, "[") {
		if j := strings.Index(auth, "]"); j >= 0 {
			auth = auth[1:j]
		} else {
			auth = ""
		}
	} else if j := strings.Index(auth, ":"); j >= 0 {
		auth = auth[:j]
	}
	if d, err := url.PathUnescape(auth); err == nil {
		auth = d
	}
	return scheme, strings.ToLower(auth), true
}
