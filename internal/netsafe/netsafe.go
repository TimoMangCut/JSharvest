// Package netsafe is the one dialer the tool's own HTTP clients share (the
// crawl's, the replay sender's, the AIA fetch's): resolve a name once,
// check every address it gives, dial the address checked. The name is
// never resolved a second time between the check and the connection (no
// TOCTOU, no DNS rebinding), a failed lookup is a refusal, and there is
// no dial by name.
package netsafe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// ErrPrivate: the name leads to an address no request of this tool goes
// to (private, loopback, link-local, CGNAT, unspecified, multicast).
var ErrPrivate = errors.New("private address refused")

// special are the ranges besides the address classes of net/netip that a
// request of this tool does not go to: they reach a local or internal
// address by another name or are no destination at all. TEST-NET
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) is left public on
// purpose: the lan gate's origin is in it.
var special = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"100.64.0.0/10",   // CGNAT
		"0.0.0.0/8",       // this network
		"192.0.0.0/24",    // IETF protocol assignments
		"198.18.0.0/15",   // benchmarking
		"240.0.0.0/4",     // reserved, and the broadcast 255.255.255.255
		"64:ff9b::/96",    // NAT64: embeds any IPv4
		"64:ff9b:1::/48",  // local-use NAT64
		"2002::/16",       // 6to4: the whole range is refused, embedded address or not
		"2001::/32",       // Teredo
		"::/96",           // IPv4-compatible
		"::ffff:0:0:0/96", // SIIT
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// Private reports an address a request does not go to: private, loopback,
// link-local (169.254.169.254), unspecified, multicast, CGNAT, "this
// network". An IPv4-mapped IPv6 address is judged as the IPv4 one. The
// single source of truth: tlsutil.Private calls it.
func Private(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true // not an address: not one to dial
	}
	return PrivateAddr(a)
}

// PrivateAddr is Private for a netip.Addr.
func PrivateAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	a = a.WithZone("")
	for _, p := range special {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Resolver looks a name up.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// SystemResolver is the system's.
func SystemResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Dialer dials what it has checked. The zero value is a closed dialer on
// the system's resolver.
type Dialer struct {
	// Resolver looks names up (nil: the system's).
	Resolver Resolver
	// HostRules are the user's -host-resolver-rules: a host they map is
	// trusted (the user wrote where it goes), even to a private address.
	HostRules Rules
	// AllowPrivate: the target itself is internal (testbed, authorized
	// internal test): private addresses are allowed.
	AllowPrivate bool
	// AllowPrivateHost allows private addresses for one host (optional).
	AllowPrivateHost func(host string) bool
	// AllowPrivateAddr is the same by host:port, the port the request names.
	AllowPrivateAddr func(hostport string) bool
	// Proxy: the address of the proxy itself is the user's, dialled
	// unchecked; what goes through it is the proxy's to resolve.
	Proxy *url.URL
	// Timeout of one connection (default 15 s); KeepAlive of 30 s is set.
	Timeout time.Duration
	// Dial makes the connection to a checked IP:port (nil: net.Dialer).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Connected is told which address a host's connection went to.
	Connected func(host string, ip netip.Addr)
}

func (d *Dialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.Dial != nil {
		return d.Dial(ctx, network, addr)
	}
	t := d.Timeout
	if t == 0 {
		t = 15 * time.Second
	}
	nd := net.Dialer{Timeout: t, KeepAlive: 30 * time.Second}
	return nd.DialContext(ctx, network, addr)
}

func (d *Dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if d.Resolver != nil {
		return d.Resolver(ctx, host)
	}
	return SystemResolver(ctx, host)
}

// isProxy: addr is the proxy's own (host:port, the scheme's default port
// when the URL names none).
func (d *Dialer) isProxy(addr string) bool {
	if d.Proxy == nil {
		return false
	}
	port := d.Proxy.Port()
	if port == "" {
		switch d.Proxy.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	h, p, err := net.SplitHostPort(addr)
	return err == nil && p == port && asciiHost(h) == asciiHost(d.Proxy.Hostname())
}

// asciiHost: a host as the transport sends it (punycode, lower case), so a
// proxy named with Unicode matches the address the transport hands over.
// golang.org/x/net/idna would need x/text, a new dependency: the labels are
// lower-cased and punycode-encoded here (no Unicode normalisation: a host
// written in a decomposed form is not matched).
func asciiHost(h string) string {
	l := strings.ToLower(strings.TrimRight(h, "."))
	labels := strings.Split(l, ".")
	for i, lab := range labels {
		if a, ok := punycodeLabel(lab); ok {
			labels[i] = a
		}
	}
	return strings.Join(labels, ".")
}

// DialContext is a transport's DialContext.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// The proxy itself: the user's choice (127.0.0.1:8080 is the usual).
	if d.isProxy(addr) {
		return d.dialTrusted(ctx, network, host, port)
	}
	// A host the user's rules map: trusted, to where the rule says.
	if m := d.HostRules.MapAddr(addr); m != addr {
		mh, mp, err := net.SplitHostPort(m)
		if err != nil {
			return nil, err
		}
		return d.dialTrusted(ctx, network, mh, mp)
	}
	allow := d.AllowPrivate || (d.AllowPrivateHost != nil && d.AllowPrivateHost(host)) ||
		(d.AllowPrivateAddr != nil && d.AllowPrivateAddr(net.JoinHostPort(strings.ToLower(host), port)))
	var ips []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{a}
	} else {
		if ips, err = d.resolve(ctx, host); err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no address", host)
	}
	for _, a := range ips {
		if !allow && PrivateAddr(a) {
			return nil, fmt.Errorf("%w: %s is %s", ErrPrivate, host, a.Unmap())
		}
	}
	return d.dialAll(ctx, network, host, port, ips)
}

// dialTrusted dials a host the user named (a proxy, a host rule): its
// addresses are not checked, but it is resolved once all the same.
func (d *Dialer) dialTrusted(ctx context.Context, network, host, port string) (net.Conn, error) {
	var ips []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{a}
	} else {
		var err error
		if ips, err = d.resolve(ctx, host); err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no address", host)
	}
	return d.dialAll(ctx, network, host, port, ips)
}

// dialAll tries the addresses, IPv4 first (a machine without an IPv6
// route gets "network is unreachable" from the first AAAA).
func (d *Dialer) dialAll(ctx context.Context, network, host, port string, ips []netip.Addr) (net.Conn, error) {
	for _, a := range ips {
		if a.Zone() != "" {
			return nil, fmt.Errorf("%w: %s has a zone (%s): an interface of this machine", ErrLiteral, host, a.Zone())
		}
	}
	c := append([]netip.Addr(nil), ips...)
	sort.SliceStable(c, func(i, j int) bool { return c[i].Unmap().Is4() && !c[j].Unmap().Is4() })
	var last error
	for _, a := range c {
		a = a.Unmap()
		conn, err := d.dial(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			if d.Connected != nil {
				d.Connected(host, a)
			}
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// --- -host-resolver-rules ---

type hostRule struct{ pattern, to string }

// Rules are the rules of Chrome's -host-resolver-rules the HTTP clients
// understand: MAP <pattern> <host[:port]>.
type Rules []hostRule

// ParseHostRules reads "MAP *.example.test 127.0.0.1, MAP example.test 127.0.0.1".
func ParseHostRules(s string) (Rules, error) {
	var out Rules
	for _, r := range strings.Split(s, ",") {
		f := strings.Fields(r)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 || !strings.EqualFold(f[0], "MAP") {
			return nil, fmt.Errorf("host resolver rule %q: only MAP <pattern> <host> is understood", strings.TrimSpace(r))
		}
		out = append(out, hostRule{pattern: strings.ToLower(f[1]), to: f[2]})
	}
	return out, nil
}

// MapAddr maps host:port by the first rule that matches (addr as it came
// when none does).
func (rs Rules) MapAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	for _, r := range rs {
		if ok, _ := path.Match(r.pattern, strings.ToLower(host)); ok {
			to := r.to
			if h, p, err := net.SplitHostPort(to); err == nil {
				return net.JoinHostPort(h, p)
			}
			return net.JoinHostPort(to, port)
		}
	}
	return addr
}

// InternalTargetVia says whether the target host is internal (a literal or
// resolved private address, or a host the user's rules map to one) for a run
// that may go through a proxy: behind one no name is looked up on this
// machine (its answer could differ from the proxy's, and the lookup would
// leave outside it), so only a literal address or a host rule can make the
// target internal; a name is public. Not knowing (a lookup that fails, no
// address) is public: closed.
func InternalTargetVia(ctx context.Context, target string, rules Rules, res Resolver, viaProxy bool) bool {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	probe := net.JoinHostPort(host, "0")
	if m := rules.MapAddr(probe); m != probe {
		host, _, _ = net.SplitHostPort(m)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return PrivateAddr(a)
	}
	if loopbackHost(host) {
		return true // localhost, *.localhost (RFC 6761): no lookup needed
	}
	if viaProxy {
		return false
	}
	if res == nil {
		res = SystemResolver
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := res(cctx, host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, a := range ips {
		if !PrivateAddr(a) {
			return false
		}
	}
	return true
}

// Matches reports whether a host is one the user's rules map (to anywhere).
func (rs Rules) Matches(host string) bool {
	if len(rs) == 0 {
		return false
	}
	host = strings.Trim(host, "[]")
	probe := host + ":0"
	if strings.Contains(host, ":") {
		probe = "[" + host + "]:0"
	}
	return rs.MapAddr(probe) != probe
}

// InternalMapped reports a host the user's -host-resolver-rules map to a
// private literal or localhost: the user wrote where it goes, so it is an
// internal host that is allowed, whatever DNS would say (the names of the
// testbed, *.jsh.test, have no DNS at all).
func InternalMapped(host string, rules Rules) bool {
	if !rules.Matches(host) {
		return false
	}
	host = strings.Trim(host, "[]")
	probe := host + ":0"
	if strings.Contains(host, ":") {
		probe = "[" + host + "]:0"
	}
	m := rules.MapAddr(probe)
	i := strings.LastIndex(m, ":")
	if i < 0 {
		return false
	}
	return RefuseHost(strings.Trim(m[:i], "[]"), true) != nil
}

// OriginPublic reports whether the page or worker at origin (a URL) is
// public: public unless it is an http(s) page on a private literal,
// localhost, or a host the rules map to one. A name is public (nothing is
// looked up); an origin that is unknown or not a web one (empty,
// about:blank, data:) is public too: closed.
func OriginPublic(origin string, rules Rules) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return true
	}
	h := u.Hostname()
	if InternalMapped(h, rules) {
		return false
	}
	return RefuseHost(h, true) == nil
}
