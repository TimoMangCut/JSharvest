// Package tlsutil verifies a server's certificate as a browser does when
// the server sends its leaf alone: the intermediates the leaf names in its
// Authority Information Access (caIssuers) are fetched and the chain is
// verified again to the system's roots. A self-signed or a forged
// certificate fails as ever; only a real chain the server forgot to send in
// full passes, and the host is noted (an incomplete chain is a finding).
package tlsutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

const (
	maxHops  = 2        // intermediates fetched one after another, at most
	maxCert  = 64 << 10 // bytes of one fetched certificate
	fetchFor = 5 * time.Second
	// handshakeFor bounds a handshake, the AIA's fetches in it.
	handshakeFor = 15*time.Second + maxHops*fetchFor
)

// AIA completes chains. One serves a whole run: what it fetched is kept.
type AIA struct {
	// UA is the User-Agent presented on AIA fetches; when empty,
	// marker.FallbackUA is sent instead of Go's default client string.
	UA string
	// AllowPrivate lets the fetch reach private addresses (tests only).
	AllowPrivate bool
	// Roots replaces the system's roots (tests only).
	Roots *x509.CertPool

	mu       sync.Mutex
	certs    map[string]*x509.Certificate // by AIA URL
	failed   map[string]error
	complete map[string]bool // hosts whose chain needed the AIA
	client   *http.Client
}

// New makes one.
func New() *AIA {
	return &AIA{certs: map[string]*x509.Certificate{}, failed: map[string]error{}, complete: map[string]bool{}}
}

// DialTLS is a transport's DialTLSContext: dial (the transport's own
// dialler: its host rules, its address checks), then the handshake with
// Go's verification of the certificate for the host asked, and the AIA's
// when the issuer is unknown. The host is the one the request names, so
// an IP target is verified as an IP. h2 offers HTTP/2 (ALPN): only for a
// transport that speaks it (ForceAttemptHTTP2).
func (a *AIA) DialTLS(dial func(ctx context.Context, network, addr string) (net.Conn, error), h2 bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	protos := []string{"http/1.1"}
	if h2 {
		protos = []string{"h2", "http/1.1"}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		raw, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{ServerName: host, NextProtos: protos,
			// The verification is ours (VerifyConnection), Go's skipped: it
			// would stop at the unknown issuer before ours runs.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				cs.ServerName = host
				return a.verify(cs, net.JoinHostPort(strings.ToLower(host), port))
			}}
		tc := tls.Client(raw, cfg)
		hctx, cancel := context.WithTimeout(ctx, handshakeFor)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tc, nil
	}
}

// verify checks a connection's certificates for its server name (which must
// be set), the server noted under key (host:port): two servers of one host
// on two ports are two servers (POL-22B-2).
func (a *AIA) verify(cs tls.ConnectionState, key string) error {
	certs := cs.PeerCertificates
	if len(certs) == 0 {
		return errors.New("tls: the server sent no certificate")
	}
	if cs.ServerName == "" {
		return errors.New("tls: no server name to verify the certificate for")
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{DNSName: cs.ServerName, Intermediates: inter, Roots: a.Roots}
	_, err := certs[0].Verify(opts)
	if err == nil {
		return nil
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
	}
	// The last certificate sent names its issuer: up to maxHops of them.
	cur := certs[len(certs)-1]
	for range maxHops {
		if len(cur.IssuingCertificateURL) == 0 {
			break
		}
		next, ferr := a.issuer(cur)
		if ferr != nil {
			return &tls.CertificateVerificationError{UnverifiedCertificates: certs,
				Err: fmt.Errorf("%w (its issuer from the AIA: %v)", err, ferr)}
		}
		inter.AddCert(next)
		if _, verr := certs[0].Verify(opts); verr == nil {
			a.mu.Lock()
			a.complete[key] = true
			a.mu.Unlock()
			return nil
		}
		cur = next
	}
	return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
}

// Incomplete reports a server (host:port, or a host: port 443) that
// sent an incomplete chain the AIA completed.
func (a *AIA) Incomplete(hostport string) bool {
	hostport = strings.ToLower(hostport)
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(strings.Trim(hostport, "[]"), "443")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.complete[hostport]
}

// Hosts are those servers, host:port.
func (a *AIA) Hosts() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for h := range a.complete {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// issuer fetches the first certificate one of c's AIA URLs serves.
func (a *AIA) issuer(c *x509.Certificate) (*x509.Certificate, error) {
	var last error
	for _, u := range c.IssuingCertificateURL {
		a.mu.Lock()
		got, err := a.certs[u], a.failed[u]
		a.mu.Unlock()
		if got == nil && err == nil {
			got, err = a.fetch(u)
			a.mu.Lock()
			if err != nil {
				a.failed[u] = err
			} else {
				a.certs[u] = got
			}
			a.mu.Unlock()
		}
		if err == nil {
			return got, nil
		}
		last = err
	}
	return nil, last
}

func (a *AIA) fetch(raw string) (*x509.Certificate, error) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return nil, fmt.Errorf("aia: %q is not http(s)", raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchFor)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	ua := a.UA
	if ua == "" {
		ua = marker.FallbackUA
	}
	req.Header.Set("User-Agent", ua)
	resp, err := a.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aia: %s answered %d", raw, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxCert+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxCert {
		return nil, fmt.Errorf("aia: %s is over %d bytes", raw, maxCert)
	}
	return ParseCert(b)
}

// ParseCert reads a certificate, DER or PEM.
func ParseCert(b []byte) (*x509.Certificate, error) {
	if p, _ := pem.Decode(b); p != nil {
		if p.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("aia: a PEM %q, not a certificate", p.Type)
		}
		b = p.Bytes
	}
	return x509.ParseCertificate(b)
}

// httpClient fetches the AIA URLs: each address checked before it is
// dialled (the one dialled is the one checked), no proxy, no cookie, a
// few redirects that are checked the same way.
func (a *AIA) httpClient() *http.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil {
		return a.client
	}
	// The one dialer: resolved once, every address checked, the address
	// checked is the one dialled (internal/netsafe).
	d := &netsafe.Dialer{Timeout: fetchFor, AllowPrivate: a.AllowPrivate}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   fetchFor,
		ResponseHeaderTimeout: fetchFor,
		MaxIdleConnsPerHost:   1,
	}
	a.client = &http.Client{Transport: tr, Timeout: fetchFor, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	return a.client
}

// Private reports an address no AIA fetch goes to: private, loopback,
// link-local (169.254.169.254), unspecified, multicast, CGNAT. It is
// netsafe.Private, the one source of truth.
func Private(ip net.IP) bool { return netsafe.Private(ip) }
