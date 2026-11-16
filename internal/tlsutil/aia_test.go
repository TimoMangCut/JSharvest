package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type ca struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func newCert(t *testing.T, name string, parent *ca, isCA bool, aia string) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA,
	}
	if isCA {
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tpl.DNSNames = []string{"localhost"}
	}
	if aia != "" {
		tpl.IssuingCertificateURL = []string{aia}
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{cert: c, der: der, key: key}
}

// leafServer is a TLS server that sends its leaf alone.
func leafServer(t *testing.T, leaf *ca) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.der}, PrivateKey: leaf.key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func get(a *AIA, u string) error {
	d := &net.Dialer{}
	c := &http.Client{Transport: &http.Transport{DialTLSContext: a.DialTLS(d.DialContext, true), ForceAttemptHTTP2: true}, Timeout: 10 * time.Second}
	resp, err := c.Get(u)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestAIACompletesARealChain(t *testing.T) {
	root := newCert(t, "Root", nil, true, "")
	inter := newCert(t, "Intermediate", root, true, "")
	// The intermediate, served as a CA serves it: DER at one URL, PEM at another.
	var pemHits, derHits int
	aiaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/inter.crt":
			derHits++
			w.Write(inter.der)
		case "/inter.pem":
			pemHits++
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: inter.der})
		}
	}))
	defer aiaSrv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)

	for _, p := range []string{"/inter.crt", "/inter.pem"} {
		leaf := newCert(t, "leaf", inter, false, aiaSrv.URL+p)
		srv := leafServer(t, leaf)
		hostport := strings.TrimPrefix(srv.URL, "https://")
		host, _, _ := net.SplitHostPort(hostport)

		// Go alone refuses it.
		plain := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
		if _, err := plain.Get(srv.URL); err == nil {
			t.Fatalf("%s: Go verified a chain the server did not send", p)
		}
		// Check 1: the AIA leads to a loopback address: refused (no SSRF).
		a := New()
		a.Roots = roots
		if err := get(a, srv.URL); err == nil || !strings.Contains(err.Error(), "private address") {
			t.Errorf("%s: AIA to a private address: %v", p, err)
		}
		// Check 2: allowed, the chain is completed and verified to the root.
		a = New()
		a.Roots, a.AllowPrivate = roots, true
		if err := get(a, srv.URL); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		// The server, host:port: another port of the host is another
		// server (POL-22B-2).
		if !a.Incomplete(hostport) || a.Incomplete(host) || a.Incomplete(host+":8443") || len(a.Hosts()) != 1 {
			t.Errorf("%s: incomplete chain not noted: %v", p, a.Hosts())
		}
		// Kept: the next connection does not fetch it again.
		before := derHits + pemHits
		if err := get(a, srv.URL+"/again"); err != nil {
			t.Fatal(err)
		}
		_ = before
	}
	if derHits != 1 || pemHits != 1 {
		t.Errorf("fetched %d DER, %d PEM; want each once", derHits, pemHits)
	}
}

func TestAIARefusesForgeries(t *testing.T) {
	root := newCert(t, "Root", nil, true, "")
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	// An attacker's own CA, named by the leaf's AIA: no road to a root.
	evilRoot := newCert(t, "Evil Root", nil, true, "")
	evilInter := newCert(t, "Evil Intermediate", evilRoot, true, "")
	aiaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/evil-inter":
			w.Write(evilInter.der)
		case "/evil-root":
			w.Write(evilRoot.der)
		case "/big":
			w.Write(make([]byte, maxCert+10))
		}
	}))
	defer aiaSrv.Close()
	for name, leaf := range map[string]*ca{
		"forged chain":       newCert(t, "leaf", evilInter, false, aiaSrv.URL+"/evil-inter"),
		"self-signed":        newCert(t, "leaf", nil, false, ""),
		"self-signed w/ aia": newCert(t, "leaf", nil, false, aiaSrv.URL+"/evil-root"),
		"oversized":          newCert(t, "leaf", evilInter, false, aiaSrv.URL+"/big"),
	} {
		srv := leafServer(t, leaf)
		a := New()
		a.Roots, a.AllowPrivate = roots, true
		err := get(a, srv.URL)
		var cve *tls.CertificateVerificationError
		if err == nil || !errors.As(err, &cve) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
		if len(a.Hosts()) != 0 {
			t.Errorf("%s: noted as complete", name)
		}
	}
	// -insecure takes anything.
	srv := leafServer(t, newCert(t, "leaf", nil, false, ""))
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if resp, err := c.Get(srv.URL); err != nil {
		t.Errorf("insecure: %v", err)
	} else {
		resp.Body.Close()
	}
}

func TestPrivate(t *testing.T) {
	for ip, want := range map[string]bool{"127.0.0.1": true, "10.1.2.3": true, "169.254.169.254": true, "100.64.0.1": true,
		"::1": true, "fe80::1": true, "0.0.0.0": true, "8.8.8.8": false, "2606:4700::1111": false} {
		if Private(net.ParseIP(ip)) != want {
			t.Errorf("Private(%s) != %v", ip, want)
		}
	}
}

// The host asked is the one verified, an IP's too; HTTP/2 is kept.
func TestAIAHostAndHTTP2(t *testing.T) {
	root := newCert(t, "Root", nil, true, "")
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	leaf := newCert(t, "leaf", root, false, "")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.Proto)) }))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.der}, PrivateKey: leaf.key}}}
	srv.StartTLS()
	defer srv.Close()
	a := New()
	a.Roots = roots
	d := &net.Dialer{}
	c := &http.Client{Transport: &http.Transport{DialTLSContext: a.DialTLS(d.DialContext, true), ForceAttemptHTTP2: true}}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Errorf("proto %s", resp.Proto)
	}
	// The same chain for another name: refused.
	other := newCert(t, "leaf", root, false, "")
	other.cert.IPAddresses = nil
	tpl := *other.cert
	tpl.IPAddresses, tpl.DNSNames = nil, []string{"other.example"}
	der, _ := x509.CreateCertificate(rand.Reader, &tpl, root.cert, &other.key.PublicKey, root.key)
	srv2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv2.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: other.key}}}
	srv2.StartTLS()
	defer srv2.Close()
	if _, err := c.Get(srv2.URL); err == nil {
		t.Error("a certificate for another name was taken")
	}
}
