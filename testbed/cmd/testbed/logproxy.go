package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// logproxy is the proxy of testbed/proxy-check.sh: a forward proxy that
// logs every request (an absolute-URI HTTP one, or a CONNECT tunnel) as one
// line, "METHOD host path" (a tunnel: "CONNECT host:port"). It is the only
// thing in the gate's network namespace that resolves names: a host ending
// in .jsh.test goes to 127.0.0.1 at the port the request names, any other
// host is refused (and logged REFUSED). A client that reaches a .jsh.test
// name without the proxy fails its DNS lookup, so the gate catches a
// connection that went around it.
func logproxy(args []string) error {
	fset := flag.NewFlagSet("logproxy", flag.ExitOnError)
	listen := fset.String("listen", "127.0.0.1:8899", "listen address")
	logPath := fset.String("log", "", "the log file (one line a request)")
	fset.Parse(args)
	if *logPath == "" {
		return fmt.Errorf("-log is required")
	}
	lf, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	var mu sync.Mutex
	note := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(lf, format+"\n", a...)
	}
	// where maps host:port to the address the proxy dials ("" refuses).
	where := func(hostport string) string {
		h, p, err := net.SplitHostPort(hostport)
		if err != nil {
			return ""
		}
		if h == "127.0.0.1" || strings.HasSuffix(strings.ToLower(h), ".jsh.test") {
			return net.JoinHostPort("127.0.0.1", p)
		}
		return ""
	}
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		w := where(addr)
		if w == "" {
			return nil, fmt.Errorf("refused %s", addr)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, w)
	}}
	srv := &http.Server{Addr: *listen, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			dst := where(r.Host)
			if dst == "" {
				note("REFUSED CONNECT %s", r.Host)
				http.Error(w, "refused", http.StatusBadGateway)
				return
			}
			note("CONNECT %s", r.Host)
			up, err := net.DialTimeout("tcp", dst, 5*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				up.Close()
				return
			}
			c, _, err := hj.Hijack()
			if err != nil {
				up.Close()
				return
			}
			c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go func() { io.Copy(up, c); up.Close() }()
			io.Copy(c, up)
			c.Close()
			return
		}
		if !r.URL.IsAbs() {
			note("DIRECT %s %s", r.Method, r.URL.Path) // a client that spoke to the proxy as a server
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		if where(r.URL.Host) == "" && where(r.URL.Host+":80") == "" {
			note("REFUSED %s %s%s", r.Method, r.URL.Host, r.URL.RequestURI())
			http.Error(w, "refused", http.StatusBadGateway)
			return
		}
		note("%s %s%s", r.Method, r.URL.Host, r.URL.RequestURI())
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.Header.Del("Proxy-Connection")
		resp, err := tr.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})}
	return srv.ListenAndServe()
}
