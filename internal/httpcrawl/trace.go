package httpcrawl

import (
	"context"
	"net"
	"net/http/httptrace"
	"sync"
)

// remoteTrace keeps the address a request was sent to, for the request
// log (the archive's live check pins the hosts the crawls reached).
type remoteTrace struct {
	mu sync.Mutex
	ip string
}

func (t *remoteTrace) addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ip
}

func withTrace(ctx context.Context, t *remoteTrace) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			if host, _, err := net.SplitHostPort(info.Conn.RemoteAddr().String()); err == nil {
				t.mu.Lock()
				t.ip = host
				t.mu.Unlock()
			}
		},
	})
}
