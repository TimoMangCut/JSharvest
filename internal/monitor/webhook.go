package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/roles"
)

// Payload is what the webhook gets: by default counts and where the
// report is; the endpoints' keys only when asked (they tell a third-party
// chat the target's internals). Text is for Slack and Mattermost.
type Payload struct {
	ID       string         `json:"id"` // the same for a resend: deduplicate on it
	Target   string         `json:"target"`
	Snapshot string         `json:"snapshot"`
	Counts   map[string]int `json:"counts"`
	Report   string         `json:"report"`
	Changes  []PayloadItem  `json:"changes,omitempty"`
	Text     string         `json:"text"`
}

type PayloadItem struct {
	Severity string   `json:"severity"`
	Kind     string   `json:"kind"`
	Key      string   `json:"key"`
	Roles    []string `json:"roles"`
}

const maxPayload = 32 << 10

// NewPayload builds the webhook's body for the changes from floor up.
func NewPayload(r *Result, target, report, floor string, keys bool) *Payload {
	p := &Payload{Target: target, Snapshot: r.Snapshot.ID, Report: report, Counts: map[string]int{}}
	sum := sha256.Sum256([]byte(target + r.Snapshot.ID))
	p.ID = hex.EncodeToString(sum[:8])
	var lines []string
	for _, c := range r.Changes {
		if !AtLeast(c.Severity, floor) {
			continue
		}
		p.Counts[c.Severity]++
		if keys && len(p.Changes) < 50 {
			k := roles.MaskTokens(c.Key)
			p.Changes = append(p.Changes, PayloadItem{c.Severity, c.Kind, k, c.Roles})
			lines = append(lines, fmt.Sprintf("• %s %s %s", c.Severity, c.Kind, chat(k)))
		}
	}
	p.Text = fmt.Sprintf("jsharvest monitor: %s — %d high, %d medium, %d low. Report: %s", chat(target), p.Counts[High], p.Counts[Medium], p.Counts[Low], chat(report))
	if len(lines) > 0 {
		p.Text += "\n" + strings.Join(lines, "\n")
	}
	for b, _ := json.Marshal(p); len(b) > maxPayload && len(p.Changes) > 0; b, _ = json.Marshal(p) {
		p.Changes = p.Changes[:len(p.Changes)/2]
		p.Text = p.Text[:min(len(p.Text), maxPayload/2)] + "…"
	}
	return p
}

// chat quotes the target's text for a chat: no markup, no mentions.
func chat(s string) string {
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "*", "∗", "_", "\\_", "~", "∼", "`", "'").Replace(s)
	return strings.ReplaceAll(s, "@", "@​")
}

// ErrInsecure says a webhook URL is not https (or the loopback's).
var ErrInsecure = errors.New("the webhook must be https (http only to the loopback)")

// Send posts a payload: no redirect followed, ten seconds, one retry.
// Its errors never hold the URL (it carries the chat's secret).
func Send(ctx context.Context, rawURL string, p *Payload) error {
	return SendWith(ctx, rawURL, p, nil)
}

// SendWith is Send through the run's proxy (netsafe.ProxyFrom; nil: none).
// The webhook is a URL the user wrote, not the target: no check of its
// address is made (an internal webhook is a valid one), only the proxy
// the run chose is followed, never the environment's by Go's own rule
// (loopback goes direct, as everywhere: netsafe.ProxyFunc).
func SendWith(ctx context.Context, rawURL string, p *Payload, proxy *url.URL) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("the webhook URL does not parse")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname())) {
		return ErrInsecure
	}
	body, _ := json.Marshal(p)
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: netsafe.ProxyFunc(proxy, nil)}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last error
	for try := 0; try < 2; try++ {
		req, _ := http.NewRequestWithContext(ctx, "POST", rawURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", p.ID)
		resp, err := cl.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err // the URL out
			}
			last = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		last = fmt.Errorf("the webhook answered %d", resp.StatusCode)
		if resp.StatusCode < 500 {
			break // a redirect, a refusal: a retry would not help
		}
	}
	return last
}

func loopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Pending keeps a payload the webhook did not take, for the next run.
func Pending(dir string, p *Payload) error {
	b, _ := json.Marshal(p)
	return os.WriteFile(filepath.Join(dir, "pending-webhook.json"), b, 0o600)
}

// TakePending returns the payload left by a failed send, and forgets it.
func TakePending(dir string) *Payload {
	f := filepath.Join(dir, "pending-webhook.json")
	b, err := os.ReadFile(f)
	if err != nil {
		return nil
	}
	os.Remove(f)
	var p Payload
	if json.Unmarshal(b, &p) != nil {
		return nil
	}
	return &p
}
