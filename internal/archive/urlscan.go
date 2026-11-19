package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// URLScan lists what urlscan.io's public scans saw of a host (MAX-05): a
// real browser's visits, so an SPA's pages and, in each scan's result, every
// URL the page loaded (its scripts too). It only searches what others
// scanned: nothing is ever submitted. The search needs no key (a lower
// limit); URLSCAN_API_KEY raises it.
type URLScan struct {
	Base   string // https://urlscan.io
	Key    string
	Client *Client
	Budget *Budget
	// Pages: search pages of 100 scans to read, at most; Results: scans of
	// the target whose result (the URLs the page loaded) is read, the
	// newest first.
	Pages, Results int
}

// Scan is a search hit: a scan's id, when, and the page it visited.
type Scan struct {
	ID   string
	Time time.Time
	Page string
}

// Search lists a page of the scans of a host, from a cursor ("" first). It
// returns the pages the scans visited as captures, the scans, and the next
// cursor ("" when no more).
func (u *URLScan) Search(ctx context.Context, host, after string) ([]Capture, []Scan, string, error) {
	q := url.Values{}
	q.Set("q", "domain:"+host)
	q.Set("size", "100")
	if after != "" {
		q.Set("search_after", after)
	}
	a, err := u.get(ctx, u.Base+"/api/v1/search/?"+q.Encode())
	if err != nil {
		return nil, nil, "", err
	}
	var r struct {
		Results []struct {
			ID   string `json:"_id"`
			Task struct {
				URL  string `json:"url"`
				Time string `json:"time"`
			} `json:"task"`
			Page struct {
				URL      string `json:"url"`
				MIMEType string `json:"mimeType"`
				Status   any    `json:"status"`
			} `json:"page"`
			Sort []any `json:"sort"`
		} `json:"results"`
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal(a.Body, &r); err != nil {
		return nil, nil, "", fmt.Errorf("urlscan search: %w", err)
	}
	var caps []Capture
	var scans []Scan
	next := ""
	for _, x := range r.Results {
		t, _ := time.Parse(time.RFC3339, x.Task.Time)
		for _, raw := range []string{x.Page.URL, x.Task.URL} {
			if raw != "" {
				caps = append(caps, Capture{URL: Normalize(raw), Time: t, MIME: x.Page.MIMEType, Status: status(x.Page.Status), Source: "urlscan"})
			}
		}
		if x.ID != "" {
			scans = append(scans, Scan{ID: x.ID, Time: t, Page: Normalize(x.Page.URL)})
		}
		if len(x.Sort) > 0 {
			var parts []string
			for _, v := range x.Sort {
				parts = append(parts, fmt.Sprint(v))
			}
			next = strings.Join(parts, ",")
		}
	}
	if !r.HasMore {
		next = ""
	}
	return caps, scans, next, nil
}

// Result lists the URLs a scan's page loaded, as captures at the scan's
// time.
func (u *URLScan) Result(ctx context.Context, s Scan) ([]Capture, error) {
	a, err := u.get(ctx, u.Base+"/api/v1/result/"+url.PathEscape(s.ID)+"/")
	if err != nil {
		return nil, err
	}
	var r struct {
		Lists struct {
			URLs []string `json:"urls"`
		} `json:"lists"`
	}
	if err := json.Unmarshal(a.Body, &r); err != nil {
		return nil, fmt.Errorf("urlscan result: %w", err)
	}
	var caps []Capture
	for _, raw := range r.Lists.URLs {
		caps = append(caps, Capture{URL: Normalize(raw), Time: s.Time, Source: "urlscan"})
	}
	return caps, nil
}

func (u *URLScan) get(ctx context.Context, raw string) (*Answer, error) {
	var h http.Header
	if u.Key != "" {
		h = http.Header{"Api-Key": {u.Key}}
	}
	a, err := u.Client.GetIndexWith(ctx, u.Budget, raw, 64<<20, h)
	if err != nil {
		return nil, err
	}
	switch {
	case a.Status == 404:
		return &Answer{Status: 404, Body: []byte(`{}`)}, nil // a result gone
	case a.Status != 200:
		return nil, fmt.Errorf("urlscan: %d %s", a.Status, head(a.Body, 200))
	}
	return a, nil
}

// status is a page status as urlscan writes it: a number or a string.
func status(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprint(int(x))
	}
	return ""
}

// listURLScan searches the scans of the target, then reads the newest
// scans of its own pages for the URLs they loaded.
func (r *runner) listURLScan(ctx context.Context, stream *hostQueue) error {
	if stream != nil {
		defer stream.drop()
	}
	st := &r.st.URLScan
	for pages := 0; !st.Searched; pages++ {
		if r.o.URLScan.Pages > 0 && pages >= r.o.URLScan.Pages {
			r.mu.Lock()
			st.Searched = true // the newest are enough: older scans are older
			r.noteLocked(fmt.Sprintf("urlscan: the newest %d search pages read", pages))
			r.mu.Unlock()
			break
		}
		caps, scans, next, err := r.o.URLScan.Search(ctx, r.o.Host, st.After)
		if err != nil {
			return err
		}
		r.took(caps, func() {
			for _, s := range scans {
				if u, err := url.Parse(s.Page); err == nil && r.o.InScope(u.Hostname()) && len(st.Scans) < r.o.URLScan.Results {
					st.Scans = append(st.Scans, s.ID+" "+s.Time.Format(time.RFC3339))
				}
			}
			st.After, st.Searched = next, next == ""
		})
	}
	extraErr := r.extra(ctx, "urlscan", stream, func(hctx context.Context, host string) error {
		after := ""
		for page := 0; page < 2; page++ {
			caps, scans, next, err := r.o.URLScan.Search(hctx, host, after)
			if err != nil {
				return err
			}
			r.took(caps, func() {
				for _, s := range scans {
					if u, err := url.Parse(s.Page); err == nil && r.o.InScope(u.Hostname()) && len(st.Scans) < r.o.URLScan.Results {
						st.Scans = append(st.Scans, s.ID+" "+s.Time.Format(time.RFC3339))
					}
				}
			})
			if after = next; next == "" {
				break
			}
		}
		return nil
	})
	if extraErr != nil && (errors.Is(extraErr, ErrBlocked) || ctx.Err() != nil) {
		return extraErr
	}
	for st.Read < len(st.Scans) {
		id, ts, _ := strings.Cut(st.Scans[st.Read], " ")
		t, _ := time.Parse(time.RFC3339, ts)
		caps, err := r.o.URLScan.Result(ctx, Scan{ID: id, Time: t})
		if err != nil {
			return err
		}
		r.took(caps, func() { st.Read++ })
	}
	return extraErr
}
