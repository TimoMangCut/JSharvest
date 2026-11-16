package guard

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Redact returns the records with credentials hidden.
func Redact(records []Record, r *traffic.Redactor) []Record {
	out := make([]Record, len(records))
	for i, rec := range records {
		rec.URL, rec.Page = r.URL(rec.URL), r.URL(rec.Page)
		rec.Headers = r.Headers(rec.Headers)
		rec.Body = r.Text(rec.Body)
		out[i] = rec
	}
	return out
}

// Append adds records to blocked.jsonl in dir, so that every run's held-back
// requests stay on record next to the scripts. The file holds real headers
// and bodies, so only the user may read it.
func Append(dir string, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(dir, "blocked.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	enc := json.NewEncoder(f)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

// WriteHAR writes the records of this run as a HAR 1.2 log, which Burp and
// browsers' devtools open, so a held-back request can be replayed by hand.
func WriteHAR(path string, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	type nv struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type post struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
	}
	type request struct {
		Method      string `json:"method"`
		URL         string `json:"url"`
		HTTPVersion string `json:"httpVersion"`
		Headers     []nv   `json:"headers"`
		QueryString []nv   `json:"queryString"`
		Cookies     []nv   `json:"cookies"`
		PostData    *post  `json:"postData,omitempty"`
		HeadersSize int    `json:"headersSize"`
		BodySize    int    `json:"bodySize"`
	}
	type entry struct {
		StartedDateTime string         `json:"startedDateTime"`
		Time            int            `json:"time"`
		Request         request        `json:"request"`
		Response        map[string]any `json:"response"`
		Cache           map[string]any `json:"cache"`
		Timings         map[string]int `json:"timings"`
		Comment         string         `json:"comment"`
	}
	var entries []entry
	for _, r := range records {
		req := request{Method: r.Method, URL: r.URL, HTTPVersion: "HTTP/1.1", HeadersSize: -1, BodySize: len(r.Body),
			Headers: []nv{}, QueryString: []nv{}, Cookies: []nv{}}
		names := make([]string, 0, len(r.Headers))
		for k := range r.Headers {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			req.Headers = append(req.Headers, nv{k, r.Headers[k]})
		}
		if u, err := url.Parse(r.URL); err == nil {
			for k, vs := range u.Query() {
				for _, v := range vs {
					req.QueryString = append(req.QueryString, nv{k, v})
				}
			}
		}
		if r.Body != "" {
			req.PostData = &post{MimeType: r.Headers["content-type"], Text: r.Body}
		}
		entries = append(entries, entry{
			StartedDateTime: r.Time.Format("2006-01-02T15:04:05.000Z07:00"), Request: req,
			Response: map[string]any{"status": 0, "statusText": "held back by jsharvest guard", "httpVersion": "HTTP/1.1", "headers": []nv{},
				"cookies": []nv{}, "content": map[string]any{"size": 0, "mimeType": ""}, "redirectURL": "", "headersSize": -1, "bodySize": -1},
			Cache: map[string]any{}, Timings: map[string]int{"send": 0, "wait": 0, "receive": 0},
			Comment: r.Reason,
		})
	}
	doc := map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]string{"name": "jsharvest", "version": "guard"}, "entries": entries}}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
