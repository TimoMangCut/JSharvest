package export

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// HAR 1.2, with what ZAP's importer and DevTools' (HARFormat.ts) require
// of every entry: a response, content.size, timings, the HTTP versions.

type HAR struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string      `json:"version"`
	Creator nameVersion `json:"creator"`
	Pages   []harPage   `json:"pages"`
	Entries []harEntry  `json:"entries"`
}

type nameVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harPage struct {
	Started string         `json:"startedDateTime"`
	ID      string         `json:"id"`
	Title   string         `json:"title"`
	Timings map[string]int `json:"pageTimings"`
}

type nv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harEntry struct {
	PageRef         string         `json:"pageref,omitempty"`
	StartedDateTime string         `json:"startedDateTime"`
	Time            float64        `json:"time"`
	Request         harRequest     `json:"request"`
	Response        harResponse    `json:"response"`
	Cache           struct{}       `json:"cache"`
	Timings         harTimings     `json:"timings"`
	ServerIP        string         `json:"serverIPAddress,omitempty"`
	ResourceType    string         `json:"_resourceType,omitempty"`
	Jsharvest       map[string]any `json:"_jsharvest,omitempty"`
	Comment         string         `json:"comment,omitempty"`
}

type harRequest struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Cookies     []nv     `json:"cookies"`
	Headers     []nv     `json:"headers"`
	QueryString []nv     `json:"queryString"`
	PostData    *harPost `json:"postData,omitempty"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
}

type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Comment  string `json:"comment,omitempty"`
}

type harResponse struct {
	Status      int64      `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Cookies     []nv       `json:"cookies"`
	Headers     []nv       `json:"headers"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int        `json:"bodySize"`
	Comment     string     `json:"comment,omitempty"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// HAREntry is one request of a HAR, with what the export knows of it.
type HAREntry struct {
	traffic.Entry
	Page string         // the pageref: the flow's id
	Info map[string]any // _jsharvest
}

// NewHAR makes a HAR of entries, with a page for each flow.
func NewHAR(pages []HARPage, entries []HAREntry) HAR {
	h := HAR{Log: harLog{Version: "1.2", Creator: nameVersion{"jsharvest", "export"}, Pages: []harPage{}, Entries: []harEntry{}}}
	for _, p := range pages {
		h.Log.Pages = append(h.Log.Pages, harPage{Started: stamp(p.Started), ID: p.ID, Title: p.Title, Timings: map[string]int{}})
	}
	for _, e := range entries {
		h.Log.Entries = append(h.Log.Entries, harOf(e))
	}
	return h
}

type HARPage struct {
	ID, Title string
	Started   time.Time
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// httpVersion maps CDP's protocol (http/1.1, h2, h3) to what HAR readers
// take; ZAP drops a version it does not know.
func httpVersion(p string) string {
	switch strings.ToLower(p) {
	case "h2", "http/2", "http/2.0":
		return "HTTP/2"
	case "h3", "http/3", "quic", "h3-29":
		return "HTTP/3"
	case "http/1.0":
		return "HTTP/1.0"
	}
	return "HTTP/1.1"
}

func sortedNV(h map[string]string) []nv {
	out := []nv{}
	for k, v := range h {
		for _, line := range strings.Split(v, "\n") {
			out = append(out, nv{k, line})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func harOf(x HAREntry) harEntry {
	e := x.Entry
	version := "HTTP/1.1"
	if e.Response != nil {
		version = httpVersion(e.Response.Protocol)
	}
	req := harRequest{Method: e.Method, URL: e.URL, HTTPVersion: version, Cookies: []nv{}, Headers: sortedNV(e.Headers),
		QueryString: []nv{}, HeadersSize: -1, BodySize: len(e.Body.Bytes())}
	for k, v := range e.Headers {
		if strings.EqualFold(k, "cookie") {
			for _, c := range strings.Split(v, ";") {
				if name, val, ok := strings.Cut(strings.TrimSpace(c), "="); ok {
					req.Cookies = append(req.Cookies, nv{name, val})
				}
			}
		}
	}
	if u, err := url.Parse(e.URL); err == nil {
		keys := []string{}
		q := u.Query()
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range q[k] {
				req.QueryString = append(req.QueryString, nv{k, v})
			}
		}
	}
	if e.Body.Body != "" {
		p := &harPost{MimeType: header(e.Headers, "content-type"), Text: e.Body.Body}
		if e.BodyBase64 {
			p.Comment = "text is base64: the body is not UTF-8"
		}
		if e.BodyTruncated {
			p.Comment = strings.TrimPrefix(p.Comment+"; truncated by the recorder", "; ")
		}
		req.PostData = p
	}
	out := harEntry{PageRef: x.Page, StartedDateTime: stamp(e.Time), Time: e.DurationMS, Request: req,
		Timings: harTimings{Send: 0, Wait: e.DurationMS, Receive: 0}, ResourceType: strings.ToLower(e.ResourceType), Jsharvest: x.Info}
	held := strings.HasPrefix(e.Outcome, "held_back")
	switch {
	case e.Response != nil && !held:
		r := e.Response
		resp := harResponse{Status: r.Status, StatusText: r.StatusText, HTTPVersion: version, Cookies: []nv{}, Headers: sortedNV(r.Headers),
			RedirectURL: header(r.Headers, "location"), HeadersSize: -1, BodySize: -1,
			Content: harContent{Size: len(r.Body.Bytes()), MimeType: r.MIME, Text: r.Body.Body}}
		if resp.Content.MimeType == "" {
			resp.Content.MimeType = "x-unknown"
		}
		if r.BodyBase64 {
			resp.Content.Encoding = "base64"
		}
		if r.BodyOmitted != "" {
			resp.Content.Comment = "body not recorded: " + r.BodyOmitted
		} else if r.BodyTruncated {
			resp.Content.Comment = "body truncated by the recorder"
		}
		out.Response, out.ServerIP = resp, r.RemoteIP
	default:
		// Held back by the guard, failed, or still open: never answered by
		// the server, as Chrome writes a blocked request.
		text := e.Outcome
		if held {
			text = "held back by jsharvest's guard (" + strings.TrimPrefix(e.Outcome, "held_back:") + "): never reached the server"
		}
		out.Response = harResponse{Status: 0, StatusText: "", HTTPVersion: version, Cookies: []nv{}, Headers: []nv{},
			Content: harContent{Size: 0, MimeType: "x-unknown"}, HeadersSize: -1, BodySize: -1, Comment: text}
		out.Comment = text
	}
	return out
}

func header(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// Marshal is the HAR as indented JSON.
func (h HAR) Marshal() ([]byte, error) { return json.MarshalIndent(h, "", " ") }
