package flow

import (
	"strconv"
	"strings"
	"time"
)

// Event is one DOM event the page's reporter saw. Its Tag is the name the
// page's tagger gave the task its handlers ran in, so a request whose async
// stack carries the tag was caused by this event.
type Event struct {
	Tag     string    `json:"tag"` // "<timeOrigin>:<timeStamp>:<type>"
	Type    string    `json:"type"`
	Wall    time.Time `json:"-"`
	Trusted bool      `json:"trusted"`
	Top     bool      `json:"top"` // in the main frame
	URL     string    `json:"url"`
	Element *Element  `json:"element,omitempty"`
	Lane    int       `json:"-"` // the tab it came from (crawl -tabs); 0 with one
}

type Element struct {
	Tag      string `json:"tag,omitempty"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Role     string `json:"role,omitempty"`
	Label    string `json:"label,omitempty"`
	Selector string `json:"selector,omitempty"`
	Href     string `json:"href,omitempty"`
	Action   string `json:"action,omitempty"`
}

// tagParts splits a tag into its document (the time origin), its time
// stamp and its event type.
func tagParts(tag string) (doc string, ts float64, typ string, ok bool) {
	doc, rest, ok1 := strings.Cut(tag, ":")
	tsText, typ, ok2 := strings.Cut(rest, ":")
	if !ok1 || !ok2 {
		return "", 0, "", false
	}
	ts, err := strconv.ParseFloat(tsText, 64)
	if err != nil {
		return "", 0, "", false
	}
	return doc, ts, typ, true
}

// Frame is one frame of a request's initiator stack.
type Frame struct {
	URL  string
	Func string
	Line int64
	Col  int64
}

func (f Frame) key() string {
	u, _, _ := strings.Cut(f.URL, "?")
	return u + "#" + f.Func + ":" + strconv.FormatInt(f.Line, 10) + ":" + strconv.FormatInt(f.Col, 10)
}

// Request is what grouping needs of one line of requests.jsonl.
type Request struct {
	ID           int
	Time, End    time.Time
	Target       string // page, iframe, worker…
	Page         string
	Method       string
	URL          string
	ResourceType string
	Outcome      string
	MainDocument bool     // a navigation of the tab's main frame
	Chain        []string // async boundaries, nearest first
	Stack        []Frame  // top first
	Internal     bool     // made by jsharvest itself
	Lane         int      // the tab it came from (crawl -tabs); 0 with one

	// Values found in the request (where a fuzzer would put its input),
	// and values its response provides that a later request may carry.
	Uses     []Value
	Provides []Value
}

// Value is a value at a place in a request or a response, such as
// header:x-csrf-token or json:$.csrf.
type Value struct {
	V  string
	At string
}

// How a request came to belong to an action.
const (
	Causal  = "causal"  // the action's tag is in the request's async stack
	Handler = "handler" // an HTML attribute handler of the action's event type made it
	Window  = "window"  // it started while the action was the last one and still active
)

// Flow is one line of flows.jsonl: an action and the requests it caused.
type Flow struct {
	Run         string         `json:"run"`
	Action      string         `json:"action"`
	Kind        string         `json:"kind"`          // load, click, submit, change, input, key, nav, background
	Tab         int            `json:"tab,omitempty"` // the tab of the action (crawl -tabs)
	Label       string         `json:"label"`
	Trusted     bool           `json:"trusted,omitempty"`
	Element     *Element       `json:"element,omitempty"`
	Page        string         `json:"page,omitempty"`
	Started     time.Time      `json:"started"`
	Ended       time.Time      `json:"ended"`
	StartedBy   string         `json:"started_by,omitempty"` // for background work an action started
	Requests    []Ref          `json:"requests"`
	Writes      []int          `json:"writes,omitempty"`
	Endpoints   []Endpoint     `json:"endpoints,omitempty"`
	DependsOn   []Link         `json:"depends_on,omitempty"`
	Attribution map[string]int `json:"attribution,omitempty"`
}

type Ref struct {
	ID  int    `json:"id"`
	How string `json:"how,omitempty"`
}

type Endpoint struct {
	Method   string   `json:"method"`
	Host     string   `json:"host"`
	Template string   `json:"template"`
	Requests []int    `json:"requests"`
	Samples  []string `json:"samples,omitempty"` // distinct paths seen, at most 5
	Outcomes []string `json:"outcomes,omitempty"`
}

// Link says that a request carries a value an earlier response gave.
type Link struct {
	Request int     `json:"request"`
	At      string  `json:"at"`
	From    LinkEnd `json:"from"`
}

type LinkEnd struct {
	Request int    `json:"request"`
	At      string `json:"at"`
}
