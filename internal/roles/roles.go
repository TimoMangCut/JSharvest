// Package roles compares what the roles of one target reached: scripts,
// endpoints, pages and features that a higher role uses and a lower one
// does not, or only as code, or is refused. It reads the crawl output of
// each role (<out>/<host>/<role>) and never sends a request. See
// docs/gd4-roles-design.md.
package roles

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"time"
)

// State is what one role has of an item.
type State string

const (
	Absent     State = "absent"     // the role went where the item is, and did not meet it
	Unknown    State = "unknown"    // the role did not go there: no sign either way
	Code       State = "code"       // in code the role has (a static endpoint, a script only the resolver fetched)
	Denied     State = "denied"     // asked, and refused: 401, 403, the login page
	Redirected State = "redirected" // asked, and sent elsewhere
	Held       State = "held"       // asked; the guard held the write back
	Used       State = "used"       // run, called or visited with success
)

// uses reports whether a state is the role having the item for real.
func (s State) uses() bool { return s == Used || s == Held }

// refused reports whether the server turned the role away.
func (s State) refused() bool { return s == Denied || s == Redirected }

// Classes, see the design.
const (
	ClientGated    = "client_gated"    // the role below has it as code only
	DeniedBelow    = "denied_below"    // the role below was refused
	HigherOnly     = "higher_only"     // the role below did not have it, where it looked
	ServerGated    = "server_gated"    // a script the role below was never given
	NotCovered     = "not_covered"     // the role below did not look where it is
	LowerOK        = "lower_ok"        // a role below its own uses it with success
	Inconsistent   = "inconsistent"    // a lower role uses it, a higher one is refused
	Unreached      = "unreached"       // in code, used by no role
	ContentDiffers = "content_differs" // one script, other contents by role
	ShapeDiffers   = "shape_differs"   // one endpoint, more parameters for a higher role
	Same           = "same"
)

// Item is one line of the report.
type Item struct {
	Layer    string               `json:"layer"` // endpoint, feature, page, script
	Key      string               `json:"key"`
	Class    string               `json:"class"`
	Also     []string             `json:"also,omitempty"`   // other classes that hold
	Lowest   string               `json:"lowest,omitempty"` // the lowest role that uses it
	Native   string               `json:"native,omitempty"` // the role it belongs to, when known
	States   map[string]State     `json:"states"`
	Evidence map[string]*Evidence `json:"evidence,omitempty"`
}

// Evidence is what one role saw of an item.
type Evidence struct {
	Statuses []int64  `json:"statuses,omitempty"`
	Mixed    bool     `json:"mixed,omitempty"` // success and refusal both: an IDOR's sign
	Samples  []string `json:"samples,omitempty"`
	Refs     []Ref    `json:"refs,omitempty"`
	Pages    []string `json:"pages,omitempty"`
	Params   []string `json:"params,omitempty"`
	SHA256   []string `json:"sha256,omitempty"`
	Label    string   `json:"label,omitempty"`
	Writes   int      `json:"writes,omitempty"`
	FinalURL string   `json:"final_url,omitempty"`
	Status   int64    `json:"status,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

type Ref struct {
	Run string `json:"run"`
	ID  int    `json:"id"`
}

// Report is diff.json.
type Report struct {
	Host      string                    `json:"host"`
	Roles     []string                  `json:"roles"`
	Generated time.Time                 `json:"generated"`
	Config    map[string][]RunConfig    `json:"config"`
	Warnings  []string                  `json:"warnings,omitempty"`
	Summary   map[string]map[string]int `json:"summary"`
	Items     []Item                    `json:"items"`
}

// RunConfig is a run's config, as run.json and runs.jsonl keep it.
type RunConfig struct {
	Run      string `json:"run"`
	Depth    int    `json:"depth"`
	MaxPages int    `json:"max_pages,omitempty"`
	Explore  bool   `json:"explore"`
	Resolve  bool   `json:"resolve"`
	Guard    bool   `json:"guard"`
	Debugger bool   `json:"debugger"`
	Session  bool   `json:"session"`
	Lost     bool   `json:"session_lost,omitempty"`
	// Engine is "http" for a crawl without a browser (crawl -engine http,
	// the default for anon); a browser's run leaves it out.
	Engine string `json:"engine,omitempty"`
	Known  bool   `json:"-"`
}

type Options struct {
	Root  string   // <out>/<host>
	Roles []string // lowest first
	All   bool     // report what is the same too
	// Redact hides credentials in what the report quotes; nil quotes as is.
	Redact func(string) string
	// InScope tells the target's hosts.
	InScope func(host string) bool
}

// Known role names, lowest first: the order taken when -roles is not given.
var known = []string{"anon", "default", "guest", "user", "member", "admin"}

// Order sorts role names lowest first, when all are known names.
func Order(names []string) ([]string, error) {
	var out []string
	for _, k := range known {
		if slices.Contains(names, k) {
			out = append(out, k)
		}
	}
	if len(out) != len(names) {
		return nil, fmt.Errorf("roles %v: give their order, lowest first (-roles a,b,c); only %v are ordered by name", names, known)
	}
	return out, nil
}

// Compare reads the roles' output and builds the report.
func Compare(o Options) (*Report, error) {
	if len(o.Roles) < 2 {
		return nil, fmt.Errorf("compare: need two roles at least, got %v", o.Roles)
	}
	if o.Redact == nil {
		o.Redact = func(s string) string { return s }
	}
	if o.InScope == nil {
		o.InScope = func(string) bool { return true }
	}
	rep := &Report{Host: filepath.Base(o.Root), Roles: o.Roles, Generated: time.Now().UTC(), Config: map[string][]RunConfig{},
		Summary: map[string]map[string]int{}}
	var data []*roleData
	for _, r := range o.Roles {
		d, err := load(filepath.Join(o.Root, r), r, o)
		if err != nil {
			return nil, err
		}
		data = append(data, d)
		rep.Config[r] = d.configs
		rep.Warnings = append(rep.Warnings, d.warnings...)
	}
	rep.Warnings = append(rep.Warnings, compareConfigs(data)...)
	c := &comparer{o: o, roles: data}
	pages := c.pages()
	scripts, buildWarn := c.scripts()
	rep.Warnings = append(rep.Warnings, buildWarn...)
	endpoints := c.endpoints(scripts, pages)
	features := c.features()
	for _, layer := range [][]Item{endpoints, features, pages, scripts} {
		for _, it := range layer {
			if it.Class == Same && !o.All {
				continue
			}
			rep.Items = append(rep.Items, it)
		}
	}
	for _, it := range rep.Items {
		if rep.Summary[it.Layer] == nil {
			rep.Summary[it.Layer] = map[string]int{}
		}
		rep.Summary[it.Layer][it.Class]++
	}
	sort.SliceStable(rep.Items, func(i, j int) bool {
		a, b := rep.Items[i], rep.Items[j]
		if layerRank[a.Layer] != layerRank[b.Layer] {
			return layerRank[a.Layer] < layerRank[b.Layer]
		}
		if classRank[a.Class] != classRank[b.Class] {
			return classRank[a.Class] < classRank[b.Class]
		}
		return a.Key < b.Key
	})
	return rep, nil
}

var (
	layerRank = map[string]int{"endpoint": 0, "feature": 1, "page": 2, "script": 3}
	classRank = map[string]int{LowerOK: 0, ClientGated: 1, Inconsistent: 2, DeniedBelow: 3, HigherOnly: 4, ServerGated: 5,
		ShapeDiffers: 6, ContentDiffers: 7, NotCovered: 8, Unreached: 9, Same: 10}
)

// classify gives an item its class from its states, lowest role first, and
// the role it belongs to (an index, or -1).
func classify(states []State, native int) (class string, lowest int, also []string) {
	lowest = slices.IndexFunc(states, State.uses)
	if lowest < 0 {
		if slices.Contains(states, Code) {
			return Unreached, -1, nil
		}
		return "", -1, nil
	}
	// A lower role uses it while a higher one is refused.
	for i := lowest + 1; i < len(states); i++ {
		if states[i].refused() {
			also = append(also, Inconsistent)
			break
		}
	}
	if lowest == 0 {
		class = Same
	} else {
		// The role right below decides: what the server refused it is the
		// server's check, though a role lower still has the code.
		switch states[lowest-1] {
		case Denied, Redirected:
			class = DeniedBelow
		case Code:
			class = ClientGated
		case Absent:
			class = HigherOnly
		default:
			class = NotCovered
		}
	}
	if native > lowest {
		also = append([]string{class}, also...)
		class = LowerOK
	} else if class == Same && len(also) > 0 {
		class, also = Inconsistent, also[1:]
	}
	return class, lowest, also
}

// item makes a report line of states by role.
func (c *comparer) item(layer, key string, states []State, native int, ev []*Evidence) Item {
	class, lowest, also := classify(states, native)
	it := Item{Layer: layer, Key: key, Class: class, Also: also, States: map[string]State{}, Evidence: map[string]*Evidence{}}
	for i, r := range c.roles {
		it.States[r.name] = states[i]
		if i < len(ev) && ev[i] != nil {
			it.Evidence[r.name] = ev[i]
		}
	}
	if lowest >= 0 {
		it.Lowest = c.roles[lowest].name
	}
	if native >= 0 {
		it.Native = c.roles[native].name
	}
	if len(it.Evidence) == 0 {
		it.Evidence = nil
	}
	return it
}

type comparer struct {
	o     Options
	roles []*roleData

	pageStates   []map[string]State // by role: each page's state
	pageItems    map[string]Item    // by page key
	scriptNative map[string]int     // by SHA-256: the role a gated script belongs to
}

// readLines decodes each line of a jsonl file into a fresh T; a missing
// file is no lines.
func readLines[T any](path string, f func(T)) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			f(v)
		}
	}
	return sc.Err()
}

var (
	digitsRe = regexp.MustCompile(`\d+`)
	emailRe  = regexp.MustCompile(`[\w.+-]+@[\w-]+(\.[\w-]+)+`)
)

func norm(s string) string { return digitsRe.ReplaceAllString(s, "#") }

func uniq[T comparable](xs []T, x T) []T {
	if slices.Contains(xs, x) {
		return xs
	}
	return append(xs, x)
}
