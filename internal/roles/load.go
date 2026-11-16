package roles

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// roleData is one role's output, read and never written.
type roleData struct {
	name, dir string
	configs   []RunConfig
	warnings  []string
	latest    time.Time // the start of the role's latest run

	res     *results.Dir
	reqs    []*results.Req
	scripts []store.Entry
	catalog []endpoints.Endpoint
	pages   []pageLine
	flows   []flowOf
	login   string // the login page's path, from the saved session
}

type flowOf struct {
	run string
	f   flow.Flow
}

// pageLine is what roles reads of a line of pages.jsonl.
type pageLine struct {
	Run      string `json:"run"`
	URL      string `json:"url"`
	Visited  bool   `json:"visited"`
	FinalURL string `json:"final_url"`
	Status   int64  `json:"status"`
	Reason   string `json:"reason"`
	Error    string `json:"error"`
}

// runLine is what roles reads of a run's record (runs.jsonl).
type runLine struct {
	RunID   string     `json:"run_id"`
	Mode    string     `json:"mode"`
	Started time.Time  `json:"started"`
	Config  *RunConfig `json:"config"`
	Session *struct {
		Profile string `json:"profile"`
		Lost    bool   `json:"lost"`
	} `json:"session"`
}

func load(dir, name string, o Options) (*roleData, error) {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("role %s: no output at %s", name, dir)
	}
	d := &roleData{name: name, dir: dir}
	if _, live := results.ReadLive(dir); live {
		d.warnings = append(d.warnings, fmt.Sprintf("%s: a watch is writing this role's output now; the report is of a moment", name))
	}
	profile := ""
	err := readLines(filepath.Join(dir, "runs.jsonl"), func(r runLine) {
		c := RunConfig{Run: r.RunID}
		if r.Config != nil {
			c = *r.Config
			c.Run, c.Known = r.RunID, true
		}
		if r.Session != nil {
			c.Lost = r.Session.Lost
			if r.Session.Profile != "" {
				profile = r.Session.Profile
			}
		}
		if r.Mode == "watch" {
			return // a person's or an agent's session: no coverage to compare
		}
		d.configs = append(d.configs, c)
		if r.Started.After(d.latest) {
			d.latest = r.Started
		}
		if c.Lost {
			d.warnings = append(d.warnings, fmt.Sprintf("%s: run %s lost its session; its refusals may be the lost session's", name, r.RunID))
		}
	})
	if err != nil {
		return nil, err
	}
	if profile != "" {
		if snap, err := session.Load(profile); err == nil {
			d.login = pathOf(snap.LoginURL)
		}
	}
	if err := readLines(filepath.Join(dir, "index.jsonl"), func(e store.Entry) { d.scripts = append(d.scripts, e) }); err != nil {
		return nil, err
	}
	if err := readLines(filepath.Join(dir, "endpoints.jsonl"), func(e endpoints.Endpoint) { d.catalog = append(d.catalog, e) }); err != nil {
		return nil, err
	}
	if err := readLines(filepath.Join(dir, "pages.jsonl"), func(p pageLine) { d.pages = append(d.pages, p) }); err != nil {
		return nil, err
	}
	d.res = results.Open(dir)
	if err := d.res.Refresh(); err != nil {
		return nil, err
	}
	for _, run := range d.res.Runs() {
		d.reqs = append(d.reqs, d.res.Requests(run)...)
		fs, _, err := d.res.Flows(run)
		if err != nil {
			return nil, err
		}
		for _, f := range fs {
			d.flows = append(d.flows, flowOf{run, f})
		}
	}
	return d, nil
}

// compareConfigs warns when the roles were not crawled alike: then what
// only one role has may only be what only its crawl went to.
//
// A role crawled without a browser (-engine http, the default for anon)
// next to one crawled with Chrome is the tool's usual pair, not a mistake:
// it gets one note that says what the static crawl cannot see, in place of
// the explore/resolve/debugger differences that come with the engine.
func compareConfigs(data []*roleData) []string {
	var warn []string
	type cover struct {
		depth            int
		explore, resolve bool
		debugger         bool
		static           bool // every known run was the HTTP engine's
	}
	most := map[string]cover{}
	for _, d := range data {
		c := cover{static: true}
		known := false
		for _, rc := range d.configs {
			if !rc.Known {
				continue
			}
			known = true
			c.depth = max(c.depth, rc.Depth)
			c.explore = c.explore || rc.Explore
			c.resolve = c.resolve || rc.Resolve
			c.debugger = c.debugger || rc.Debugger
			c.static = c.static && rc.Engine == "http"
		}
		if !known {
			warn = append(warn, fmt.Sprintf("%s: no run says how it was crawled (an older jsharvest); coverage cannot be compared", d.name))
			continue
		}
		most[d.name] = c
		if !c.debugger && !c.static {
			warn = append(warn, fmt.Sprintf("%s: crawled with -no-debugger: scripts the resolver fetched and scripts that ran cannot be told apart", d.name))
		}
	}
	for i, a := range data {
		for _, b := range data[i+1:] {
			ca, oka := most[a.name]
			cb, okb := most[b.name]
			if !oka || !okb {
				continue
			}
			var diffs []string
			if ca.depth != cb.depth {
				diffs = append(diffs, fmt.Sprintf("depth %d vs %d", ca.depth, cb.depth))
			}
			// Explore and resolve come with the engine: a static role next to
			// a browser's is told once, after the pairs.
			if ca.static == cb.static {
				if ca.explore != cb.explore {
					diffs = append(diffs, fmt.Sprintf("explore %v vs %v", ca.explore, cb.explore))
				}
				if ca.resolve != cb.resolve {
					diffs = append(diffs, fmt.Sprintf("resolve %v vs %v", ca.resolve, cb.resolve))
				}
			}
			if len(diffs) > 0 {
				warn = append(warn, fmt.Sprintf("%s and %s were not crawled alike (%s): what only one of them has may be its crawl's reach, not its rights",
					a.name, b.name, strings.Join(diffs, ", ")))
			}
		}
	}
	var browser []string
	for _, d := range data {
		if c, ok := most[d.name]; ok && !c.static {
			browser = append(browser, d.name)
		}
	}
	if len(browser) > 0 {
		for _, d := range data {
			if c, ok := most[d.name]; ok && c.static {
				s := d.name
				warn = append(warn, fmt.Sprintf("%s was crawled without a browser (-engine http) and %s with Chrome: %s's scripts never ran, so what a role above used and %s only has in code is client_gated because %s sent nothing, not because its client hides it (authz still tests each; crawl %s with -engine cdp to compare requests)",
					s, strings.Join(browser, ", "), s, s, s, s))
			}
		}
	}
	return warn
}

func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.Path, "/") + "/"
}

// loginPathRe-free check: a path is a login page when one of its segments
// names one, or it is the saved session's login page.
func (d *roleData) isLogin(raw string) bool {
	p := pathOf(raw)
	if d.login != "" && d.login != "/" && p == d.login {
		return true
	}
	for _, seg := range strings.Split(strings.ToLower(p), "/") {
		if slices.Contains([]string{"login", "signin", "sign-in", "log-in", "logon"}, seg) {
			return true
		}
	}
	return false
}
