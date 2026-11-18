package endpoints

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// IntelFile is what the code tells besides its endpoints: the headers its
// clients add to every request (an API gateway's client_id and
// client_secret, an app_version it checks), the base URLs clients are
// given, and the cloud storage it names. It is 0600: the values are
// credentials as often as not.
const IntelFile = "intel.json"

type Intel struct {
	Bases   []string      `json:"bases,omitempty"`
	Headers []IntelHeader `json:"client_headers,omitempty"`
	Cloud   []IntelURL    `json:"cloud,omitempty"`
	// Keys are the settings the code names that are keys, ids or secrets
	// (a Firebase apiKey, a client_id), with their value.
	Keys        []IntelHeader      `json:"keys,omitempty"`
	Routes      []IntelRoute       `json:"routes,omitempty"`
	GraphQLDocs []jsapi.GraphQLDoc `json:"graphql_docs,omitempty"`
	ClientAuthz *ClientAuthz       `json:"client_authz,omitempty"`
	// ServerHints and SecurityNotes are read from the answers the crawls
	// got (requests.jsonl), passively: what the servers run, what of their
	// configuration is worth a look.
	ServerHints   []ServerHint   `json:"server_hints,omitempty"`
	SecurityNotes []SecurityNote `json:"security_notes,omitempty"`
	AuthFlows     []AuthFlow     `json:"auth_flows,omitempty"`
}

// IntelHeader is a header a client sets, with the value the code gives it
// ({} for what it computes: "Bearer {}").
type IntelHeader struct {
	Name    string   `json:"name"`
	Value   string   `json:"value"`
	Sources []Source `json:"sources"`
}

type IntelURL struct {
	URL           string   `json:"url"`
	Provider      string   `json:"provider,omitempty"`
	Bucket        string   `json:"bucket,omitempty"`
	Region        string   `json:"region,omitempty"`
	ObjectKey     string   `json:"object_key,omitempty"`
	BucketRootURL string   `json:"bucket_root_url,omitempty"`
	Status        string   `json:"status,omitempty"`
	Sources       []Source `json:"sources"`
}

type IntelRoute struct {
	Path         string   `json:"path"`
	Redirect     string   `json:"redirect,omitempty"`
	AuthRequired *bool    `json:"auth_required,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	Sources      []Source `json:"sources"`
}

var trackerDomains = map[string]bool{
	"google-analytics.com":        true,
	"googletagmanager.com":        true,
	"analytics.google.com":        true,
	"doubleclick.net":             true,
	"googlesyndication.com":       true,
	"googleadservices.com":        true,
	"facebook.net":                true,
	"facebook.com":                true,
	"hotjar.com":                  true,
	"clarity.ms":                  true,
	"intercom.io":                 true,
	"intercomcdn.com":             true,
	"segment.io":                  true,
	"segment.com":                 true,
	"mixpanel.com":                true,
	"amplitude.com":               true,
	"fullstory.com":               true,
	"datadoghq-browser-agent.com": true,
	"newrelic.com":                true,
	"nr-data.net":                 true,
	"tiktok.com":                  true,
	"snapchat.com":                true,
	"linkedin.com":                true,
	"bing.com":                    true,
	"yandex.ru":                   true,
	"baidu.com":                   true,
}

// IsTrackerHost reports whether host belongs to a known third-party analytics,
// advertising, or tag-manager service rather than application infrastructure.
func IsTrackerHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(hostname(strings.TrimSpace(host)), "."))
	for h != "" {
		if trackerDomains[h] {
			return true
		}
		_, rest, ok := strings.Cut(h, ".")
		if !ok {
			return false
		}
		h = rest
	}
	return false
}

func allURLsTracker(urls []string) bool {
	if len(urls) == 0 {
		return true
	}
	for _, raw := range urls {
		baseRaw, _, _ := strings.Cut(raw, "#")
		u, err := url.Parse(baseRaw)
		if err != nil || u.Hostname() == "" || !IsTrackerHost(u.Hostname()) {
			return false
		}
	}
	return true
}

func isTrackerScript(s Script) bool {
	return s.ThirdParty && allURLsTracker(s.URLs)
}

// BuildIntel gathers static intelligence from app-referenced scripts (including
// first-party bundles hosted on CDNs), while excluding third-party analytics
// and advertising trackers.
func BuildIntel(scripts []Script, inScope func(host string) bool) Intel {
	var in Intel
	headers := map[[2]string]*IntelHeader{}
	keys := map[[2]string]*IntelHeader{}
	cloud := map[string]*IntelURL{}
	routes := map[string]*IntelRoute{}
	linkedConsts := resolveScriptAuthzConsts(scripts)
	for idx, s := range scripts {
		if isTrackerScript(s) {
			continue
		}
		script := ""
		if len(s.URLs) > 0 {
			script = s.URLs[0]
		}
		in.Bases = append(in.Bases, s.Bases...)
		in.GraphQLDocs = mergeGQLDocs(in.GraphQLDocs, s.GraphQLDocs)
		for _, h := range s.ClientHeaders {
			k := [2]string{h.Name, h.Value}
			ih := headers[k]
			if ih == nil {
				ih = &IntelHeader{Name: h.Name, Value: h.Value}
				headers[k] = ih
			}
			if len(ih.Sources) < maxSources {
				ih.Sources = append(ih.Sources, Source{SHA256: s.SHA256, Script: script, Line: h.Line, Kind: "header"})
			}
		}
		for _, h := range s.Keys {
			k := [2]string{h.Name, h.Value}
			ik := keys[k]
			if ik == nil {
				ik = &IntelHeader{Name: h.Name, Value: h.Value}
				keys[k] = ik
			}
			if len(ik.Sources) < maxSources {
				ik.Sources = append(ik.Sources, Source{SHA256: s.SHA256, Script: script, Line: h.Line, Kind: "key"})
			}
		}
		for _, u := range s.Cloud {
			iu := cloud[u]
			if iu == nil {
				iu = newIntelURL(u)
				cloud[u] = iu
			}
			if len(iu.Sources) < maxSources {
				iu.Sources = append(iu.Sources, Source{SHA256: s.SHA256, Script: script, Kind: "string"})
			}
		}
		extra := linkedConsts[idx]
		for _, re := range s.RouteEntries {
			if re.Path == "" {
				continue
			}
			ir := routes[re.Path]
			if ir == nil {
				ir = &IntelRoute{Path: re.Path, Redirect: re.Redirect}
				if re.AuthRequired != nil {
					v := *re.AuthRequired
					ir.AuthRequired = &v
				}
				routes[re.Path] = ir
			} else {
				if ir.Redirect == "" && re.Redirect != "" {
					ir.Redirect = re.Redirect
				}
				if ir.AuthRequired == nil && re.AuthRequired != nil {
					v := *re.AuthRequired
					ir.AuthRequired = &v
				}
			}
			roles := re.Roles
			perms := re.Permissions
			if extra != nil {
				if xr := extra.routeRoles[re.Path]; len(xr) > 0 {
					roles = append(slices.Clone(roles), xr...)
				}
				if xp := extra.routePerms[re.Path]; len(xp) > 0 {
					perms = append(slices.Clone(perms), xp...)
				}
			}
			if len(roles) > 0 {
				ir.Roles = uniq(append(ir.Roles, roles...))
			}
			if len(perms) > 0 {
				ir.Permissions = uniq(append(ir.Permissions, perms...))
			}
			if len(ir.Sources) < maxSources {
				ir.Sources = append(ir.Sources, Source{SHA256: s.SHA256, Script: script, Line: re.Line, Kind: "route"})
			}
		}
	}
	in.Bases = PreferInScope(uniq(in.Bases), inScope)
	for _, k := range keys {
		in.Keys = append(in.Keys, *k)
	}
	sort.Slice(in.Keys, func(i, j int) bool {
		a, b := in.Keys[i], in.Keys[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Value < b.Value
	})
	for _, h := range headers {
		in.Headers = append(in.Headers, *h)
	}
	sort.Slice(in.Headers, func(i, j int) bool {
		a, b := in.Headers[i], in.Headers[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Value < b.Value
	})
	for _, u := range cloud {
		in.Cloud = append(in.Cloud, *u)
	}
	sort.Slice(in.Cloud, func(i, j int) bool { return in.Cloud[i].URL < in.Cloud[j].URL })
	for _, r := range routes {
		in.Routes = append(in.Routes, *r)
	}
	sort.Slice(in.Routes, func(i, j int) bool { return in.Routes[i].Path < in.Routes[j].Path })
	in.ClientAuthz = MergeClientAuthz(scripts)
	return in
}

// SaveIntel builds intel.json out of the analysis cache (Catalog with
// analyze fills it) and writes it, or removes an old one when there is
// nothing. redact, when not nil, hides a header's value.
func SaveIntel(dir string, inScope func(host string) bool, redact func(name, value string) string) (Intel, error) {
	scripts, err := loadDir(dir, true)
	if err != nil {
		return Intel{}, err
	}
	return SaveIntelFromScripts(dir, scripts, inScope, redact)
}

// SaveIntelFromScripts builds and persists intel.json from an already-loaded
// slice of scripts so callers that just ran AnalyzeSlim/Catalog avoid a second
// full pass over thousands of static/<sha>.json files.
func SaveIntelFromScripts(dir string, scripts []Script, inScope func(host string) bool, redact func(name, value string) string) (Intel, error) {
	in := BuildIntel(scripts, inScope)
	in.Bases = enrichIntelBases(dir, scripts, in.Bases, inScope)
	in.ServerHints, in.SecurityNotes, in.AuthFlows = infraAll(dir, inScope)
	if redact != nil {
		for i := range in.Headers {
			in.Headers[i].Value = redact(in.Headers[i].Name, in.Headers[i].Value)
		}
		for i := range in.Keys {
			in.Keys[i].Value = redact(in.Keys[i].Name, in.Keys[i].Value)
		}
	}
	path := filepath.Join(dir, IntelFile)
	if len(in.Bases) == 0 && len(in.Headers) == 0 && len(in.Cloud) == 0 && len(in.Keys) == 0 && len(in.Routes) == 0 && len(in.GraphQLDocs) == 0 && in.ClientAuthz == nil && len(in.ServerHints) == 0 && len(in.SecurityNotes) == 0 && len(in.AuthFlows) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return in, err
		}
		return in, nil
	}
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return in, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		_ = os.Remove(tmp)
		return in, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return in, err
	}
	return in, nil
}

// Names lists the headers' names, once each.
func (in Intel) Names() []string {
	var out []string
	for _, h := range in.Headers {
		if !slices.Contains(out, h.Name) {
			out = append(out, h.Name)
		}
	}
	return out
}

func enrichIntelBases(dir string, scripts []Script, bases []string, inScope func(string) bool) []string {
	hasAbsInScope := func(bs []string) bool {
		for _, b := range bs {
			if u, err := url.Parse(b); err == nil && u.Host != "" && (inScope == nil || inScope(u.Hostname())) {
				return true
			}
		}
		return false
	}
	var extra []string
	if f, err := os.Open(filepath.Join(dir, File)); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
		for sc.Scan() {
			var e Endpoint
			if json.Unmarshal(sc.Bytes(), &e) != nil || e.ThirdParty {
				continue
			}
			if strings.HasPrefix(e.Base, "/") && !strings.HasPrefix(e.Base, "//") {
				orig := e.Origin
				if e.Host != "" && !strings.Contains(e.Host, "{") {
					orig = hostOrigin(e.Host)
				} else if orig == "" {
					orig = epScriptOrigin(&e, inScope)
				}
				if orig != "" && (!hasAbsInScope(bases) || !slices.Contains(bases, e.Base)) {
					extra = append(extra, strings.TrimRight(orig, "/")+e.Base)
				}
			}
		}
		f.Close()
	}
	if !hasAbsInScope(bases) && len(extra) == 0 {
		var pageOrigs []string
		for _, s := range scripts {
			if isTrackerScript(s) || len(s.URLs) == 0 {
				continue
			}
			orig := originOf(s.URLs[0])
			if orig == "" {
				continue
			}
			_, h, _ := strings.Cut(orig, "://")
			hn := hostname(h)
			if inScope != nil && !inScope(hn) {
				continue
			}
			if !strings.HasPrefix(hn, "cdn.") && !strings.HasPrefix(hn, "static.") && !strings.HasPrefix(hn, "assets.") && !slices.Contains(pageOrigs, orig) {
				pageOrigs = append(pageOrigs, orig)
			}
			for _, b := range s.Bases {
				if strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
					extra = append(extra, strings.TrimRight(orig, "/")+b)
				}
			}
		}
		if len(extra) == 0 && len(pageOrigs) == 1 {
			for _, b := range bases {
				if strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
					extra = append(extra, strings.TrimRight(pageOrigs[0], "/")+b)
				}
			}
		}
	}
	if len(extra) == 0 {
		return bases
	}
	return PreferInScope(uniq(append(bases, extra...)), inScope)
}

func hostOrigin(host string) string {
	if strings.HasSuffix(host, ":80") || strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost") {
		return "http://" + host
	}
	return "https://" + host
}
