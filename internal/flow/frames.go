package flow

import (
	"net/url"
	"regexp"

	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// libraryRe names script files that hold libraries, not the application:
// their frames are never the feature's.
var libraryRe = regexp.MustCompile(`(?i)(^|[/._-])(vendors?|chunk-vendors|framework|polyfills?|runtime|node_modules|axios|jquery|react-dom|zone|lodash|webpack)([/._~-]|$)`)

// appFrames returns the first application frame of each request: the top
// frame that is not jsharvest's, not a third party's, not a library's, and
// not a hub. A hub is a frame on top of requests to three or more
// different endpoints: the application's own request wrapper (apiClient),
// found from the data, not from its name. Hubs are found from the shapes
// of the endpoints, before the frames are used to merge them.
func appFrames(reqs []Request, thirdParty func(string) bool) []string {
	candidates := make([][]Frame, len(reqs))
	for i, r := range reqs {
		for _, f := range r.Stack {
			if marker.IsInternal(f.URL) || marker.IsTagger(f.URL) || f.URL == "" || thirdParty(f.URL) {
				continue
			}
			if u, err := url.Parse(f.URL); err == nil && libraryRe.MatchString(u.Path) {
				continue
			}
			candidates[i] = append(candidates[i], f)
		}
	}
	hubs := map[string]bool{}
	pick := func(i int) string {
		for _, f := range candidates[i] {
			if !hubs[f.key()] {
				return f.key()
			}
		}
		return ""
	}
	// Peel wrappers off one layer at a time: an app may wrap its wrapper.
	for range 4 {
		seen := map[string]map[string]bool{}
		for i, r := range reqs {
			k := pick(i)
			if k == "" {
				continue
			}
			u, err := url.Parse(r.URL)
			if err != nil {
				continue
			}
			if seen[k] == nil {
				seen[k] = map[string]bool{}
			}
			seen[k][r.Method+" "+u.Host+ByShape(u.EscapedPath())] = true
		}
		grew := false
		for k, eps := range seen {
			if len(eps) >= 3 && !hubs[k] {
				hubs[k], grew = true, true
			}
		}
		if !grew {
			break
		}
	}
	out := make([]string, len(reqs))
	for i := range reqs {
		out[i] = pick(i)
	}
	return out
}

func endpointTemplates(reqs []Request, o Options) []string {
	frames := appFrames(reqs, o.ThirdParty)
	calls := make([]Call, len(reqs))
	for i, r := range reqs {
		calls[i] = Call{Method: r.Method, URL: r.URL, Frame: frames[i]}
	}
	return Templates(calls)
}

// EntryTemplates is the endpoint template of each logged request, as the
// flows have them: calls merged by their first application frame below
// the request wrappers, not by the wrapper all of them go through.
// thirdParty tells a script URL outside the target.
func EntryTemplates(entries []traffic.Entry, thirdParty func(url string) bool) []string {
	reqs := make([]Request, len(entries))
	for i, en := range entries {
		reqs[i] = Request{Method: en.Method, URL: en.URL}
		if in := en.Initiator; in != nil {
			for _, f := range in.Stack {
				reqs[i].Stack = append(reqs[i].Stack, Frame{URL: f.URL, Func: f.Func, Line: f.Line, Col: f.Col})
			}
		}
	}
	o := Options{ThirdParty: thirdParty}
	o.defaults()
	return endpointTemplates(reqs, o)
}
