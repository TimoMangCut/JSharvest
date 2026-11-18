package httpcrawl

import (
	"crypto/sha256"
	"net/url"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// skeletonController wraps frontier.Skeleton for the HTTP crawler while
// computing inline <script> semantic signatures directly on HTML page scans.
type skeletonController struct {
	skel *frontier.Skeleton
}

func newSkeletonController() *skeletonController {
	return &skeletonController{skel: frontier.NewSkeleton()}
}

func (sc *skeletonController) skeletonKey(rawURL string, register bool) (key string, dynamic bool) {
	if sc == nil || sc.skel == nil {
		return "", false
	}
	return sc.skel.Key(rawURL, register)
}

func (sc *skeletonController) shouldSkip(rawURL string) bool {
	if sc == nil || sc.skel == nil {
		return false
	}
	return sc.skel.ShouldSkip(rawURL)
}

func (sc *skeletonController) observe(cr *crawler, pageURL string, status int, admittedJobs []job, inlineSigs [][32]byte, links []frontier.Found, b *bucket) bool {
	if sc == nil || sc.skel == nil {
		return false
	}
	var newScripts []string
	if len(admittedJobs) > 0 {
		newScripts = make([]string, 0, len(admittedJobs))
		for _, j := range admittedJobs {
			ck := store.CanonicalKey(j.url)
			if ck == "" {
				ck = j.url
			}
			newScripts = append(newScripts, ck)
		}
	}
	var jsFound, jsOrigins []string
	if b != nil {
		for _, f := range b.found {
			jsFound = append(jsFound, f.f.URL)
		}
		for _, o := range b.origins {
			jsOrigins = append(jsOrigins, o.f.URL)
		}
	}
	var inScope func(string) bool
	if cr != nil {
		inScope = cr.o.InScope
	}
	return sc.skel.Observe(frontier.Observation{
		PageURL:      pageURL,
		Status:       status,
		NewScripts:   newScripts,
		InlineSigs:   inlineSigs,
		JSFoundURLs:  jsFound,
		JSAPIOrigins: jsOrigins,
		Links:        links,
		InScope:      inScope,
	})
}

func (sc *skeletonController) recordAsyncFindings(pageURL string, fs []found, origins []string) {
	if sc == nil || sc.skel == nil || (len(fs) == 0 && len(origins) == 0) {
		return
	}
	foundURLs := make([]string, 0, len(fs))
	for _, x := range fs {
		foundURLs = append(foundURLs, x.f.URL)
	}
	sc.skel.RecordAsync(pageURL, foundURLs, origins)
}

func inlineSemanticSig(cr *crawler, sc *skeletonController, code []byte, pageURL string) ([32]byte, bool) {
	res := cr.extractScript(code, pageURL)
	base, _ := url.Parse(pageURL)
	norm := func(raw string) string {
		if sc != nil && base != nil && (strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")) {
			if u, err := base.Parse(raw); err == nil {
				if sk, _ := sc.skeletonKey(u.String(), false); sk != "" {
					return sk
				}
			}
		}
		return raw
	}
	var parts []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	for _, e := range res.Endpoints {
		if e.Collector {
			continue
		}
		u := e.URL
		if e.Kind == "string" || e.Kind == "navigation" {
			u = norm(u)
		}
		add("ep:" + e.Method + "|" + e.Kind + "|" + norm(e.Base) + "|" + u + "|" + strings.Join(e.Query, ",") + "|" + strings.Join(e.Body, ","))
	}
	for _, b := range res.Bases {
		add("b:" + norm(b))
	}
	for _, pb := range res.PropBases {
		add("pb:" + pb.Name + "=" + norm(pb.Value))
	}
	for _, h := range res.ClientHeaders {
		add("ch:" + strings.ToLower(h.Name) + "=" + h.Value)
	}
	for _, k := range res.Keys {
		add("k:" + k.Name + "=" + k.Value)
	}
	for _, s := range res.Settings {
		add("s:" + s.Name + "=" + norm(s.Value))
	}
	for _, c := range res.Cloud {
		add("cl:" + c)
	}
	for _, op := range res.Operations {
		add("op:" + op)
	}
	for _, r := range res.Routes {
		add("r:" + norm(r))
	}
	for _, p := range res.Paths {
		add("p:" + norm(p))
	}
	if len(parts) == 0 {
		return [32]byte{}, false
	}
	sort.Strings(parts)
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p + "\x00"))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, true
}
