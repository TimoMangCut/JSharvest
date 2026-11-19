package archive

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type uaTally struct {
	browser map[string]int
	engine  map[string]int
}

func (c *uaTally) add(ua string, tags []string) {
	if ua == "" || !strings.HasPrefix(ua, "Mozilla/5.0") || strings.Contains(ua, "HeadlessChrome") || strings.Contains(strings.ToLower(ua), "jsharvest") {
		return
	}
	if slices.Contains(tags, "jsharvest") || slices.Contains(tags, "challenge") {
		return
	}
	if c.browser == nil {
		c.browser = map[string]int{}
		c.engine = map[string]int{}
	}
	if slices.Contains(tags, "http") {
		c.engine[ua]++
	} else {
		c.browser[ua]++
	}
}

func (c *uaTally) merge(o uaTally) {
	if len(o.browser) == 0 && len(o.engine) == 0 {
		return
	}
	if c.browser == nil {
		c.browser = map[string]int{}
		c.engine = map[string]int{}
	}
	for k, v := range o.browser {
		c.browser[k] += v
	}
	for k, v := range o.engine {
		c.engine[k] += v
	}
}

func (c uaTally) best() string {
	most := func(count map[string]int) string {
		best := ""
		for ua, n := range count {
			if n > count[best] || (n == count[best] && ua > best) {
				best = ua
			}
		}
		return best
	}
	if ua := most(c.browser); ua != "" {
		return ua
	}
	return most(c.engine)
}

// CrawlHosts are the hosts the crawls of the target reached (host:port, as
// requests name them), and the address each answered from: the live check
// goes to those only, pinned to their kind of address. The hosts of the
// in-scope base URLs today's code gives its clients (intel.json) count
// too: an API's host is in use, not an old name that may be someone
// else's now, though a crawl without a session sends it nothing.
func CrawlHosts(root string, inScope func(string) bool) (map[string]bool, map[string]string) {
	hosts, recorded, _ := CrawlHostsWithUA(root, "", "", inScope)
	return hosts, recorded
}

// CrawlHostsWithUA scans <root>/<host>/<role> once in a single streaming pass,
// collecting reached hosts, recorded remote IPs, and the observed User-Agent
// (preferring roleDir's browser/engine UA, then targetHostPrefix role dirs, with
// Chrome's real UA always prioritized ahead of the HTTP engine's UA).
func CrawlHostsWithUA(root, targetHostPrefix, roleDir string, inScope func(string) bool) (map[string]bool, map[string]string, string) {
	hosts, recorded := map[string]bool{}, map[string]string{}
	cleanRole := ""
	if roleDir != "" {
		cleanRole = filepath.Clean(roleDir)
	}
	var roleUA, targetUA uaTally

	scanDir := func(dir string, matchTarget, matchRole bool) {
		var in struct {
			Bases []string `json:"bases"`
		}
		if b, err := os.ReadFile(filepath.Join(dir, "intel.json")); err == nil && json.Unmarshal(b, &in) == nil {
			for _, base := range in.Bases {
				if u, err := url.Parse(base); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && inScope(u.Hostname()) {
					hosts[u.Host] = true
				}
			}
		}
		eachLine(filepath.Join(dir, "requests.jsonl"), func(b []byte) {
			var e struct {
				URL      string            `json:"url"`
				Headers  map[string]string `json:"headers"`
				Tags     []string          `json:"tags"`
				Response *struct {
					Status   int    `json:"status"`
					RemoteIP string `json:"remote_ip"`
				} `json:"response"`
			}
			if json.Unmarshal(b, &e) != nil {
				return
			}
			if matchRole {
				roleUA.add(e.Headers["user-agent"], e.Tags)
			} else if matchTarget {
				targetUA.add(e.Headers["user-agent"], e.Tags)
			}
			if e.Response == nil || e.Response.Status == 0 {
				return
			}
			u, err := url.Parse(e.URL)
			if err != nil || !inScope(u.Hostname()) {
				return
			}
			hosts[u.Host] = true
			if e.Response.RemoteIP != "" {
				recorded[u.Hostname()] = e.Response.RemoteIP
			}
		})
	}

	visitedRole := false
	dirs, _ := os.ReadDir(root)
	for _, h := range dirs {
		if !h.IsDir() {
			continue
		}
		hName := h.Name()
		isTargetDir := targetHostPrefix != "" && (hName == targetHostPrefix || strings.HasPrefix(hName, targetHostPrefix+"_"))
		inSc := inScope(hostOnly(hName))
		if !inSc && !isTargetDir {
			continue
		}
		roles, _ := os.ReadDir(filepath.Join(root, hName))
		for _, r := range roles {
			if !r.IsDir() || r.Name() == "archive" {
				continue
			}
			dir := filepath.Join(root, hName, r.Name())
			isRole := cleanRole != "" && filepath.Clean(dir) == cleanRole
			if isRole {
				visitedRole = true
			}
			if inSc {
				scanDir(dir, isTargetDir, isRole)
			} else if isTargetDir || isRole {
				// Out-of-scope dir matching targetHostPrefix/roleDir: scan UA only.
				eachLine(filepath.Join(dir, "requests.jsonl"), func(b []byte) {
					var e struct {
						Headers map[string]string `json:"headers"`
						Tags    []string          `json:"tags"`
					}
					if json.Unmarshal(b, &e) == nil {
						if isRole {
							roleUA.add(e.Headers["user-agent"], e.Tags)
						} else {
							targetUA.add(e.Headers["user-agent"], e.Tags)
						}
					}
				})
			}
		}
	}
	if cleanRole != "" && !visitedRole {
		eachLine(filepath.Join(cleanRole, "requests.jsonl"), func(b []byte) {
			var e struct {
				Headers map[string]string `json:"headers"`
				Tags    []string          `json:"tags"`
			}
			if json.Unmarshal(b, &e) == nil {
				roleUA.add(e.Headers["user-agent"], e.Tags)
			}
		})
	}
	if ua := roleUA.best(); ua != "" {
		return hosts, recorded, ua
	}
	targetUA.merge(roleUA)
	return hosts, recorded, targetUA.best()
}
