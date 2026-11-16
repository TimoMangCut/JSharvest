package archive

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
)

// CrawlHosts are the hosts the crawls of the target reached (host:port, as
// requests name them), and the address each answered from: the live check
// goes to those only, pinned to their kind of address. The hosts of the
// in-scope base URLs today's code gives its clients (intel.json) count
// too: an API's host is in use, not an old name that may be someone
// else's now, though a crawl without a session sends it nothing.
func CrawlHosts(root string, inScope func(string) bool) (map[string]bool, map[string]string) {
	hosts, recorded := map[string]bool{}, map[string]string{}
	dirs, _ := os.ReadDir(root)
	for _, h := range dirs {
		if !h.IsDir() || !inScope(hostOnly(h.Name())) {
			continue
		}
		roles, _ := os.ReadDir(filepath.Join(root, h.Name()))
		for _, r := range roles {
			if !r.IsDir() || r.Name() == "archive" {
				continue
			}
			var in struct {
				Bases []string `json:"bases"`
			}
			if b, err := os.ReadFile(filepath.Join(root, h.Name(), r.Name(), "intel.json")); err == nil && json.Unmarshal(b, &in) == nil {
				for _, base := range in.Bases {
					if u, err := url.Parse(base); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && inScope(u.Hostname()) {
						hosts[u.Host] = true
					}
				}
			}
			eachLine(filepath.Join(root, h.Name(), r.Name(), "requests.jsonl"), func(b []byte) {
				var e struct {
					URL      string `json:"url"`
					Response *struct {
						Status   int    `json:"status"`
						RemoteIP string `json:"remote_ip"`
					} `json:"response"`
				}
				if json.Unmarshal(b, &e) != nil || e.Response == nil || e.Response.Status == 0 {
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
	}
	return hosts, recorded
}
