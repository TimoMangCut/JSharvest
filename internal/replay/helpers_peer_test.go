package replay

import (
	"regexp"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func regexpMust(s string) *regexp.Regexp { return regexp.MustCompile(s) }

func entryFor(method, url, body string) traffic.Entry {
	e := traffic.Entry{Method: method, URL: url}
	if body != "" {
		e.Headers = map[string]string{"content-type": "application/json"}
		e.Body = traffic.Body{Body: body}
	}
	return e
}
