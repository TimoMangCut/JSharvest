package endpoints

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// archiveFile is the path of the archive catalog a role's directory is
// enriched from; "" for the archive's own directory.
func archiveFile(dir string) string {
	if filepath.Base(dir) == "archive" {
		return ""
	}
	hostDir := filepath.Dir(dir)
	return filepath.Join(filepath.Dir(hostDir), scope.TargetHost(filepath.Base(hostDir)), "archive", File)
}

// archiveCatalog is the archive's catalog of a role's directory: the
// host's archive/endpoints.jsonl (one per host, whatever port the role's
// crawl was on). Nothing for the archive's own directory.
func archiveCatalog(dir string) []Endpoint {
	p := archiveFile(dir)
	if p == "" {
		return nil
	}
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Endpoint
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var e Endpoint
		if json.Unmarshal(sc.Bytes(), &e) == nil && !e.ThirdParty && e.Method != "" && (e.Confidence == "code" || e.Confidence == "spec") {
			out = append(out, e)
		}
	}
	return out
}

// EnrichFromArchive fills what a line of today's catalog lacks (its
// method, query, body, headers, parameters) from the archive's catalog,
// when an old script calls the same path (PIP-01): a document names
// /api/v1/conversations/{}/messages/send, the old bundle's code sends it
// with its body. The path must be the same (a client's {} base aside), the
// host the same or unknown, the methods the same or one unknown. Bases are
// never touched (archivecheck reads them). What was filled is said
// (enriched_from: archive); a line only a document named is now code.
func EnrichFromArchive(eps []Endpoint, archived []Endpoint) []Endpoint {
	if len(archived) == 0 {
		return eps
	}
	trim := func(p string) string { return strings.TrimPrefix(p, placeholder) }
	by := map[string][]int{}
	for i, a := range archived {
		by[trim(a.Path)] = append(by[trim(a.Path)], i)
	}
	for i := range eps {
		e := &eps[i]
		if e.ThirdParty {
			continue
		}
		var src *Endpoint
		for _, j := range by[trim(e.Path)] {
			a := &archived[j]
			if (e.Host != "" && a.Host != "" && !strings.EqualFold(e.Host, a.Host)) || (e.Method != "" && e.Method != a.Method) {
				continue
			}
			if src != nil && src.Method != a.Method {
				src = nil // two methods for a line with none: neither
				break
			}
			src = a
		}
		if src == nil {
			continue
		}
		filled := false
		if e.Method == "" {
			e.Method, filled = src.Method, true
		}
		for _, f := range []struct {
			to   *[]string
			from []string
		}{{&e.Query, src.Query}, {&e.Body, src.Body}, {&e.Headers, src.Headers}, {&e.Auth, src.Auth}} {
			for _, v := range f.from {
				if !slices.Contains(*f.to, v) {
					*f.to = append(*f.to, v)
					filled = true
				}
			}
		}
		if len(src.Params) > 0 {
			before := len(e.Params)
			e.Params = jsapi.MergeParams(e.Params, src.Params)
			filled = filled || len(e.Params) != before
		}
		if !filled {
			continue
		}
		slices.Sort(e.Query)
		slices.Sort(e.Body)
		slices.Sort(e.Headers)
		slices.Sort(e.Auth)
		if !slices.Contains(e.Enriched, "archive") {
			e.Enriched = append(e.Enriched, "archive")
		}
		if rank(e.Confidence) < rank(src.Confidence) && rank(e.Confidence) < rank("code") {
			e.Confidence = "code"
		}
	}
	return eps
}

// rank orders the confidences: confirmed > spec > code > string > doc.
func rank(c string) int {
	return map[string]int{"doc": 1, "string": 2, "code": 3, "spec": 4, "confirmed": 5}[c]
}
