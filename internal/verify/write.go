package verify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DraftsIndex is drafts/index.json: every draft, with its file or why it
// has none.
type DraftsIndex struct {
	Note   string         `json:"note"`
	Tiers  map[string]int `json:"tiers"`
	Files  int            `json:"files"`
	Drafts []IndexEntry   `json:"drafts"`
}

type IndexEntry struct {
	Draft
	File    string `json:"file,omitempty"`
	Omitted string `json:"omitted,omitempty"`
}

// indexName marks a drafts directory jsharvest wrote: only such a one is
// replaced.
const indexName = "index.json"

var slugRe = regexp.MustCompile(`[^A-Za-z0-9]+`)

// WriteDraftsFull writes the drafts as raw requests (0600, a 0700 directory):
// one file a draft that has one URL (its candidates' first when it has
// several), each read back with http.ReadRequest. A document's line, bare
// string, or source-only endpoint is left out unless the corresponding
// include flag is set, or a verification found it alive (alive, by method
// path). A third party's is left out.
func WriteDraftsFull(dir string, drafts []Draft, includeDocs, includeStrings, includeSourceOnly bool, alive map[string]string) (DraftsIndex, error) {
	idx := DraftsIndex{Tiers: map[string]int{},
		Note: "drafts of the catalog's endpoints with sample values (jsharvest export -drafts / verify): unverified unless verify says so; review before sending"}
	if _, err := os.Stat(dir); err == nil {
		if _, err := os.Stat(filepath.Join(dir, indexName)); err != nil {
			return idx, fmt.Errorf("%s exists and is not jsharvest's drafts: not replaced", dir)
		}
		if err := os.RemoveAll(dir); err != nil {
			return idx, err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return idx, err
	}
	for _, d := range drafts {
		e := IndexEntry{Draft: d}
		target := d.URL
		if u := alive[d.Method+" "+d.Path]; target == "" && u != "" {
			target = u // the candidate verify found the route at (POL-23-3)
		}
		if target == "" && len(d.Candidates) > 0 {
			target = d.Candidates[0]
		}
		switch {
		case d.ThirdParty:
			e.Omitted = "third party"
		case d.SourceOnly && !includeSourceOnly && alive[d.Method+" "+d.Path] == "":
			e.Omitted = "tree-shaken sourcemap endpoint (-include-source-only)"
		case d.Confidence == "string" && d.Method == "" && !includeStrings && alive[d.Method+" "+d.Path] == "":
			e.Omitted = "bare string (-include-strings)"
		case d.Confidence == "doc" && !includeDocs && alive[d.Method+" "+d.Path] == "":
			e.Omitted = "a document's line, not verified (-include-docs)"
		case target == "":
			e.Omitted = "no URL: " + d.Why
		}
		if e.Omitted == "" {
			raw, err := d.Raw(target)
			if err == nil {
				_, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
			}
			if err != nil {
				e.Omitted = "does not read as a request: " + err.Error()
			} else {
				method := d.Method
				if method == "" {
					method = "GET"
				}
				slug := strings.Trim(slugRe.ReplaceAllString(d.Path, "-"), "-")
				if len(slug) > 60 {
					slug = slug[:60]
				}
				e.File = fmt.Sprintf("%s-%s-%s.http", d.ID, strings.ToLower(method), slug)
				if err := os.WriteFile(filepath.Join(dir, e.File), raw, 0o600); err != nil {
					return idx, err
				}
				idx.Files++
				idx.Tiers[d.Tier]++
			}
		}
		idx.Drafts = append(idx.Drafts, e)
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return idx, err
	}
	return idx, os.WriteFile(filepath.Join(dir, indexName), append(b, '\n'), 0o600)
}
