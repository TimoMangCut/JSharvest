package replay

import (
	"fmt"
	"sort"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/htmlscan"
)

// The block kinds are detect's (round 25J: one classifier for the Sender,
// the HTTP engine and the browser frontier).
type (
	BlockKind = detect.BlockKind
	Block     = detect.Block
)

const (
	BlockRequest   = detect.BlockRequest
	BlockClient    = detect.BlockClient
	BlockSignature = detect.BlockSignature
	BlockChallenge = detect.BlockChallenge
	BlockRate      = detect.BlockRate
)

// ClassifyBlock says whether an answer is a vendor's block, and what kind;
// nil when it is the application's own (its 403 included). It reads the
// title of an HTML answer for detect.Classify.
func ClassifyBlock(status int, hdr map[string]string, bodyHead []byte) *Block {
	var title string
	if len(bodyHead) > 0 && looksHTML(hdr["content-type"], bodyHead) {
		title = htmlscan.Scan(bodyHead, "http://localhost/").Title
	}
	return detect.Classify(detect.Doc{Status: int64(status), Headers: hdr, Title: title, Body: string(bodyHead)})
}

// blockOf is an answer's block: the one the Sender saw, or one read from
// the answer itself (an Answer made by hand, in a test or a dry run).
func blockOf(a Answer) *Block {
	if a.Block != nil {
		return a.Block
	}
	if a.Err != "" || a.Status == 0 {
		return nil
	}
	return ClassifyBlock(a.Status, a.Header, head(a.Body, 64<<10))
}

// OnBlock values: what a run does when a vendor's block answers.
const (
	// OnBlockHost (the default): the request's verdict says blocked; a
	// control request asks whether the host still answers; when it does
	// not, the host is given up (the run goes on with the others).
	OnBlockHost = "host"
	// OnBlockSkip: the request's verdict says blocked, nothing else; no
	// control request, no host given up.
	OnBlockSkip = "skip"
	// OnBlockStop: the first block stops the run (rate answers too).
	OnBlockStop = "stop"
)

// ParseOnBlock checks an -on-block value.
func ParseOnBlock(v string) (string, error) {
	switch v {
	case "", OnBlockHost:
		return OnBlockHost, nil
	case OnBlockSkip, OnBlockStop:
		return v, nil
	}
	return "", fmt.Errorf("-on-block: %q is not host, skip or stop", v)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
