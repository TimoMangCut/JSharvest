package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/mdsafe"
)

// Line is a line of changes.jsonl.
type Line struct {
	At       time.Time `json:"at"`
	Snapshot string    `json:"snapshot"`
	Change
}

// Write appends the changes to changes.jsonl and writes latest.md.
func (r *Result) Write(root, target string) error {
	dir := filepath.Join(root, "monitor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "changes.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, c := range r.Changes {
		enc.Encode(Line{At: r.Snapshot.Taken, Snapshot: r.Snapshot.ID, Change: c})
	}
	if err := f.Close(); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "latest.md"), []byte(r.Markdown(target)))
}

func (r *Result) Markdown(target string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Changes of %s\n\nSnapshot %s.", mdsafe.InlineCode(target), mdsafe.InlineCode(r.Snapshot.ID))
	for _, rs := range r.Snapshot.Roles {
		state := "compares with its baseline"
		if !rs.Comparable {
			state = "not comparable: " + mdsafe.InlineText(rs.Why)
		}
		fmt.Fprintf(&b, "\n- %s: %d run(s), %s", mdsafe.InlineCode(rs.Role), len(rs.Runs), state)
	}
	for _, role := range r.Baseline {
		fmt.Fprintf(&b, "\n- %s: first runs, the baseline", mdsafe.InlineCode(role))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\n\n> %s", mdsafe.InlineText(n))
	}
	if len(r.Changes) == 0 {
		b.WriteString("\n\nNo change.\n")
		return b.String()
	}
	b.WriteString("\n\n| Severity | Change | Endpoint, parameter or script | Roles | Before | After | Why |\n|---|---|---|---|---|---|---|\n")
	for _, c := range r.Changes {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			mdsafe.TableText(string(c.Severity)),
			mdsafe.TableText(string(c.Kind)),
			mdsafe.TableCode(c.Key),
			mdsafe.TableText(strings.Join(c.Roles, ", ")),
			mdsafe.TableText(c.Before),
			mdsafe.TableText(c.After),
			mdsafe.TableText(c.Reason))
	}
	return b.String()
}
