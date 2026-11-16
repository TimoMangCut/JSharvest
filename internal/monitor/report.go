package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	return os.WriteFile(filepath.Join(dir, "latest.md"), []byte(r.Markdown(target)), 0o600)
}

// md quotes text of the target's (an endpoint's path) in Markdown: a code
// span, its backticks out.
func md(s string) string { return "`" + strings.ReplaceAll(s, "`", "'") + "`" }

func (r *Result) Markdown(target string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Changes of %s\n\nSnapshot %s.", md(target), md(r.Snapshot.ID))
	for _, rs := range r.Snapshot.Roles {
		state := "compares with its baseline"
		if !rs.Comparable {
			state = "not comparable: " + rs.Why
		}
		fmt.Fprintf(&b, "\n- %s: %d run(s), %s", md(rs.Role), len(rs.Runs), state)
	}
	for _, role := range r.Baseline {
		fmt.Fprintf(&b, "\n- %s: first runs, the baseline", md(role))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\n\n> %s", strings.ReplaceAll(n, "\n", " "))
	}
	if len(r.Changes) == 0 {
		b.WriteString("\n\nNo change.\n")
		return b.String()
	}
	b.WriteString("\n\n| Severity | Change | Endpoint, parameter or script | Roles | Before | After | Why |\n|---|---|---|---|---|---|---|\n")
	for _, c := range r.Changes {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", c.Severity, c.Kind, md(c.Key), strings.Join(c.Roles, ", "),
			cell(c.Before), cell(c.After), cell(c.Reason))
	}
	return b.String()
}

func cell(s string) string { return strings.NewReplacer("|", "/", "\n", " ").Replace(s) }
