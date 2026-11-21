package replay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/mdsafe"
)

// Write saves bola.json and bola.md in dir (0600, the directory 0700):
// authz.json and authz.md of the vertical run stay as they are. The trial
// files (trials/bola.*.http) hold a peer's live credentials; the report names
// endpoints, ids and the evidence's paths (its values as REDACTED_<hash>
// unless the run had -reveal).
func (r *BolaReport) Write(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, "trials"), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bola.json"), append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "bola.md"), []byte(r.Markdown()), 0o600)
}

func (r *BolaReport) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Horizontal authorization trials: %s\n\nPeers: %s and %s (%s). Requests sent: %d.",
		mdsafe.InlineText(r.Host), mdsafe.InlineText(r.Peers[0]), mdsafe.InlineText(r.Peers[1]), mdsafe.InlineText(string(r.Relation)), r.Sent)
	if r.Redacted {
		b.WriteString(" The evidence's values are masked (REDACTED_<hash>: the same value, the same mask).")
	}
	b.WriteString("\n")
	if r.Stopped != "" {
		fmt.Fprintf(&b, "\n**The run stopped:** %s. Items after it were not tried.\n", mdsafe.InlineText(r.Stopped))
	}
	for _, h := range sortedKeys(r.HostsBlocked) {
		fmt.Fprintf(&b, "\n**Host given up:** %s: %s.\n", mdsafe.InlineText(h), mdsafe.InlineText(r.HostsBlocked[h]))
	}
	for _, k := range sortedKeys(r.StoppedEndpoints) {
		fmt.Fprintf(&b, "\n**Endpoint stopped:** %s: %s.\n", mdsafe.InlineCode(k), mdsafe.InlineText(r.StoppedEndpoints[k]))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\n- %s", mdsafe.InlineText(n))
	}
	items := append([]PeerItem(nil), r.Items...)
	sort.SliceStable(items, func(i, j int) bool { return verdictRank[items[i].Verdict] < verdictRank[items[j].Verdict] })
	b.WriteString("\n\n| Verdict | Endpoint | Direction | Mode | Trial | Control | Evidence | Why |\n|---|---|---|---|---|---|---|---|\n")
	for _, it := range items {
		trial, ctl := "—", "—"
		if it.Trial != nil && it.Trial.Status != 0 {
			trial = fmt.Sprintf("%d, %d B", it.Trial.Status, it.Trial.Size)
		}
		if it.Control != nil {
			ctl = fmt.Sprintf("%d, %d B", it.Control.Status, it.Control.Size)
		}
		var ev []string
		for _, e := range it.Evidence {
			s := e.Path
			if e.Short {
				s += " (short)"
			}
			if !r.Redacted {
				s += " = " + e.Value
			}
			ev = append(ev, s)
		}
		why := it.Reason
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			mdsafe.TableText(string(it.Verdict)),
			mdsafe.TableCode(it.Key),
			mdsafe.TableText(it.Direction),
			mdsafe.TableText(string(it.Mode)),
			mdsafe.TableText(trial),
			mdsafe.TableText(ctl),
			mdsafe.TableText(strings.Join(ev, ", ")),
			mdsafe.TableText(why))
	}
	b.WriteString("\nVerdicts: bypass, B read what only A had (a value of A's answer, found in B's: not echoed, not B's own, not shown to B or a visitor before), and, with -relation same-org, the object is private (-private, a private flag, an owner that is A); unauthenticated, a request with no identity got it too; shared, same-org with nothing private about it; enforced, refused or nothing of A's in the answer (B's session still lives); enforced-parent, refused where the request has two ids or more: only the parent level was tried (-substitute); needs-review, a success with another answer or a blind write; replay_broken, A's own request no longer answers as recorded; unclear, nothing to conclude (a dead session, a control that failed, an id that names nothing answered with data); skipped, not sent. The trial files (authz/trials/bola.*.http) hold the peers' live credentials.\n")
	return b.String()
}
