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

// verdictRank orders authz.md: the findings first.
var verdictRank = map[Verdict]int{Unauthenticated: 0, Bypass: 1, Shared: 2, Likely: 3, NeedsReview: 4, ReplayBroken: 5, Unclear: 6, EnforcedParent: 7, Enforced: 8, Skipped: 9, Blocked: 10}

// Write saves authz.json and authz.md in dir (0600): the trial files hold
// live credentials of the lower roles, the report names only endpoints.
func (r *AuthzReport) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "authz.json"), append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "authz.md"), []byte(r.Markdown()), 0o600)
}

func (r *AuthzReport) Markdown() string {
	var b strings.Builder
	var safeRoles []string
	for _, role := range r.Roles {
		safeRoles = append(safeRoles, mdsafe.InlineText(role))
	}
	fmt.Fprintf(&b, "# Authorization trials: %s\n\nRoles, lowest first: %s. Requests sent: %d.\n", mdsafe.InlineText(r.Host), strings.Join(safeRoles, " < "), r.Sent)
	if r.Stopped != "" {
		fmt.Fprintf(&b, "\n**The run stopped:** %s. Items after it were not tried.\n", mdsafe.InlineText(r.Stopped))
	}
	for _, h := range sortedKeys(r.HostsBlocked) {
		fmt.Fprintf(&b, "\n**Host given up:** %s: %s. Its items after that were not tried.\n", mdsafe.InlineText(h), mdsafe.InlineText(r.HostsBlocked[h]))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\n- %s", mdsafe.InlineText(n))
	}
	type row struct {
		it AuthzItem
		t  Trial
	}
	var rows []row
	for _, it := range r.Items {
		for _, t := range it.Trials {
			rows = append(rows, row{it, t})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return verdictRank[rows[i].t.Verdict] < verdictRank[rows[j].t.Verdict] })
	b.WriteString("\n\n| Verdict | Endpoint | Diff class | As | Sample | Trial | Control | Why |\n|---|---|---|---|---|---|---|---|\n")
	for _, x := range rows {
		ctl := "—"
		if x.it.Control != nil {
			ctl = fmt.Sprintf("%d, %d B", x.it.Control.Status, x.it.Control.Size)
		}
		trial := "—"
		if x.t.Status != 0 {
			trial = fmt.Sprintf("%d, %d B", x.t.Status, x.t.Size)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			mdsafe.TableText(string(x.t.Verdict)),
			mdsafe.TableCode(x.it.Key),
			mdsafe.TableText(x.it.Class),
			mdsafe.TableText(x.t.Role),
			mdsafe.TableText(x.it.Sample),
			mdsafe.TableText(trial),
			mdsafe.TableText(ctl),
			mdsafe.TableText(x.t.Reason))
	}
	b.WriteString("\nVerdicts: bypass, the lower role gets what the higher one gets; unauthenticated, so does a request with no identity; likely, nearly; needs-review, a success with another answer (filtered, its own object); enforced, refused; unclear, nothing to conclude (a control failed, a CSRF token went stale, a dead session…); skipped, not sent. The trial files (authz/trials/) hold the lower roles' live credentials.\n")
	return b.String()
}
