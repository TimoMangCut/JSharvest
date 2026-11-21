package roles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/mdsafe"
)

// What each class means for a tester, in the order of the report.
var classText = map[string]string{
	LowerOK:        "a role below the one it belongs to uses it with success: test it as the lower role, it may be a missing check",
	ClientGated:    "the role below has it in its code and was not stopped by the server, only by its UI: replay it with that role's session",
	Inconsistent:   "a lower role uses it while a higher one is refused: the checks disagree",
	DeniedBelow:    "the server refused the role below: replay with other values (ids, parameters)",
	HigherOnly:     "the role below never met it where it looked: replay it with that role's session",
	ServerGated:    "the server gave this script to the higher role only",
	ShapeDiffers:   "a higher role sends parameters the lower one does not: try them as the lower role",
	ContentDiffers: "the server renders this script by role: read what changes (flags, config)",
	NotCovered:     "the role below did not go where it is: crawl it further before concluding",
	Unreached:      "in code, used by no role: trigger it by hand",
	Same:           "the same for every role",
}

// Write saves diff.json and diff.md in the host's directory, readable by
// the owner only: they quote URLs of logged-in sessions.
func (r *Report) Write(root string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "diff.json"), append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "diff.md"), []byte(r.Markdown()), 0o600)
}

// Markdown is the report for a person.
func (r *Report) Markdown() string {
	var b strings.Builder
	var safeRoles []string
	for _, role := range r.Roles {
		safeRoles = append(safeRoles, mdsafe.InlineText(role))
	}
	fmt.Fprintf(&b, "# Roles of %s: %s\n\n", mdsafe.InlineText(r.Host), strings.Join(safeRoles, " < "))
	fmt.Fprintf(&b, "Generated %s. Each line: the item, its class, and the state of each role (lowest first).\n\n", r.Generated.Format("2006-01-02 15:04 UTC"))
	if len(r.Warnings) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "- %s\n", mdsafe.InlineText(w))
		}
		b.WriteString("\n")
	}
	for _, layer := range []string{"endpoint", "feature", "page", "script"} {
		var lines []string
		last := ""
		for _, it := range r.Items {
			if it.Layer != layer {
				continue
			}
			if it.Class != last {
				lines = append(lines, fmt.Sprintf("\n**%s**: %s\n", mdsafe.InlineText(it.Class), classText[it.Class]))
				last = it.Class
			}
			var st []string
			for _, role := range r.Roles {
				st = append(st, fmt.Sprintf("%s=%s", mdsafe.InlineText(role), mdsafe.InlineText(string(it.States[role]))))
			}
			extra := ""
			if len(it.Also) > 0 {
				var also []string
				for _, a := range it.Also {
					also = append(also, mdsafe.InlineText(a))
				}
				extra = " (also " + strings.Join(also, ", ") + ")"
			}
			if e := it.Evidence[it.Lowest]; e != nil && e.Label != "" {
				extra += fmt.Sprintf(" — %q", mdsafe.InlineText(e.Label))
			}
			lines = append(lines, fmt.Sprintf("- %s %s%s", mdsafe.InlineCode(it.Key), strings.Join(st, " "), extra))
		}
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %ss\n", strings.ToUpper(layer[:1])+layer[1:])
		b.WriteString(strings.Join(lines, "\n"))
		b.WriteString("\n\n")
	}
	return b.String()
}

// MaskTokens replaces the path segments of a URL or path that read as
// tokens, hashes or emails (a reset link, a signed file URL) with their
// placeholder: the redactor masks credentials by name, and these have none.
func MaskTokens(s string) string {
	pathPart, rest := s, ""
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		pathPart, rest = s[:i], s[i:]
	}
	segs := strings.Split(pathPart, "/")
	for i, seg := range segs {
		switch p := flow.Segment(seg); p {
		case "{token}", "{hash}", "{email}":
			segs[i] = p
		}
	}
	return strings.Join(segs, "/") + rest
}
