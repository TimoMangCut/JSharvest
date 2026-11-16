package guard

import (
	"testing"

	"github.com/chromedp/cdproto/target"
)

// In attach mode a request passes only when its frame is, for sure, the
// main frame of a tab that is not ours and was not opened from ours.
func TestOtherTab(t *testing.T) {
	g := &Guard{tabID: "T", ours: map[target.ID]bool{"T": true}, pages: map[target.ID]target.Info{
		"T": {TargetID: "T", Type: "page"},
		"B": {TargetID: "B", Type: "page"},                   // a tab of a -urls batch: no opener
		"O": {TargetID: "O", Type: "page"},                   // the user's own tab
		"P": {TargetID: "P", Type: "page", OpenerID: "T"},    // a popup of ours
		"Q": {TargetID: "Q", Type: "page", OpenerID: "P"},    // opened by our popup
		"R": {TargetID: "R", Type: "page", OpenerID: "O"},    // opened by the user's tab
		"X": {TargetID: "X", Type: "page", OpenerID: "gone"}, // opener no longer known
	}}
	for frame, want := range map[string]bool{
		"O": true, "R": true, "B": false,
		"T": false, "P": false, "Q": false, "X": false,
		"sw-or-worker-target": false, // not a known page: guarded
		"":                    false,
	} {
		if frame == "B" {
			// Until the batch registers it, the tool's own tab looks like the
			// user's (NEW-BUG-01).
			if !g.otherTab(frame) {
				t.Fatal("unregistered batch tab: want it taken for another tab")
			}
			g.AddTab("B")
		}
		if got := g.otherTab(frame); got != want {
			t.Errorf("otherTab(%q) = %v, want %v", frame, got, want)
		}
	}
}
