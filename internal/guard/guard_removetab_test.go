package guard

import (
	"testing"

	"github.com/chromedp/cdproto/target"
)

func TestRemoveTab(t *testing.T) {
	g := &Guard{ours: map[target.ID]bool{}}
	g.AddTab("t1")
	if !g.ours["t1"] {
		t.Fatal("AddTab")
	}
	g.RemoveTab("t1")
	g.RemoveTab("nope")
	if g.ours["t1"] {
		t.Error("RemoveTab kept the tab")
	}
}
