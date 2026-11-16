package browser

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/browser"
)

func TestLNACommands(t *testing.T) {
	cmds := LNACommands("ctx1")
	if len(cmds) != 3 || cmds[0].Permission.Name != "local-network-access" || cmds[1].Permission.Name != "local-network" || cmds[2].Permission.Name != "loopback-network" {
		t.Fatalf("names: %+v", cmds)
	}
	for _, c := range cmds {
		if c.Setting != browser.PermissionSettingDenied || c.Origin != "" || c.EmbeddedOrigin != "" || c.BrowserContextID != "ctx1" {
			t.Errorf("command: %+v", c)
		}
	}
	if LNACommands("")[0].BrowserContextID != "" {
		t.Error("the default context takes no id")
	}
}

func TestApplyLNA(t *testing.T) {
	cmds := LNACommands("")
	// One name accepted: no warning, the other is not an error of the run.
	r := applyLNA(cmds, func(p browser.SetPermissionParams) error {
		if p.Permission.Name == "local-network" {
			return errors.New("unsupported")
		}
		return nil
	})
	if r.Applied != 2 || len(r.Errors) != 1 || r.Warning() != "" || !slices.Equal(r.Names, []string{"local-network-access", "loopback-network"}) {
		t.Errorf("one accepted: %+v %q", r, r.Warning())
	}
	// Neither: a warning that names both.
	r = applyLNA(cmds, func(browser.SetPermissionParams) error { return errors.New("unknown permission") })
	w := r.Warning()
	if r.Applied != 0 || !strings.Contains(w, "local-network-access") || !strings.Contains(w, "local-network:") {
		t.Errorf("none accepted: %+v %q", r, w)
	}
}

func TestLNAWarningOfContext(t *testing.T) {
	if LNAWarning(context.Background()) != "" {
		t.Error("a context that was never denied has no warning")
	}
	bad := context.WithValue(context.Background(), lnaKey{}, applyLNA(LNACommands(""), func(browser.SetPermissionParams) error { return errors.New("x") }))
	if LNAWarning(bad) == "" {
		t.Error("no warning for a total failure")
	}
}
