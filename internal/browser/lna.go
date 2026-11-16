package browser

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// lnaNames are the permission descriptors of Chrome's Local Network
// Access (a public page reaching a more private address): the one the
// permission has had since it was a prompt, the one of newer Chrome, and
// the loopback one (PermissionTypeLoopbackNetwork) that newer Chrome splits
// out of it.
// Chrome does not know both; each is set, and one that is refused is
// only a debug line.
var lnaNames = []string{"local-network-access", "local-network", "loopback-network"}

// LNACommands are the Browser.setPermission calls that deny Local Network
// Access, for one browser context ("" is the default one). No origin is
// passed: the denial holds for every origin.
func LNACommands(id cdp.BrowserContextID) []browser.SetPermissionParams {
	out := make([]browser.SetPermissionParams, 0, len(lnaNames))
	for _, n := range lnaNames {
		out = append(out, browser.SetPermissionParams{
			Permission: &browser.PermissionDescriptor{Name: n}, Setting: browser.PermissionSettingDenied, BrowserContextID: id,
		})
	}
	return out
}

// LNAResult is what denying did.
type LNAResult struct {
	Applied int      // names Chrome accepted
	Names   []string // which
	Errors  []string // "name: error" of the others
}

// Warning is the line for run.json when no name was accepted (a Chrome
// that knows neither): "" when at least one was, so the protection holds.
func (r LNAResult) Warning() string {
	if r.Applied > 0 {
		return ""
	}
	return "Local Network Access could not be denied (Chrome refused every permission name: " + strings.Join(r.Errors, "; ") + "); layer 2 against a public page reaching the internal network is off"
}

// applyLNA sends the commands through call and tallies the answers.
func applyLNA(cmds []browser.SetPermissionParams, call func(browser.SetPermissionParams) error) LNAResult {
	var res LNAResult
	for _, c := range cmds {
		if err := call(c); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", c.Permission.Name, err))
			slog.Debug("local network access: permission not set", "name", c.Permission.Name, "err", err)
			continue
		}
		res.Applied++
		res.Names = append(res.Names, c.Permission.Name)
	}
	slog.Debug("local network access: denied", "accepted", res.Names, "refused", len(res.Errors))
	return res
}

type lnaKey struct{}

// DenyLocalNetwork denies Local Network Access in browser context id of
// tab ("" the default one) and returns tab carrying the result
// (LNAWarning). Not fatal: the run goes on with what it got. In an
// attached Chrome the context may be the user's own, and the denial, which
// names no origin, then holds for their other tabs until
// ResetLocalNetwork.
func DenyLocalNetwork(tab context.Context, id cdp.BrowserContextID) context.Context {
	res := applyLNA(LNACommands(id), func(p browser.SetPermissionParams) error {
		ctx, cancel := context.WithTimeout(tab, 10*time.Second)
		defer cancel()
		_, err := chromedp.CallBrowser(ctx, browser.SetPermission, p)
		return err
	})
	return context.WithValue(tab, lnaKey{}, res)
}

// LNAWarning is the warning DenyLocalNetwork left on tab, "" if none.
func LNAWarning(tab context.Context) string {
	r, ok := tab.Value(lnaKey{}).(LNAResult)
	if !ok {
		return ""
	}
	return r.Warning()
}

// ResetLocalNetwork undoes DenyLocalNetwork (Browser.resetPermissions),
// for an attached Chrome, which is the user's and keeps no permission of
// ours. A launched one dies with the run.
func ResetLocalNetwork(base context.Context, id cdp.BrowserContextID) error {
	ctx, cancel := context.WithTimeout(base, 10*time.Second)
	defer cancel()
	_, err := chromedp.CallBrowser(ctx, browser.ResetPermissions, browser.ResetPermissionsParams{BrowserContextID: id})
	return err
}

// ContextOf is the browser context of a target ("" when it cannot be
// told: the default one is then assumed).
func ContextOf(tab context.Context, id target.ID) cdp.BrowserContextID {
	ctx, cancel := context.WithTimeout(tab, 10*time.Second)
	defer cancel()
	res, err := chromedp.CallBrowser(ctx, target.GetTargetInfo, target.GetTargetInfoParams{TargetID: id})
	if err != nil || res.TargetInfo == nil {
		return ""
	}
	return res.TargetInfo.BrowserContextID
}
