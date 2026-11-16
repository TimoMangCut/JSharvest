package browser

import (
	"context"
	"log/slog"
	"regexp"
	"runtime"
	"strings"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/uahints"
)

// UA is the User-Agent a launched browser presents (CF-06): a headless
// Chrome's own says HeadlessChrome, in the header and in Sec-CH-UA, which
// every bot manager reads first. A run that must use Chrome (after a login,
// to explore) presents the desktop Chrome it is instead, or the User-Agent
// the login was made with, so that a session tied to it (Cloudflare's
// cf_clearance) holds.
type UA struct {
	String   string
	Metadata *emulation.UserAgentMetadata
}

type uaKey struct{}

// UAOf returns the User-Agent a tab of a launched browser presents, or nil
// (the user's own browser, attached, presents its own).
func UAOf(ctx context.Context) *UA {
	ua, _ := ctx.Value(uaKey{}).(*UA)
	return ua
}

var chromeVersionRe = regexp.MustCompile(`(?:Headless)?Chrome/((\d+)[\d.]*)`)

// cleanUA makes the browser's User-Agent: o.UserAgent if given, else the
// browser's own with HeadlessChrome made Chrome; the client hints to match.
// A headful browser with no -ua presents its own: nil.
func cleanUA(ctx context.Context, o Options) *UA {
	if o.Headful && o.UserAgent == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ver, err := chromedp.CallBrowser(cctx, cdpbrowser.GetVersion, cdp.Empty{})
	if err != nil {
		slog.Debug("browser version", "err", err)
		if o.UserAgent == "" {
			return nil
		}
	}
	ua := o.UserAgent
	if ua == "" {
		ua = strings.Replace(ver.UserAgent, "HeadlessChrome/", "Chrome/", 1)
	}
	full, major := "", ""
	if m := chromeVersionRe.FindStringSubmatch(ver.Product); m != nil {
		full, major = m[1], m[2]
	}
	if m := chromeVersionRe.FindStringSubmatch(ua); m != nil {
		if major != m[2] || full == "" {
			full, major = m[1], m[2] // the given User-Agent's version is the one to match
		}
	}
	if major == "" {
		return &UA{String: ua}
	}
	// The brands are uahints's, as the HTTP engine and the Sender send
	// them (round 25K): the full versions are Chrome's, the GREASE brand's
	// a constant.
	brands := func(v func(string) string) []*emulation.UserAgentBrandVersion {
		var out []*emulation.UserAgentBrandVersion
		for _, b := range uahints.Brands(major) {
			ver := full
			if b[0] == "Not)A;Brand" {
				ver = b[1] + ".0.0.0"
			}
			out = append(out, &emulation.UserAgentBrandVersion{Brand: b[0], Version: v(ver)})
		}
		return out
	}
	md := &emulation.UserAgentMetadata{
		Brands:          brands(func(s string) string { return strings.SplitN(s, ".", 2)[0] }),
		FullVersionList: brands(func(s string) string { return s }),
		Platform:        platform(ua), Architecture: arch(), Bitness: "64", Mobile: false,
	}
	return &UA{String: ua, Metadata: md}
}

func platform(ua string) string { return uahints.Platform(ua) }

func arch() string {
	if strings.HasPrefix(runtime.GOARCH, "arm") {
		return "arm"
	}
	return "x86"
}

// networkUAOverride is Network.setUserAgentOverride, which workers take
// (Emulation is a page's); cdproto keeps only Emulation's.
var networkUAOverride = cdp.Command[emulation.SetUserAgentOverrideParams, cdp.Empty]{Method: "Network.setUserAgentOverride"}

// Apply sets the User-Agent and its client hints on one session: a page
// through Emulation (navigator.userAgent too), a worker through Network.
// ctx is the session's.
func (ua *UA) Apply(ctx context.Context, page bool) error {
	if ua == nil {
		return nil
	}
	p := emulation.SetUserAgentOverrideParams{UserAgent: ua.String, AcceptLanguage: "en-US,en", UserAgentMetadata: ua.Metadata}
	if ua.Metadata != nil {
		p.Platform = map[string]string{"Linux": "Linux x86_64", "Windows": "Win32", "macOS": "MacIntel"}[ua.Metadata.Platform]
	}
	cmd := networkUAOverride
	if page {
		cmd = emulation.SetUserAgentOverride
	}
	_, err := chromedp.Call(ctx, cmd, p)
	return err
}
