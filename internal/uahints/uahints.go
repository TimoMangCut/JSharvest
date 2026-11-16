// Package uahints is how every client of a run presents itself as the same
// browser (round 25K, N1 of docs/research-2026-11-13-bot-transport.md): a
// User-Agent of the Chrome installed (its major version, as Chrome's
// reduced UA gives it), and the client hints a Chrome with that User-Agent
// sends (Sec-CH-UA, -Mobile, -Platform). The HTTP engine and the replay
// Sender take them; the browser package takes the platform and brands, so
// the three agree.
package uahints

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	chromeRe  = regexp.MustCompile(`\bChrome/(\d+)\.`)
	versionRe = regexp.MustCompile(`\b(\d{2,4})\.\d+\.\d+\.\d+\b`)
	// otherBrandRe are Chromium browsers whose brands are not Chrome's.
	otherBrandRe = regexp.MustCompile(`\b(Edg|EdgA|OPR|YaBrowser|SamsungBrowser|Vivaldi|Brave)/`)
)

// ChromeMajor is a Chrome User-Agent's major version, "" for another
// browser's (Firefox, Safari, Edge…) or a library's.
func ChromeMajor(ua string) string {
	if !strings.HasPrefix(ua, "Mozilla/5.0") || strings.Contains(ua, "HeadlessChrome") || otherBrandRe.MatchString(ua) {
		return ""
	}
	if m := chromeRe.FindStringSubmatch(ua); m != nil {
		return m[1]
	}
	return ""
}

// Platform is the Sec-CH-UA-Platform value of a User-Agent (unquoted):
// the system it names, else this machine's.
func Platform(ua string) string {
	switch {
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Mac OS X"):
		return "macOS"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "CrOS"):
		return "Chrome OS"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	}
	switch runtime.GOOS {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	}
	return "Linux"
}

// Brands are the Sec-CH-UA brands of a Chrome major version, in the order
// and with the GREASE brand the browser package gives a tab (cleanUA).
func Brands(major string) [][2]string {
	return [][2]string{{"Google Chrome", major}, {"Chromium", major}, {"Not)A;Brand", "24"}}
}

// Hints are the low-entropy client hints a Chrome with this User-Agent
// sends to a secure origin, by lower-case header name; nil for a User-Agent
// that is not Chrome's.
func Hints(ua string) map[string]string {
	major := ChromeMajor(ua)
	if major == "" {
		return nil
	}
	var b []string
	for _, br := range Brands(major) {
		b = append(b, `"`+br[0]+`";v="`+br[1]+`"`)
	}
	mobile := "?0"
	if strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android") {
		mobile = "?1"
	}
	return map[string]string{
		"sec-ch-ua":          strings.Join(b, ", "),
		"sec-ch-ua-mobile":   mobile,
		"sec-ch-ua-platform": `"` + Platform(ua) + `"`,
	}
}

// ChromeUA is the reduced User-Agent of a desktop Chrome of a major
// version on this machine's system.
func ChromeUA(major string) string {
	sys := "X11; Linux x86_64"
	switch runtime.GOOS {
	case "darwin":
		sys = "Macintosh; Intel Mac OS X 10_15_7"
	case "windows":
		sys = "Windows NT 10.0; Win64; x64"
	}
	return "Mozilla/5.0 (" + sys + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + major + ".0.0.0 Safari/537.36"
}

var (
	localMu sync.Mutex
	local   = map[string]string{}
)

// LocalChromeMajor is the major version of the Chrome at path, or of the
// first Chrome on PATH when path is "": what `chrome --version` prints,
// asked once a process. "" when none answers.
func LocalChromeMajor(path string) string {
	localMu.Lock()
	defer localMu.Unlock()
	if v, ok := local[path]; ok {
		return v
	}
	cands := []string{path}
	if path == "" {
		cands = []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"}
	}
	v := ""
	for _, c := range cands {
		bin, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, bin, "--version").Output()
		cancel()
		if err != nil {
			continue
		}
		if m := versionRe.FindStringSubmatch(string(out)); m != nil {
			v = m[1]
			break
		}
	}
	local[path] = v
	return v
}

// LocalChromeUA is ChromeUA of the Chrome at path (see LocalChromeMajor),
// or fallback when no Chrome answers.
func LocalChromeUA(path, fallback string) string {
	if m := LocalChromeMajor(path); m != "" {
		return ChromeUA(m)
	}
	return fallback
}
