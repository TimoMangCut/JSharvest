package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// Step is one action of a login script:
//
//	{"do": "goto", "url": "https://app/login"}
//	{"do": "type", "selector": "#email", "text": "${APP_USER}"}
//	{"do": "click", "selector": "button[type=submit]"}
//	{"do": "wait", "selector": "#dashboard"}   or "url": "/dashboard"  or "ms": 1000
//
// ${NAME} in a text or a URL is the environment variable NAME, so that no
// password needs to be in the file.
type Step struct {
	Do       string `json:"do"`
	URL      string `json:"url,omitempty"`
	Selector string `json:"selector,omitempty"`
	Text     string `json:"text,omitempty"`
	MS       int    `json:"ms,omitempty"`
}

// ReadSteps reads a login script, and checks that every variable it names
// is set.
func ReadSteps(path string) ([]Step, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var steps []Step
	if err := json.Unmarshal(b, &steps); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, s := range steps {
		switch s.Do {
		case "goto", "type", "click", "wait":
		default:
			return nil, fmt.Errorf("%s: step %d: unknown %q (goto, type, click or wait)", path, i+1, s.Do)
		}
		for _, v := range vars(s.Text + s.URL) {
			if _, ok := os.LookupEnv(v); !ok {
				return nil, fmt.Errorf("%s: step %d needs the environment variable %s", path, i+1, v)
			}
		}
	}
	return steps, nil
}

var varRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func vars(s string) []string {
	var out []string
	for _, m := range varRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func expand(s string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string { return os.Getenv(m[2 : len(m)-1]) })
}

// Run performs a login script in a tab. Each step has stepTimeout.
func Run(tab context.Context, steps []Step, stepTimeout time.Duration) error {
	for i, s := range steps {
		ctx, cancel := context.WithTimeout(tab, stepTimeout)
		var err error
		switch s.Do {
		case "goto":
			err = chromedp.Do(ctx, chromedp.Navigate(expand(s.URL)))
		case "type":
			_, err = chromedp.Run(ctx, chromedp.SendKeys(chromedp.CSS(s.Selector), expand(s.Text)))
		case "click":
			_, err = chromedp.Run(ctx, chromedp.Click(chromedp.CSS(s.Selector)))
		case "wait":
			err = wait(ctx, s)
		}
		cancel()
		if err != nil {
			return fmt.Errorf("login step %d (%s %s%s): %w", i+1, s.Do, s.Selector, s.URL, err)
		}
	}
	return nil
}

func wait(ctx context.Context, s Step) error {
	switch {
	case s.Selector != "":
		_, err := chromedp.Run(ctx, chromedp.WaitVisible(chromedp.CSS(s.Selector)))
		return err
	case s.URL != "":
		want := expand(s.URL)
		for {
			loc, err := chromedp.Run(ctx, chromedp.Location())
			if err == nil && strings.Contains(loc, want) {
				return nil
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("the page did not reach %q", want)
			case <-time.After(200 * time.Millisecond):
			}
		}
	default:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(s.MS) * time.Millisecond):
			return nil
		}
	}
}
