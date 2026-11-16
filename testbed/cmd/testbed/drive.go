package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
)

// flowTruth is an app's flows.truth.json: the steps a driver performs and
// the requests each must cause.
type flowTruth struct {
	URL     string     `json:"url"`
	PauseMS int        `json:"pause_ms"`
	Steps   []flowStep `json:"steps"`
	Load    []string   `json:"load"`
	Noise   []string   `json:"noise"`
	// Templates the endpoints must be grouped under.
	Templates []struct {
		Method   string `json:"method"`
		Template string `json:"template"`
	} `json:"templates"`
	DependsOn []struct {
		Request string `json:"request"`
		At      string `json:"at"`
		From    string `json:"from"`
		FromAt  string `json:"from_at"`
	} `json:"depends_on"`
}

type flowStep struct {
	Do       string   `json:"do"` // click, type or reload
	Selector string   `json:"selector"`
	Text     string   `json:"text,omitempty"`
	Expect   []string `json:"expect,omitempty"`
	// How, when set, is how each expected request must have been traced
	// (causal): the gate checks the tracing, not only the grouping.
	How string `json:"how,omitempty"`
	// PauseMS, when set, is the wait after this step instead of the file's.
	PauseMS *int `json:"pause_ms,omitempty"`
}

// stepLog is one line of the driver's log: when each step began.
type stepLog struct {
	Step    int       `json:"step"`
	Started time.Time `json:"started"`
}

func readTruthFile(p string) (*flowTruth, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var t flowTruth
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &t, nil
}

// drive performs a truth file's steps in an existing tab of a running
// Chrome, through CDP input events, as Playwright or an AI agent would from
// outside the tool:
//
//	testbed drive -cdp http://127.0.0.1:9333 -tab 127.0.0.1:8770 -steps flows.truth.json -log steps.jsonl
func drive(args []string) error {
	fset := flag.NewFlagSet("drive", flag.ExitOnError)
	cdp := fset.String("cdp", "http://127.0.0.1:9333", "Chrome's debugging endpoint")
	tabRe := fset.String("tab", "", "regexp of the tab's URL")
	steps := fset.String("steps", "", "flows.truth.json")
	logPath := fset.String("log", "", "where to write when each step began")
	pauseMS := fset.Int("pause", -1, "milliseconds between steps (default: the truth file's pause_ms)")
	mcpCmd := fset.String("mcp", "", "a jsharvest mcp command line: after each step, ask it what the step sent, as an agent would, and check that against the truth")
	mcpGuard := fset.Bool("mcp-guard", false, "with -mcp, the watch runs the guard: check the writes each step sent and that blocked has them, not every request (made-up answers change what follows)")
	fset.Parse(args)
	if *tabRe == "" || *steps == "" || *logPath == "" {
		return fmt.Errorf("-tab, -steps and -log are required")
	}
	truth, err := readTruthFile(*steps)
	if err != nil {
		return err
	}
	id, err := findTab(*cdp, *tabRe)
	if err != nil {
		return err
	}
	alloc, cancelAlloc := remote.NewAllocator(context.Background(), *cdp)
	defer cancelAlloc()
	// Detach on cancel: the tab is not the driver's to close.
	tab, cancel := chromedp.NewContext(alloc, chromedp.WithTargetID(id), chromedp.WithDetachOnCancel())
	defer cancel()
	if err := chromedp.Do(tab); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	out, err := os.Create(*logPath)
	if err != nil {
		return err
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	if *pauseMS >= 0 {
		truth.PauseMS = *pauseMS
	}
	pause := time.Duration(truth.PauseMS) * time.Millisecond
	var ask *asker
	if *mcpCmd != "" {
		if ask, err = newAsker(*mcpCmd, *mcpGuard); err != nil {
			return err
		}
		defer ask.close()
	}
	for i, s := range truth.Steps {
		enc.Encode(stepLog{Step: i, Started: time.Now().UTC()})
		ctx, c := context.WithTimeout(tab, 10*time.Second)
		switch s.Do {
		case "click":
			_, err = chromedp.Run(ctx, chromedp.Click(chromedp.CSS(s.Selector)))
		case "type":
			_, err = chromedp.Run(ctx, chromedp.SendKeys(chromedp.CSS(s.Selector), s.Text))
		case "reload":
			_, err = chromedp.Run(ctx, chromedp.Reload())
		default:
			err = fmt.Errorf("unknown step %q", s.Do)
		}
		c()
		if err != nil {
			return fmt.Errorf("step %d (%s %s): %w", i, s.Do, s.Selector, err)
		}
		fmt.Printf("step %d: %s %s\n", i, s.Do, s.Selector)
		wait := pause
		if s.PauseMS != nil && *pauseMS < 0 {
			wait = time.Duration(*s.PauseMS) * time.Millisecond
		}
		if ask != nil {
			// Right after the step, as an agent asks; the answer waits for
			// the step's requests to settle.
			asked := time.Now()
			ask.step(i, s)
			wait -= time.Since(asked)
		}
		time.Sleep(max(wait, 0))
	}
	if ask != nil {
		return ask.finish()
	}
	return nil
}

// findTab returns the one page target whose URL matches re, waiting up to
// 20 s for it: a watch's -open loads the page while a busy machine (gates
// in lanes, testbed/regress.sh) starts Chrome slowly.
func findTab(cdp, re string) (target.ID, error) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		id, err := findTabOnce(cdp, re)
		if err == nil || time.Now().After(deadline) {
			return id, err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func findTabOnce(cdp, re string) (target.ID, error) {
	rx, err := regexp.Compile(re)
	if err != nil {
		return "", err
	}
	resp, err := http.Get(cdp + "/json/list")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var list []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return "", err
	}
	var found []string
	for _, t := range list {
		if t.Type == "page" && rx.MatchString(t.URL) {
			found = append(found, t.ID)
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("%d tabs match %q, want 1", len(found), re)
	}
	return target.ID(found[0]), nil
}
