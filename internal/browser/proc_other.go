//go:build !unix

package browser

import "github.com/chromedp/chromedp"

func processOptions() []chromedp.ExecAllocatorOption { return nil }
