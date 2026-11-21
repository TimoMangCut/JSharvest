//go:build unix && !linux

package browser

import (
	"errors"
	"os/exec"
	"syscall"

	"github.com/chromedp/chromedp"
)

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// processOptions puts Chrome in a process group of its own on macOS/BSD so a
// terminal's Ctrl-C reaches jsharvest first for ordered tab/session shutdown.
func processOptions() []chromedp.ExecAllocatorOption {
	return []chromedp.ExecAllocatorOption{chromedp.ModifyCmdFunc(func(cmd *exec.Cmd) {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = new(syscall.SysProcAttr)
		}
		cmd.SysProcAttr.Setpgid = true
	})}
}
