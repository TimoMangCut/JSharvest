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

// processOptions puts Chrome in a process group of its own: a terminal's
// Ctrl-C (or tini's signal) then reaches jsharvest alone, which closes
// Chrome in order and keeps what it gathered. Chrome still dies with
// jsharvest, as chromedp has it (Pdeathsig).
func processOptions() []chromedp.ExecAllocatorOption {
	return []chromedp.ExecAllocatorOption{chromedp.ModifyCmdFunc(func(cmd *exec.Cmd) {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = new(syscall.SysProcAttr)
		}
		cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
		cmd.SysProcAttr.Setpgid = true
	})}
}
