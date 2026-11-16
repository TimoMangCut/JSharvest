//go:build integration

// Package testbed holds the capture regression gate: go test -tags integration
// ./testbed/ runs ./bench.sh (GATE=1 TOOLS=jsharvest) against every built
// testbed app, checking baseline markers, forbidden/required requests, and
// reqcheck. Run testbed/regress.sh for the full suite of gates; build the apps
// first with testbed/build.sh.
package testbed

import (
	"os"
	"os/exec"
	"testing"
)

func TestGate(t *testing.T) {
	cmd := exec.Command("./bench.sh")
	cmd.Env = append(os.Environ(), "GATE=1", "TOOLS=jsharvest")
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("regression gate failed: %v", err)
	}
}
