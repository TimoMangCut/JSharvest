package endpoints

import (
	"os"
	"testing"
	"time"
)

// JSH_ANALYZE_DIR=<role dir> go test -run TestAnalyzeBench -v ./internal/endpoints
// times Analyze cold (no cache) and warm (every script cached): what
// frontier.commit pays at each level (round 25N, step 3.1).
func TestAnalyzeBench(t *testing.T) {
	dir := os.Getenv("JSH_ANALYZE_DIR")
	if dir == "" {
		t.Skip("JSH_ANALYZE_DIR not set")
	}
	for _, pass := range []string{"cold", "warm", "warm"} {
		began := time.Now()
		ss, err := Analyze(dir, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d scripts in %s", pass, len(ss), time.Since(began).Round(time.Millisecond))
	}
}
