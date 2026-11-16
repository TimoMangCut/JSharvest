package jsapi

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// JSAPI_SNAPSHOT=listfile go test -run TestSnapshot -v ./internal/jsapi
// prints, for each file listed, Extract's whole Result as JSON: diffed
// before and after a change meant to change nothing (the round 25N split
// of jsapi.go).
func TestSnapshot(t *testing.T) {
	list := os.Getenv("JSAPI_SNAPSHOT")
	if list == "" {
		t.Skip("JSAPI_SNAPSHOT not set")
	}
	b, _ := os.ReadFile(list)
	n := 0
	for _, f := range strings.Fields(string(b)) {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		n++
		r := ExtractSource(src, f)
		j, _ := json.Marshal(r)
		fmt.Printf("SNAP %s %s\n", f, j)
	}
	fmt.Printf("SNAPFILES %d\n", n)
}
