package sourcemap

import (
	"fmt"
	"testing"
)

func TestGuesses(t *testing.T) {
	var g Guesses
	for i := range GuessMisses {
		u := fmt.Sprintf("https://a.test/x%d.js.map", i)
		if !g.Allow(u) {
			t.Fatalf("guess %d refused", i)
		}
		g.Done(u, false)
	}
	if g.Allow("https://a.test/more.js.map") {
		t.Fatalf("an origin with %d misses and no map still guessed", GuessMisses)
	}
	if !g.Allow("https://b.test/x.js.map") {
		t.Fatal("another origin was held")
	}
	// One map found: the build ships them, the misses are chunks without.
	var h Guesses
	h.Done("https://a.test/main.js.map", true)
	for i := range 3 * GuessMisses {
		h.Done(fmt.Sprintf("https://a.test/c%d.js.map", i), false)
	}
	if !h.Allow("https://a.test/next.js.map") {
		t.Fatal("an origin with a map found was held")
	}
}
