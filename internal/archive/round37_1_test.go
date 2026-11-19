package archive

import (
	"context"
	"testing"
	"time"
)

// B5: a CDX client that saw the address blocked (refusals, not a 429)
// makes the memento client wait and give up at its first refusal; a CDX
// client that was only slowed down carries nothing.
func TestRound371CarryIndexBlockOnlyForRefusals(t *testing.T) {
	mk := func() *Wayback {
		return &Wayback{Client: &Client{Wait: 200 * time.Millisecond}, IndexClient: &Client{Wait: time.Second},
			Files: &Budget{Gap: time.Millisecond}, Index: &Budget{Gap: time.Millisecond}}
	}
	// Slowed down only (a 429 widened the index budget): nothing carried.
	w := mk()
	w.Index.noteThrottle(time.Second)
	if w.CarryIndexBlock() {
		t.Fatal("a CDX 429 was carried to the mementos")
	}
	if w.Client.recordConnTrouble() {
		t.Fatal("memento client latched at its first refusal without a CDX block")
	}
	// Refused until latched: carried.
	w = mk()
	for !w.IndexClient.recordConnTrouble() {
	}
	if !w.CarryIndexBlock() {
		t.Fatal("a CDX block was not carried")
	}
	start := time.Now()
	if err := w.Files.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 150*time.Millisecond {
		t.Errorf("first memento did not wait the cooldown (%s)", waited)
	}
	if !w.Client.recordConnTrouble() {
		t.Error("memento client did not give up at its first refusal after a CDX block")
	}
	// Separate clients are the point: one client for both carries nothing.
	w = mk()
	w.IndexClient = w.Client
	for !w.Client.recordConnTrouble() {
	}
	if w.CarryIndexBlock() {
		t.Error("carried onto itself")
	}
}
