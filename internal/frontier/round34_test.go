package frontier

import (
	"fmt"
	"testing"
)

func TestQueueWeightedDRRFairnessAndDecay(t *testing.T) {
	q := NewQueue(Options{
		InScope:  func(string) bool { return true },
		MaxDepth: 3,
	})
	// Noisy CMS host queues 30 links at depth 1 before smaller subdomains appear.
	for i := 0; i < 30; i++ {
		if r := q.Add(Found{URL: fmt.Sprintf("https://www.example.test/news/%d", i), How: Link, Visit: true}, 1, "https://www.example.test/"); r != "" {
			t.Fatalf("unexpected add reason: %s", r)
		}
	}
	// Pop 2 items from www so bandFloor advances, then discover admin & portal subdomains.
	for range 2 {
		if _, ok := q.Next(); !ok {
			t.Fatal("expected item")
		}
	}
	for i := 0; i < 3; i++ {
		q.Add(Found{URL: fmt.Sprintf("https://admin.example.test/p/%d", i), How: Link, Visit: true}, 1, "https://www.example.test/")
		q.Add(Found{URL: fmt.Sprintf("https://portal.example.test/p/%d", i), How: Link, Visit: true}, 1, "https://www.example.test/")
	}

	// Within the very next 9 pops, all 3 admin and all 3 portal pages must be
	// scheduled rather than waiting behind the remaining 28 www pages.
	seenAdmin, seenPortal := 0, 0
	for range 9 {
		it, ok := q.Next()
		if !ok {
			t.Fatal("queue ended early")
		}
		if len(it.URL) >= 24 && it.URL[:26] == "https://admin.example.test" {
			seenAdmin++
		}
		if len(it.URL) >= 25 && it.URL[:27] == "https://portal.example.test" {
			seenPortal++
		}
	}
	if seenAdmin != 3 || seenPortal != 3 {
		t.Fatalf("DRR starved late subdomains: seenAdmin=%d seenPortal=%d (want 3, 3)", seenAdmin, seenPortal)
	}

	// Priority boost (cap 4) and 3-strike saturation decay back to 1.
	for range 10 {
		q.Feedback("https://api.example.test/docs", true)
	}
	if w := q.hostWeight["api.example.test"]; w != 4 {
		t.Fatalf("boosted weight = %d, want 4", w)
	}
	for range 9 {
		q.Feedback("https://api.example.test/empty", false)
	}
	if w := q.hostWeight["api.example.test"]; w != 1 {
		t.Fatalf("decayed weight after 9 empty pages = %d, want 1", w)
	}
}

func TestQueueRefundRestoresMaxPagesSlot(t *testing.T) {
	q := NewQueue(Options{
		InScope:  func(string) bool { return true },
		MaxDepth: 2,
		MaxPages: 2,
	})
	if r := q.Add(Found{URL: "https://a.test/1", How: Link, Visit: true}, 1, ""); r != "" {
		t.Fatal(r)
	}
	if r := q.Add(Found{URL: "https://a.test/2", How: Link, Visit: true}, 1, ""); r != "" {
		t.Fatal(r)
	}
	// Third URL initially hits Limit.
	if r := q.Add(Found{URL: "https://a.test/3", How: Link, Visit: true}, 1, ""); r != Limit {
		t.Fatalf("got %q, want %q", r, Limit)
	}
	// Pop /1 and refund it (pruned without HTTP visit) -> a new URL can take its slot.
	_, _ = q.Next()
	q.Refund()
	if r := q.Add(Found{URL: "https://a.test/4", How: Link, Visit: true}, 1, ""); r != "" {
		t.Fatalf("after Refund, Add returned %q, want empty", r)
	}
}
