package flow

import (
	"net/url"
	"slices"
	"testing"
)

func TestOperationsAndSplit(t *testing.T) {
	u, _ := url.Parse("https://app.test/graphql")
	got := Operations(u, "application/json", batchBody)
	if !slices.Equal(got, []string{"op=A", "op=B"}) {
		t.Fatalf("%v", got)
	}
	parts := SplitBatch(batchBody)
	if len(parts) != 2 || parts[0].Op != "op=A" || parts[1].Op != "op=B" {
		t.Fatalf("%+v", parts)
	}
	// One operation each, still an array, the element as sent (the first of A).
	if parts[0].Body != `[{"operationName":"A","query":"query A { a }","variables":{"x":1}}]` ||
		parts[1].Body != `[{"operationName":"B","query":"mutation B { b }","extensions":{"k":"v"}}]` {
		t.Fatalf("%+v", parts)
	}
	// Not a batch: one element, as Operation says; no split.
	for _, b := range []string{``, `{"query":"query Q { q }"}`, `[{"query":"query Q { q }"}]`, `[1,2]`, `[{"query":"{ anon }"},{"query":"{ x }"}]`} {
		if SplitBatch(b) != nil {
			t.Errorf("%q split", b)
		}
		if ops := Operations(u, "application/json", b); len(ops) != 1 || ops[0] != Operation(u, "application/json", b) {
			t.Errorf("%q: %v", b, ops)
		}
	}
	u2, _ := url.Parse("https://app.test/rpc?action=x")
	if ops := Operations(u2, "", ""); !slices.Equal(ops, []string{"action=x"}) {
		t.Fatalf("%v", ops)
	}
}
