package flow

import "testing"

func TestSplitBatchIndex(t *testing.T) {
	parts := SplitBatch(`[{"query":"{ me }"},{"operationName":"A","query":"query A { a }"},{"operationName":"A","query":"query A { a2 }"},{"query":"{ x }"},{"operationName":"B","query":"query B { b }"}]`)
	if len(parts) != 3 || parts[0].Index != 0 || parts[0].Op != "" || parts[1].Index != 1 || parts[2].Index != 4 {
		t.Fatalf("%+v", parts)
	}
	if parts[1].Body != `[{"operationName":"A","query":"query A { a }"}]` {
		t.Fatalf("%s", parts[1].Body)
	}
}
