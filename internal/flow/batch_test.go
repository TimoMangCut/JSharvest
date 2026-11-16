package flow

import (
	"net/url"
	"testing"
)

const batchBody = `[{"operationName":"A","query":"query A { a }","variables":{"x":1}},{"operationName":"B","query":"mutation B { b }","extensions":{"k":"v"}},{"operationName":"A","query":"query A { a }","variables":{"x":2}}]`

// A batch is not an endpoint of op "": the operation of its first element.
func TestOperationOfBatch(t *testing.T) {
	u, _ := url.Parse("https://app.test/graphql")
	if got := Operation(u, "application/json", batchBody); got != "op=A" {
		t.Fatalf("got %q, want op=A", got)
	}
	if got := Operation(u, "application/json", `[{"query":"query One { a }"}]`); got != "op=One" {
		t.Fatalf("array of one: %q", got)
	}
	// A request that is not a batch is as it was.
	if got := Operation(u, "application/json", `{"query":"mutation Del { d }"}`); got != "op=Del" {
		t.Fatalf("%q", got)
	}
	u2, _ := url.Parse("https://app.test/index.php?action=purge7")
	if got := Operation(u2, "", ""); got != "action=purge#" {
		t.Fatalf("%q", got)
	}
}
