package verify

import (
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
)

// One endpoint of many operations (what a GraphQL batch's elements are)
// makes a draft for each: the dedup key must not merge them.
func TestDraftsOnePerOperation(t *testing.T) {
	in := Inputs{
		InScope: func(h string) bool { return strings.HasSuffix(h, "x.test") },
		Catalog: []endpoints.Endpoint{
			{Method: "POST", Path: "/graphql", Host: "api.x.test", Confidence: "code", Operations: []string{"query GetA", "mutation GetB", "query GetA"}},
			{Method: "GET", Path: "/health", Host: "api.x.test", Confidence: "code"},
		},
	}
	ds := Drafts(in)
	if len(ds) != 3 {
		t.Fatalf("%d drafts, want 3 (two operations and /health)", len(ds))
	}
}
