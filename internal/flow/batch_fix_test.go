package flow

import (
	"net/url"
	"slices"
	"testing"
)

func TestBatchFixes(t *testing.T) {
	u, _ := url.Parse("https://app.test/graphql")
	ua, _ := url.Parse("https://app.test/rpc?action=bulk")
	apq := `"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ab"}}`
	for _, c := range []struct {
		name string
		u    *url.URL
		body string
		want []string
	}{
		{"anonymous next to a named one", u, `[{"query":"{ me { id } }"},{"operationName":"GetA","query":"query GetA { a }"}]`, []string{"", "op=GetA"}},
		{"anonymous, with a comment before", u, `[{"query":"# who\n{ me { id } }"},{"operationName":"GetA","query":"query GetA { a }"}]`, []string{"", "op=GetA"}},
		{"REST query field", u, `[{"query":"subscription plan"},{"query":"billing"}]`, []string{""}},
		{"REST query field, one element", u, `[{"query":"subscription plan"}]`, []string{""}},
		{"REST, the discriminator stays", ua, `[{"query":"subscription plan"},{"query":"billing"}]`, []string{"action=bulk"}},
		{"persisted queries", u, `[{"operationName":"A",` + apq + `},{"operationName":"B",` + apq + `}]`, []string{"op=A", "op=B"}},
		{"all anonymous", u, `[{"query":"{ a }"},{"query":"{ b }"}]`, []string{""}},
	} {
		if got := Operations(c.u, "application/json", c.body); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if Operation(u, "application/json", `[{"query":"subscription plan"},{"query":"billing"}]`) != "" {
		t.Error("REST array has an operation")
	}
}
