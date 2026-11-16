package verify

import (
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
)

func TestDraftsNameTheirOperation(t *testing.T) {
	in := Inputs{
		InScope: func(h string) bool { return strings.HasSuffix(h, "x.test") },
		Catalog: []endpoints.Endpoint{
			{Method: "POST", Path: "/graphql", Host: "api.x.test", Confidence: "code", Operations: []string{"query GetA", "mutation GetB"}},
			{Method: "GET", Path: "/health", Host: "api.x.test", Confidence: "code"},
		},
	}
	var got []string
	for _, d := range Drafts(in) {
		got = append(got, d.Method+" "+d.Path+" ["+d.Operation+"]")
	}
	if strings.Join(got, ",") != "POST /graphql [op=GetA],POST /graphql [op=GetB],GET /health []" {
		t.Fatalf("%v", got)
	}
}
