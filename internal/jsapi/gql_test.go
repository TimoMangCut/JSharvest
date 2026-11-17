package jsapi_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func TestExtractGraphQLDocs(t *testing.T) {
	bigPad := strings.Repeat("x", 9000)
	src := []byte(`
		const UserFields = gql` + "`" + `
			fragment UserFields on User {
				id
				email
			}
		` + "`" + `;

		const GET_USER = gql` + "`" + `
			query GetUser($id: ID!, $limit: Int = 10, $active: Boolean, $tags: [String!]) {
				user(id: $id, limit: $limit, active: $active, tags: $tags) {
					...UserFields
				}
			}
			${UserFields}
		` + "`" + `;

		const ARCHIVE = graphql(` + "`" + `
			mutation ArchiveProject($projectId: ID!) {
				archiveProject(id: $projectId) { ok }
			}
		` + "`" + `);

		const COMPILED = {
			kind: "Document",
			definitions: [{ kind: "OperationDefinition", operation: "query", name: { kind: "Name", value: "BillingSummary" } }],
			loc: { source: { body: "query BillingSummary { billing { plan } }" } }
		};

		const TOO_LARGE = gql` + "`query HugeQuery { field(pad: \"" + bigPad + "\") }`" + `;
	`)

	res := jsapi.Extract(src)
	if res.Error != "" {
		t.Fatalf("Extract error: %s", res.Error)
	}
	byName := map[string]jsapi.GraphQLDoc{}
	for _, d := range res.GraphQLDocs {
		byName[d.Name] = d
	}
	if _, bad := byName["HugeQuery"]; bad {
		t.Fatalf("expected >8192 byte GraphQL doc to be skipped")
	}
	u, ok := byName["GetUser"]
	if !ok || u.Kind != "query" {
		t.Fatalf("missing GetUser query in %+v", res.GraphQLDocs)
	}
	if !strings.Contains(u.Query, "fragment UserFields on User") {
		t.Fatalf("GetUser.Query missing interpolated fragment: %q", u.Query)
	}
	wantVars := []jsapi.GraphQLVar{
		{Name: "id", Type: "ID!"},
		{Name: "limit", Type: "Int"},
		{Name: "active", Type: "Boolean"},
		{Name: "tags", Type: "[String!]"},
	}
	if !slices.Equal(u.Vars, wantVars) {
		t.Fatalf("GetUser.Vars = %+v, want %+v", u.Vars, wantVars)
	}

	ar, ok := byName["ArchiveProject"]
	if !ok || ar.Kind != "mutation" || len(ar.Vars) != 1 || ar.Vars[0].Name != "projectId" {
		t.Fatalf("ArchiveProject doc = %+v", ar)
	}

	bs, ok := byName["BillingSummary"]
	if !ok || bs.Kind != "query" || !strings.Contains(bs.Query, "billing") {
		t.Fatalf("BillingSummary compiled doc = %+v", bs)
	}
}
