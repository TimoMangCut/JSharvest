package guard

import "testing"

// P8 (user decision 2026-11-16): the refresh exception never lets a GraphQL
// request by, whatever grant_type it carries in its query or body.
func TestRefreshGrantNotGraphQL(t *testing.T) {
	r := Rules{}
	for _, c := range []Request{
		{Method: "POST", URL: "https://app.example/graphql?grant_type=refresh_token", ContentType: "application/json",
			Body: `{"query":"mutation DeleteAll { deleteAll }"}`},
		{Method: "POST", URL: "https://app.example/api/token", ContentType: "application/json",
			Body: `{"grant_type":"refresh_token","query":"mutation Wipe { wipe }"}`},
		{Method: "POST", URL: "https://app.example/graphql?grant_type=refresh_token", ContentType: "application/json",
			Body: `[{"query":"mutation A { a }"}]`},
		{Method: "POST", URL: "https://app.example/gql?grant_type=refresh_token", ContentType: "application/graphql",
			Body: `mutation A { a }`},
		{Method: "POST", URL: "https://app.example/graphql?grant_type=refresh_token", ContentType: "application/x-www-form-urlencoded",
			Body: `query=mutation+A+%7B+a+%7D`},
	} {
		if d := r.Classify(c); d.Action != Fake {
			t.Errorf("%s %s %q: %+v, want held", c.Method, c.URL, c.Body, d)
		}
	}
	ok := Request{Method: "POST", URL: "https://app.example/oauth/token", ContentType: "application/x-www-form-urlencoded",
		Body: "grant_type=refresh_token&refresh_token=r1"}
	if d := r.Classify(ok); d.Action != Pass || d.Reason != "refresh" {
		t.Errorf("a plain refresh: %+v", d)
	}
}
