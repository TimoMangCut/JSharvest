package monitor

import (
	"net/url"
	"slices"
	"testing"
)

func TestRequestParamsOfAnArrayBody(t *testing.T) {
	u, _ := url.Parse("http://app.test/graphql")
	got := requestParams(u, "text/plain;charset=UTF-8", `[{"operationName":"A","variables":{"pa":1}}]`)
	if !slices.Contains(got, "variables.pa") {
		t.Fatalf("%v", got)
	}
}
