package replay

import "testing"

func TestJudgeBodyFixes(t *testing.T) {
	js := map[string]string{"content-type": "application/json"}
	a := func(s int, body string) Answer { return Answer{Status: s, Header: js, Body: []byte(body)} }
	exp := `{"groups":[{"items":[{"a":1},{"b":2,"c":3}]},{"items":[{"a":2},{"d":4}]}]}`
	flip := `{"groups":[{"items":[{"b":2,"c":3},{"a":1}]},{"items":[{"a":2},{"d":4}]}]}`
	inv := `{"code":2001,"msg":"invalid token","path":"/api/admin/users"}`
	for _, c := range []struct {
		name string
		c    Case
		want Verdict
	}{
		{"meta key path, both sides", Case{Trial: a(200, inv), Controls: []Answer{a(200, inv)}}, Unclear},
		{"meta key detail, a write", Case{Write: true, Trial: a(200, `{"code":2004,"msg":"permission denied","detail":"admin required"}`)}, NeedsReview},
		{"a reordered root array is the same", Case{Trial: a(200, `[{"id":2,"status":2},{"id":1,"status":1}]`),
			Controls: []Answer{a(200, `[{"id":1,"status":1},{"id":2,"status":2}]`)}}, Bypass},
		{"code 0 with a status of 1 is ok", Case{Write: true, Trial: a(200, `{"code":0,"status":1,"msg":"ok"}`)}, Bypass},
		{"a bad code still fails", Case{Write: true, Trial: a(200, `{"code":0,"status":403,"msg":"ok"}`)}, NeedsReview},
		{"nested lists reordered", Case{Trial: a(200, flip), Controls: []Answer{a(200, exp)}}, Bypass},
	} {
		if got := Judge(c.c); got.Verdict != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, got.Verdict, got.Reason, c.want)
		}
	}
}
