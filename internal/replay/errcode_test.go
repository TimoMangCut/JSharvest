package replay

import "testing"

func TestJudgeNumericCodes(t *testing.T) {
	js := map[string]string{"content-type": "application/json"}
	a := func(body string) Answer { return Answer{Status: 200, Header: js, Body: []byte(body)} }
	const fields = `"a":1,"b":2,"c":3,"d":4,"e":5`
	for _, c := range []struct {
		name  string
		trial string
		ctl   []string
		want  Verdict
	}{
		{"code 0 is a success", `{"code":0,"data":{"id":1,"n":"x"}}`, []string{`{"code":0,"data":{"id":1,"n":"x"}}`}, Bypass},
		{"code 1 with data is valid", `{"code":1,"data":{"id":1,"n":"x"}}`, []string{`{"code":1,"data":{"id":1,"n":"x"}}`}, Bypass},
		{"code 20000 with data", `{"code":20000,"data":{"id":1,"n":"x"}}`, []string{`{"code":20000,"data":{"id":1,"n":"x"}}`}, Bypass},
		{"code 1001 same as control, with data", `{"code":1001,"data":{"id":1}}`, []string{`{"code":1001,"data":{"id":1}}`}, Bypass},
		{"unknown code that differs from control", `{"code":1001,"data":{"id":1}}`, []string{`{"code":1,"data":{"id":1}}`}, NeedsReview},
		{"2001 both sides: expired session", `{"code":2001,"msg":"invalid token"}`, []string{`{"code":2001,"msg":"invalid token"}`}, Unclear},
		{"40301 both sides", `{"code":40301,"msg":"no"}`, []string{`{"code":40301,"msg":"no"}`}, Unclear},
		{"40301 trial only", `{"code":40301,"msg":"no",` + fields + `}`, []string{`{"code":0,"msg":"no",` + fields + `}`}, NeedsReview},
		{"2004 with a null data, control a success", `{"code":2004,"data":null,"msg":"x",` + fields + `}`, []string{`{"code":0,"data":null,"msg":"x",` + fields + `}`}, NeedsReview},
		{"negative code", `{"code":-1,"msg":"m",` + fields + `}`, []string{`{"code":0,"msg":"m",` + fields + `}`}, NeedsReview},
		{"statusCode 50001", `{"statusCode":50001,"message":"m",` + fields + `}`, []string{`{"statusCode":200,"message":"m",` + fields + `}`}, NeedsReview},
		{"reordered list", `{"items":[{"id":2,"n":"b"},{"id":1,"n":"a"}]}`, []string{`{"items":[{"id":1,"n":"a"},{"id":2,"n":"b"}]}`}, Bypass},
		{"shorter list", `{"items":[{"id":3},{"id":2}]}`, []string{`{"items":[{"id":1},{"id":2},{"id":3}]}`}, NeedsReview},
		{"empty list vs full", `{"items":[]}`, []string{`{"items":[{"id":1}]}`}, NeedsReview},
		{"root array, all errors", `[{"code":40301,"msg":"m",` + fields + `},{"code":40301,"msg":"m",` + fields + `}]`, []string{`[{"code":0,"msg":"m",` + fields + `},{"code":0,"msg":"m",` + fields + `}]`}, NeedsReview},
		{"root array, one error", `[{"code":0,"msg":"m",` + fields + `},{"code":40301,"msg":"m",` + fields + `}]`, []string{`[{"code":0,"msg":"m",` + fields + `},{"code":0,"msg":"m",` + fields + `}]`}, NeedsReview},
		{"root array, control all errors", `[{"errors":[{"message":"x"}]}]`, []string{`[{"errors":[{"message":"x"}]}]`}, Unclear},
		{"root array of one, same", `[{"data":{"id":1}}]`, []string{`[{"data":{"id":1}}]`}, Bypass},
	} {
		var ctls []Answer
		for _, b := range c.ctl {
			ctls = append(ctls, a(b))
		}
		if got := Judge(Case{Trial: a(c.trial), Controls: ctls}); got.Verdict != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, got.Verdict, got.Reason, c.want)
		}
	}
}
