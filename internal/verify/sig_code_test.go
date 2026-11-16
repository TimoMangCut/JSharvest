package verify

import "testing"

func TestSigOfNumericCode(t *testing.T) {
	js := map[string]string{"content-type": "application/json"}
	a := SigOf(404, js, []byte(`{"code":40401,"msg":"no route"}`))
	b := SigOf(404, js, []byte(`{"code":40402,"msg":"no route"}`))
	c := SigOf(404, js, []byte(`{"code":40401,"msg":"other"}`))
	if a.Code != "40401" {
		t.Errorf("code %q, want 40401", a.Code)
	}
	if Same(a, b) {
		t.Error("two numeric codes are one answer")
	}
	if !Same(a, c) {
		t.Error("the same numeric code is two answers")
	}
	if d := SigOf(200, js, []byte(`{"errcode":2001}`)); d.Code != "2001" {
		t.Errorf("errcode %q", d.Code)
	}
	if d := SigOf(200, js, []byte(`{"code":1.5}`)); d.Code != "" {
		t.Errorf("a fraction is not a code: %q", d.Code)
	}
}
