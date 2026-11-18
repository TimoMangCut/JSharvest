package jsapi

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSelfReferentialTernaryAndAuthzCyclesDoNotOverflowStack(t *testing.T) {
	var dag strings.Builder
	dag.WriteString("function buildUrl(id, sub) { return '/api/v1/items/' + id + (sub ? '/' + sub : ''); }\n")
	dag.WriteString("function legacyParamShadow(a, d, norm) {\n")
	dag.WriteString("  var a = 'object' === typeof a ? norm(d, a) : a;\n")
	dag.WriteString("  return fetch(buildUrl(a, 'detail'));\n")
	dag.WriteString("}\n")
	dag.WriteString("function localSelfTernary(flag) {\n")
	dag.WriteString("  var v = flag ? v : '';\n")
	dag.WriteString("  var w = flag ? w : w;\n")
	dag.WriteString("  fetch(buildUrl('u1', v));\n")
	dag.WriteString("  fetch(buildUrl('u2', w));\n")
	dag.WriteString("}\n")
	dag.WriteString("function deepTernaryDAG(c) {\n")
	for i := 0; i < 24; i++ {
		fmt.Fprintf(&dag, "  var t%d = c ? t%d : t%d;\n", i, i+1, i+1)
	}
	dag.WriteString("  var t24 = c ? '' : null;\n")
	dag.WriteString("  return fetch(buildUrl('dag', t0));\n")
	dag.WriteString("}\n")
	dag.WriteString("var ACTIONS = Object.freeze({ APPROVE: ACTIONS.APPROVE, READ: ACTIONS['READ'], VALID: 'order:write' });\n")
	dag.WriteString("function checkPerms(ability) {\n")
	dag.WriteString("  if (ability.can(ACTIONS.APPROVE, 'Order') || ability.can(ACTIONS['READ'], 'Order') || ability.can(ACTIONS.VALID, 'Order')) {\n")
	dag.WriteString("    return fetch('/api/v1/orders/approve', { method: 'POST' });\n")
	dag.WriteString("  }\n")
	dag.WriteString("}\n")

	start := time.Now()
	res := Extract([]byte(dag.String()))
	elapsed := time.Since(start)
	if res.Error != "" {
		t.Fatalf("unexpected parse/extract error: %s", res.Error)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Extract took %v on cyclic/DAG ternaries; expected fast bounded termination", elapsed)
	}

	got := map[string]bool{}
	for _, ep := range res.Endpoints {
		got[ep.Method+" "+ep.URL] = true
	}
	if !got["GET /api/v1/items/{}/detail"] {
		t.Fatalf("missing GET /api/v1/items/{}/detail in %+v", res.Endpoints)
	}
	if !got["POST /api/v1/orders/approve"] {
		t.Fatalf("missing POST /api/v1/orders/approve in %+v", res.Endpoints)
	}
}
