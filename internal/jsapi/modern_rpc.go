package jsapi

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

var nextActionIDRe = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)

// hasModernRPCHint guards the AST walk so bundles without Next.js Server
// Actions (and later tRPC / ConnectRPC / gRPC-Web) incur zero AST traversal.
func hasModernRPCHint(src []byte) bool {
	return bytes.Contains(src, []byte("ServerReference")) ||
		bytes.Contains(src, []byte("createActionProxy"))
}

func extractModernRPC(ast *js.AST, x *extractor) {
	if ast == nil || x == nil || !hasModernRPCHint(x.src) {
		return
	}
	js.Walk(walker(func(n js.INode) {
		ce, ok := n.(*js.CallExpr)
		if !ok {
			return
		}
		extractNextServerActionCall(ce, x)
	}), ast)
}

func extractNextServerActionCall(ce *js.CallExpr, x *extractor) {
	_, name := splitCallee(unwrapCalleeExpr(ce.X))
	var idExpr js.IExpr
	switch name {
	case "createServerReference", "createActionProxy":
		if len(ce.Args.List) < 1 || ce.Args.List[0].Rest {
			return
		}
		idExpr = ce.Args.List[0].Value
	case "registerServerReference":
		if len(ce.Args.List) < 2 || ce.Args.List[1].Rest {
			return
		}
		idExpr = ce.Args.List[1].Value
	default:
		return
	}
	idLit, ok := unwrapEnumGroup(idExpr).(*js.LiteralExpr)
	if !ok || idLit.TokenType != js.StringToken {
		return
	}
	rawID := strings.TrimSpace(unquote(idLit.Data))
	if !nextActionIDRe.MatchString(rawID) {
		return
	}
	x.used[idLit] = true
	hexID := strings.ToLower(rawID)
	ep := Endpoint{
		Method:        "POST",
		URL:           "/",
		Kind:          "rpc",
		NoInheritBase: true,
		Headers:       []string{"Next-Action"},
		Operations:    []string{"next-action=" + hexID},
		Params: []ParamSpec{{
			Name:   "Next-Action",
			In:     "header",
			Type:   "string",
			Values: []string{hexID},
		}},
	}
	x.addDirect(ep, ce)
}

// addDirect records a protocol-verified RPC endpoint directly in x.eps
// (allowing "/" for Next.js App Router Server Actions where looksLikePath
// rejects bare "/").
func (x *extractor) addDirect(ep Endpoint, at js.INode) string {
	if ep.Line == 0 {
		if c, ok := at.(*js.CallExpr); ok {
			x.locateCall(&ep, c)
		}
		if ep.Line == 0 && len(x.src) > 0 {
			pos := min(x.cursor, len(x.src)-1)
			x.place(&ep, pos, min(pos+1, len(x.src)))
		}
	}
	key := ep.Method + " " + ep.URL + " " + ep.Kind
	x.producers[key] = append(x.producers[key], at)
	if old, ok := x.eps[key]; ok {
		old.Params = mergeSpecs(old.Params, ep.Params)
		old.BaseKeys = uniq(append(old.BaseKeys, ep.BaseKeys...))
		old.Query = append(old.Query, ep.Query...)
		old.Body = append(old.Body, ep.Body...)
		old.Headers = append(old.Headers, ep.Headers...)
		old.Operations = append(old.Operations, ep.Operations...)
		old.NoInheritBase = old.NoInheritBase || ep.NoInheritBase
		old.Collector = old.Collector || ep.Collector
		if old.Line == 0 && ep.Line > 0 {
			old.Line, old.Col, old.Snippet = ep.Line, ep.Col, ep.Snippet
		}
		return key
	}
	x.eps[key] = &ep
	x.order = append(x.order, key)
	return key
}
