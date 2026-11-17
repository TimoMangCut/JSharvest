package jsapi

import (
	"bytes"
	"regexp"
	"slices"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

var (
	nextActionIDRe   = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)
	trpcIdentRe      = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	connectServiceRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.[A-Z][A-Za-z0-9_]*$`)
	connectMethodRe  = regexp.MustCompile(`^[A-Z][A-Za-z0-9_]*$`)
	grpcWebPathRe    = regexp.MustCompile(`^/[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.[A-Z][A-Za-z0-9_]*/[A-Z][A-Za-z0-9_]*$`)
)

func hasNextActionHint(src []byte) bool {
	return bytes.Contains(src, []byte("ServerReference")) ||
		bytes.Contains(src, []byte("createActionProxy"))
}

func hasTRPCHint(src []byte) bool {
	return bytes.Contains(src, []byte("useQuery")) ||
		bytes.Contains(src, []byte("useSuspenseQuery")) ||
		bytes.Contains(src, []byte("useInfiniteQuery")) ||
		bytes.Contains(src, []byte("useMutation")) ||
		bytes.Contains(src, []byte("TRPC")) ||
		bytes.Contains(src, []byte("trpc")) ||
		bytes.Contains(src, []byte("httpBatch"))
}

func hasConnectGRPCHint(src []byte) bool {
	return bytes.Contains(src, []byte("typeName")) ||
		bytes.Contains(src, []byte("MethodDescriptor")) ||
		bytes.Contains(src, []byte("MethodInfo"))
}

// hasModernRPCHint guards the AST walk so bundles without Next.js Server
// Actions, tRPC, ConnectRPC, or gRPC-Web incur zero AST traversal.
func hasModernRPCHint(src []byte) bool {
	return hasNextActionHint(src) || hasTRPCHint(src) || hasConnectGRPCHint(src)
}

func extractModernRPC(ast *js.AST, x *extractor) {
	if ast == nil || x == nil || !hasModernRPCHint(x.src) {
		return
	}
	wantNext := hasNextActionHint(x.src)
	wantTRPC := hasTRPCHint(x.src)
	wantConnect := hasConnectGRPCHint(x.src)

	var trpcVars map[*js.Var]bool
	trpcBase := "/api/trpc"
	hasExplicitTRPC := false
	if wantTRPC {
		trpcVars, trpcBase, hasExplicitTRPC = scanTRPCSetup(ast, x)
	}

	js.Walk(walker(func(n js.INode) {
		switch t := n.(type) {
		case *js.CallExpr:
			if wantNext {
				extractNextServerActionCall(t, x)
			}
			if wantTRPC {
				extractTRPCCall(t, x, trpcVars, trpcBase, hasExplicitTRPC)
			}
			if wantConnect {
				extractGRPCWebMethodCall(t.X, t.Args.List, t, x)
			}
		case *js.NewExpr:
			if wantConnect && t.Args != nil {
				extractGRPCWebMethodCall(t.X, t.Args.List, t, x)
			}
		case *js.ObjectExpr:
			if wantConnect {
				extractConnectServiceObject(t, x)
			}
		}
	}), ast)
}

func scanTRPCSetup(ast *js.AST, x *extractor) (map[*js.Var]bool, string, bool) {
	vars := map[*js.Var]bool{}
	base := ""
	explicit := bytes.Contains(x.src, []byte("TRPC")) || bytes.Contains(x.src, []byte("httpBatch"))
	js.Walk(walker(func(n js.INode) {
		switch t := n.(type) {
		case *js.VarDecl:
			for _, b := range t.List {
				vr, ok := b.Binding.(*js.Var)
				if !ok || b.Default == nil {
					continue
				}
				ce, ok := unwrapEnumGroup(b.Default).(*js.CallExpr)
				if !ok {
					continue
				}
				_, fn := splitCallee(unwrapCalleeExpr(ce.X))
				if isTRPCFactory(fn) {
					vars[root(vr)] = true
					explicit = true
				}
			}
		case *js.CallExpr:
			_, fn := splitCallee(unwrapCalleeExpr(t.X))
			if isTRPCLinkFactory(fn) && len(t.Args.List) >= 1 && !t.Args.List[0].Rest {
				explicit = true
				if obj, ok := unwrapEnumGroup(t.Args.List[0].Value).(*js.ObjectExpr); ok {
					for _, p := range obj.List {
						if p.Name != nil && propName(p.Name) == "url" && p.Value != nil {
							for _, v := range x.eval(p.Value, nil, 0) {
								if v != "" && v != unknown {
									base = strings.TrimRight(v, "/")
									x.addBase(base)
									break
								}
							}
						}
					}
				}
			}
		}
	}), ast)
	if base == "" {
		base = "/api/trpc"
	}
	return vars, base, explicit
}

func isTRPCFactory(name string) bool {
	switch name {
	case "createTRPCProxyClient", "createTRPCClient", "createTRPCReact", "createTRPCNext", "createTRPCUntypedClient":
		return true
	}
	return false
}

func isTRPCLinkFactory(name string) bool {
	switch name {
	case "httpBatchLink", "httpBatchStreamLink", "unstable_httpBatchStreamLink", "httpLink":
		return true
	}
	return false
}

var trpcDisallowedSegs = map[string]bool{
	"prototype": true, "default": true, "state": true, "props": true,
	"current": true, "window": true, "document": true,
}

func extractTRPCCall(ce *js.CallExpr, x *extractor, trpcVars map[*js.Var]bool, trpcBase string, hasExplicitTRPC bool) {
	// tRPC proxy calls are always direct property chains (never `(0, rq.useQuery)(...)`).
	dot, ok := ce.X.(*js.DotExpr)
	if !ok {
		return
	}
	term := propName(dot.Y)
	method := ""
	isHook := false
	switch term {
	case "useQuery", "useSuspenseQuery", "useInfiniteQuery", "useSuspenseInfiniteQuery":
		method, isHook = "GET", true
	case "useMutation":
		method, isHook = "POST", true
	case "query":
		method = "GET"
	case "mutate", "mutateAsync":
		method = "POST"
	default:
		return
	}

	// Walk back along the property chain to gather `<root>.<seg1>.<seg2>...`.
	var segs []string
	cur := dot.X
	for len(segs) < 12 {
		d, ok := cur.(*js.DotExpr)
		if !ok {
			break
		}
		seg := propName(d.Y)
		if !trpcIdentRe.MatchString(seg) || trpcDisallowedSegs[seg] {
			return
		}
		segs = append(segs, seg)
		cur = d.X
	}
	if len(segs) == 0 {
		return // `<mod>.useQuery(...)` has 0 procedure segments; never tRPC.
	}
	slices.Reverse(segs)

	rootKnown := false
	switch r := unwrapEnumGroup(cur).(type) {
	case *js.Var:
		rn := strings.ToLower(string(r.Data))
		rootKnown = trpcVars[root(r)] || strings.Contains(rn, "trpc")
	case *js.DotExpr:
		// e.g. Webpack module import `n.trpc.user.me.useQuery()` -> peel one more level if module prop is trpc/api.
		return
	default:
		return
	}

	// Reject standalone TanStack React Query option objects (`{ queryKey, queryFn, mutationFn }`)
	// or raw SQL strings (`db.users.query("SELECT ...")`).
	var inputKeys []string
	if len(ce.Args.List) > 0 && !ce.Args.List[0].Rest {
		arg0 := unwrapEnumGroup(ce.Args.List[0].Value)
		if lit, ok := arg0.(*js.LiteralExpr); ok && lit.TokenType == js.StringToken {
			return
		}
		if obj, ok := arg0.(*js.ObjectExpr); ok {
			for _, p := range obj.List {
				if p.Name == nil || p.Spread {
					continue
				}
				k := propName(p.Name)
				if k == "queryKey" || k == "queryFn" || k == "mutationFn" {
					return
				}
				if trpcIdentRe.MatchString(k) {
					inputKeys = append(inputKeys, k)
				}
			}
		}
	}

	if !isHook {
		// Imperative `.query()` / `.mutate()` requires a confirmed tRPC client root.
		if !rootKnown {
			return
		}
	} else if len(segs) == 1 && !rootKnown && !hasExplicitTRPC {
		return
	}

	ep := Endpoint{
		Method: method,
		URL:    strings.TrimRight(trpcBase, "/") + "/" + strings.Join(segs, "."),
		Kind:   "rpc",
	}
	if method == "GET" && len(ce.Args.List) > 0 {
		ep.Query = []string{"batch", "input"}
	} else if method == "POST" && len(inputKeys) > 0 {
		ep.Body = inputKeys
	}
	x.addDirect(ep, ce)
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

// extractConnectServiceObject extracts @connectrpc/connect & @bufbuild/protobuf
// service descriptors: `{ typeName: "acme.v1.UserService", methods: { ... } }`.
func extractConnectServiceObject(obj *js.ObjectExpr, x *extractor) {
	var svcName string
	var svcLit *js.LiteralExpr
	var methodsVal js.IExpr
	for _, p := range obj.List {
		if p.Name == nil || p.Value == nil {
			continue
		}
		switch propName(p.Name) {
		case "typeName":
			if lit, ok := unwrapEnumGroup(p.Value).(*js.LiteralExpr); ok && lit.TokenType == js.StringToken {
				s := strings.TrimSpace(unquote(lit.Data))
				if connectServiceRe.MatchString(s) {
					svcName, svcLit = s, lit
				}
			}
		case "methods":
			methodsVal = unwrapEnumGroup(p.Value)
		}
	}
	if svcName == "" || methodsVal == nil {
		return
	}

	var methodObjs []*js.ObjectExpr
	switch m := methodsVal.(type) {
	case *js.ObjectExpr:
		for _, mp := range m.List {
			if mp.Value != nil {
				if mo, ok := unwrapEnumGroup(mp.Value).(*js.ObjectExpr); ok {
					methodObjs = append(methodObjs, mo)
				}
			}
		}
	case *js.ArrayExpr:
		for _, el := range m.List {
			if el.Value != nil {
				if mo, ok := unwrapEnumGroup(el.Value).(*js.ObjectExpr); ok {
					methodObjs = append(methodObjs, mo)
				}
			}
		}
	}
	if len(methodObjs) == 0 {
		return
	}
	if svcLit != nil {
		x.used[svcLit] = true
	}
	for _, mo := range methodObjs {
		var mName string
		var mLit *js.LiteralExpr
		noSideEffects := false
		for _, p := range mo.List {
			if p.Name == nil || p.Value == nil {
				continue
			}
			switch propName(p.Name) {
			case "name":
				if lit, ok := unwrapEnumGroup(p.Value).(*js.LiteralExpr); ok && lit.TokenType == js.StringToken {
					s := strings.TrimSpace(unquote(lit.Data))
					if connectMethodRe.MatchString(s) {
						mName, mLit = s, lit
					}
				}
			case "idempotency":
				noSideEffects = isConnectNoSideEffects(p.Value)
			}
		}
		if mName == "" {
			continue
		}
		if mLit != nil {
			x.used[mLit] = true
		}
		rpcPath := "/" + svcName + "/" + mName
		x.addDirect(Endpoint{
			Method: "POST",
			URL:    rpcPath,
			Kind:   "rpc",
		}, mo)
		if noSideEffects {
			x.addDirect(Endpoint{
				Method: "GET",
				URL:    rpcPath,
				Kind:   "rpc",
				Query:  []string{"connect", "encoding", "message"},
			}, mo)
		}
	}
}

func isConnectNoSideEffects(e js.IExpr) bool {
	switch v := unwrapEnumGroup(e).(type) {
	case *js.LiteralExpr:
		switch v.TokenType {
		case js.DecimalToken, js.IntegerToken:
			return string(v.Data) == "1"
		case js.StringToken:
			s := strings.ToLower(unquote(v.Data))
			return s == "nosideeffects" || s == "no_side_effects"
		}
	case *js.DotExpr:
		p := strings.ToLower(propName(v.Y))
		return p == "nosideeffects" || p == "no_side_effects"
	}
	return false
}

// extractGRPCWebMethodCall extracts `new MethodDescriptor("/pkg.v1.Svc/Method", ...)`.
func extractGRPCWebMethodCall(callee js.IExpr, args []js.Arg, at js.INode, x *extractor) {
	_, name := splitCallee(unwrapCalleeExpr(callee))
	if name != "MethodDescriptor" && name != "MethodInfo" {
		return
	}
	for i := 0; i < min(len(args), 2); i++ {
		if args[i].Rest || args[i].Value == nil {
			continue
		}
		lit, ok := unwrapEnumGroup(args[i].Value).(*js.LiteralExpr)
		if !ok || lit.TokenType != js.StringToken {
			continue
		}
		p := strings.TrimSpace(unquote(lit.Data))
		if !grpcWebPathRe.MatchString(p) {
			continue
		}
		x.used[lit] = true
		x.addDirect(Endpoint{
			Method: "POST",
			URL:    p,
			Kind:   "rpc",
		}, at)
		return
	}
}
