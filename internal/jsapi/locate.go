package jsapi

// This file: where an endpoint is written: its line and column, in the source or the original.

import (
	"bytes"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2/js"
)

// locate finds where in the source an endpoint is, by the longest
// literal its URL was made of, searching on from the last one found so
// that repeated URLs get their own places.
func (x *extractor) locate(ep *Endpoint, lits [][]byte) {
	// The pieces of a template follow each other in the source: where all
	// of them do, in order, is the call (`apps/${e}/members/${t}` and
	// `apps/${e}/members?${i}` share their first piece and nothing else).
	if i, end, ok := x.inOrder(lits); ok {
		x.place(ep, i, end)
		return
	}
	// A constant's literal among them (`${base}/x/${e}`, base set
	// elsewhere): the template's own pieces.
	var tpl [][]byte
	for _, l := range lits {
		if len(l) > 0 && (l[0] == '`' || l[0] == '}') {
			tpl = append(tpl, l)
		}
	}
	if len(tpl) < len(lits) {
		if i, end, ok := x.inOrder(tpl); ok {
			x.place(ep, i, end)
			return
		}
	}
	var piece []byte
	for _, l := range lits {
		if len(l) > len(piece) {
			piece = l
		}
	}
	if len(piece) < 3 {
		return
	}
	i := bytes.Index(x.src[x.cursor:], piece)
	if i >= 0 {
		i += x.cursor
	} else if i = bytes.Index(x.src, piece); i < 0 {
		return
	}
	x.place(ep, i, i+len(piece))
}

func collectNodeLits(n js.INode) [][]byte {
	var out [][]byte
	js.Walk(walker(func(sub js.INode) {
		switch t := sub.(type) {
		case *js.LiteralExpr:
			if t.TokenType == js.StringToken && len(t.Data) >= 3 {
				out = append(out, t.Data)
			}
		case *js.TemplateExpr:
			for _, it := range t.List {
				if len(it.Value) >= 2 {
					out = append(out, it.Value)
				}
			}
			if len(t.Tail) >= 2 {
				out = append(out, t.Tail)
			}
		}
	}), n)
	return out
}

func isJSIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '$'
}

// locateCall finds a CallExpr's location in x.src when its evaluated URL had no
// string literals at the call site (e.g. `Oa(JN, YN, {...})` or `getCloudPlan(ctx)`).
func (x *extractor) locateCall(ep *Endpoint, c *js.CallExpr) {
	if c == nil || len(x.src) == 0 {
		return
	}
	if nl := collectNodeLits(c); len(nl) > 0 {
		x.locate(ep, nl)
		if ep.Line > 0 {
			return
		}
	}
	callee := c.X
	for {
		switch ce := callee.(type) {
		case *js.GroupExpr:
			callee = ce.X
			continue
		case *js.CommaExpr:
			if len(ce.List) > 0 {
				callee = ce.List[len(ce.List)-1]
				continue
			}
		}
		break
	}
	var tok []byte
	dotPrefix := false
	switch ce := callee.(type) {
	case *js.Var:
		tok = ce.Data
	case *js.DotExpr:
		if p := propName(ce.Y); p != "" {
			tok = []byte("." + p)
			dotPrefix = true
		}
	}
	if len(tok) == 0 {
		return
	}
	searchRange := func(from, to int) (int, int, bool) {
		pos := from
		for pos < to {
			idx := bytes.Index(x.src[pos:to], tok)
			if idx < 0 {
				return 0, 0, false
			}
			abs := pos + idx
			pos = abs + 1
			if !dotPrefix && abs > 0 && isJSIdentByte(x.src[abs-1]) {
				continue
			}
			after := abs + len(tok)
			if after < len(x.src) && isJSIdentByte(x.src[after]) {
				continue
			}
			k := after
			for k < len(x.src) && (x.src[k] == ' ' || x.src[k] == '\t' || x.src[k] == '\r' || x.src[k] == '\n') {
				k++
			}
			if k < len(x.src) && (x.src[k] == '(' || x.src[k] == ')') {
				// `(0, H.name)(...)` has `)` between `.name` and `(`
				if x.src[k] == ')' {
					k++
					for k < len(x.src) && (x.src[k] == ' ' || x.src[k] == '\t') {
						k++
					}
					if k >= len(x.src) || x.src[k] != '(' {
						continue
					}
				}
				return abs, after, true
			}
		}
		return 0, 0, false
	}
	if s, e, ok := searchRange(x.cursor, len(x.src)); ok {
		x.place(ep, s, e)
		return
	}
	if s, e, ok := searchRange(0, min(len(x.src), x.cursor+len(tok))); ok {
		x.place(ep, s, e)
	}
}

// maxGap is how far apart two pieces of one template may be: the code of
// a ${…} between them.
const maxGap = 256

// inOrder finds where every piece of two or more (each of 2 bytes or
// more) is, in order, each within maxGap of the one before: from the
// cursor on, then from the start. It looks from the longest piece, the
// rarest, at most maxTries places.
func (x *extractor) inOrder(lits [][]byte) (int, int, bool) {
	var ps [][]byte
	for _, l := range lits {
		if len(l) >= 2 {
			ps = append(ps, l)
		}
	}
	if len(ps) < 2 {
		return 0, 0, false
	}
	k := 0
	for i, p := range ps {
		if len(p) > len(ps[k]) {
			k = i
		}
	}
	// around checks the pieces before and after the anchor at a.
	around := func(a int) (int, int, bool) {
		start, end := a, a+len(ps[k])
		for j := k - 1; j >= 0; j-- {
			from := max(0, start-maxGap-len(ps[j]))
			i := bytes.LastIndex(x.src[from:start], ps[j])
			if i < 0 {
				return 0, 0, false
			}
			start = from + i
		}
		for _, p := range ps[k+1:] {
			i := bytes.Index(x.src[end:min(len(x.src), end+maxGap+len(p))], p)
			if i < 0 {
				return 0, 0, false
			}
			end += i + len(p)
		}
		return start, end, true
	}
	try := func(from, to int) (int, int, bool) {
		for n := 0; n < maxTries && from < to; n++ {
			i := bytes.Index(x.src[from:to], ps[k])
			if i < 0 {
				return 0, 0, false
			}
			if s, e, ok := around(from + i); ok {
				return s, e, true
			}
			from += i + 1
		}
		return 0, 0, false
	}
	if i, end, ok := try(x.cursor, len(x.src)); ok {
		return i, end, true
	}
	return try(0, min(len(x.src), x.cursor+len(ps[k])))
}

// maxTries is how many places of a template's longest piece inOrder
// looks at.
const maxTries = 256

// place sets an endpoint's line, column and snippet to the source from i
// to end.
func (x *extractor) place(ep *Endpoint, i, end int) {
	x.cursor = i + 1
	if x.lineMap != nil {
		line, col := x.mappedLineCol(i)
		ep.Line, ep.Col = line, col
		if len(x.origSrc) > 0 {
			oi, byteCol := x.origOffset(line, col)
			ep.Col = byteCol
			span := max(end-i, 0)
			from, to := max(0, oi-60), min(len(x.origSrc), oi+span+60)
			for from > 0 && !utf8.RuneStart(x.origSrc[from]) {
				from--
			}
			for to < len(x.origSrc) && !utf8.RuneStart(x.origSrc[to]) {
				to++
			}
			ep.Snippet = strings.Join(strings.Fields(string(x.origSrc[from:to])), " ")
			return
		}
	} else {
		ep.Line, ep.Col = x.lineCol(i)
	}
	from, to := max(0, i-60), min(len(x.src), end+60)
	for from > 0 && !utf8.RuneStart(x.src[from]) {
		from--
	}
	for to < len(x.src) && !utf8.RuneStart(x.src[to]) {
		to++
	}
	ep.Snippet = strings.Join(strings.Fields(string(x.src[from:to])), " ")
}

func (x *extractor) mappedLineCol(i int) (int, int) {
	line, col := x.lineCol(i)
	if x.lineMap == nil {
		return line, col
	}
	ls := x.lineStarts[line-1]
	u16 := utf16Cols(x.src[ls:min(i, len(x.src))])
	return x.lineMap.lookup(line, u16)
}

func (x *extractor) origOffset(origLine, origCol1 int) (int, int) {
	if x.origLineStarts == nil {
		x.origLineStarts = []int{0}
		for j, c := range x.origSrc {
			if c == '\n' {
				x.origLineStarts = append(x.origLineStarts, j+1)
			}
		}
	}
	l := min(max(origLine, 1), len(x.origLineStarts))
	ls := x.origLineStarts[l-1]
	le := len(x.origSrc)
	if l < len(x.origLineStarts) {
		le = max(ls, x.origLineStarts[l]-1)
	}
	rel := utf16ColToByteOffset(x.origSrc[ls:le], origCol1)
	return ls + rel, rel + 1
}

// lineCol is the line and column of an offset, by the start of each line
// (a minified bundle is one line of megabytes: no counting from 0 each
// time).
func (x *extractor) lineCol(i int) (int, int) {
	if x.lineStarts == nil {
		x.lineStarts = []int{0}
		for j, c := range x.src {
			if c == '\n' {
				x.lineStarts = append(x.lineStarts, j+1)
			}
		}
	}
	l, _ := slices.BinarySearch(x.lineStarts, i+1)
	return l, i - x.lineStarts[l-1] + 1
}

// --- result ---

// fills reports whether a URL is a frame's with its holes filled: the
// frame's known parts in it, in order, the first at its start and the
// last at its end (…/invoices{} by …/invoices/{}/pay; not …/apps/{} by
// …/marketplace/apps/{}).
func fills(frame, u string) bool {
	parts := strings.Split(frame, unknown)
	if len(parts) == 1 {
		return u == frame
	}
	if !strings.HasPrefix(u, parts[0]) {
		return false
	}
	at := len(parts[0])
	for i, p := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(u[at:], p)
		}
		j := strings.Index(u[at:], p)
		if j < 0 {
			return false
		}
		at += j + len(p)
	}
	return true
}

// knownLen is how much of a URL is known: its length without its holes.
func knownLen(u string) int {
	return len(strings.ReplaceAll(u, unknown, ""))
}

// frame reports whether an endpoint is only a helper's frame: found at
// the call in a helper's body alone (yT(`…/scopes/${e}/${t}/${n}`) in
// RE(e,t,n)), where every call to the helper made it whole (RE(e,t,
// "remove")), with fewer of its parts unknown.
func (x *extractor) frame(key string) bool {
	ep0 := x.eps[key]
	holes := strings.Count(ep0.URL, unknown)
	if holes == 0 && ep0.Method != "" {
		return false
	}
	inner := 0
	for _, n := range x.producers[key] {
		c, ok := n.(*js.CallExpr)
		if !ok {
			return false
		}
		if x.maker[c] {
			// A call to a function making a client (Rr(cfg)) repeats what
			// its methods' body makes: it says nothing either way.
			continue
		}
		whole := false
		for _, k := range x.inst[c] {
			if k == key {
				return false
			}
			if e := x.eps[k]; e != nil && (strings.Count(e.URL, unknown) < holes || ep0.Method == "" && e.Method != "" && strings.Count(e.URL, unknown) <= holes ||
				// post(path) → send("POST", prefix + path) made at pay(id)
				// as …/invoices/{}/pay: as many holes, more of it known.
				e.Method == ep0.Method && strings.Count(e.URL, unknown) <= holes && knownLen(e.URL) > knownLen(ep0.URL) && fills(ep0.URL, e.URL)) {
				whole = true
			}
		}
		if !whole {
			return false
		}
		inner++
	}
	return inner > 0
}
