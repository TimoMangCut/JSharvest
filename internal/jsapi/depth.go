package jsapi

import (
	"fmt"
)

const (
	maxEsbuildNesting  = 400
	maxEsbuildChain    = 2_500
	maxRawBracketDepth = 4_000
	maxRawExprChain    = 16_000
)

func nestingSkipError() string {
	return fmt.Sprintf("parse: nesting over %d, esbuild skipped", maxEsbuildNesting)
}

// maxNesting scans src in O(n) time using two layers:
//  1. A lexer-aware pass tracking bracket nesting ({, [, (, template ${) and
//     per-scope expression/JSX/label chains, ignoring strings, comments, and
//     regex literals (while still bounding unescaped brackets in regexes).
//  2. A zero-lexer hard fuse running on every byte so lexer desync tricks
//     (e.g. JSX text apostrophes) cannot hide deep brackets or expression chains.
//
// When limit > 0, it stops as soon as any threshold is exceeded.
func maxNesting(src []byte, limit int) (int, bool) {
	depth := 0
	maxDepth := 0
	canRegex := true
	prevDot := false
	lineStart := true
	inTemplate := false
	var tmplBraces []int
	chainStack := make([]int, 1, 32)
	var raw rawFuse
	raw.chainStack = make([]int, 1, 32)

	i := 0
	if len(src) >= 2 && src[0] == '#' && src[1] == '!' {
		if raw.feedSlice(src[:2], limit > 0) {
			return depth, true
		}
		var over bool
		i, over = skipLineComment(src, 2, &raw, limit > 0)
		if over {
			return depth, true
		}
		lineStart = true
	}

	bumpChain := func() bool {
		chainStack[len(chainStack)-1]++
		return limit > 0 && depth+chainStack[len(chainStack)-1] > maxEsbuildChain
	}

	for i < len(src) {
		if inTemplate {
			c := src[i]
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			switch {
			case c == '\\':
				if i+1 < len(src) {
					if raw.feed(src[i+1], limit > 0) {
						return depth, true
					}
					i += 2
				} else {
					i++
				}
			case c == '`':
				i++
				inTemplate = false
				canRegex = false
				prevDot = false
				lineStart = false
			case c == '$' && i+1 < len(src) && src[i+1] == '{':
				if raw.feed('{', limit > 0) {
					return depth, true
				}
				depth++
				if depth > maxDepth {
					maxDepth = depth
				}
				if limit > 0 && depth > limit {
					return depth, true
				}
				chainStack = append(chainStack, 0)
				tmplBraces = append(tmplBraces, depth)
				i += 2
				inTemplate = false
				canRegex = true
				prevDot = false
				lineStart = false
			default:
				i++
			}
			continue
		}

		c := src[i]
		switch c {
		case ' ', '\t', '\v', '\f':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			i++
		case '\n', '\r':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			lineStart = true
			i++
		case 0xe2:
			if i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] == 0xa8 || src[i+2] == 0xa9) {
				if raw.feedSlice(src[i:i+3], limit > 0) {
					return depth, true
				}
				lineStart = true
				i += 3
				continue
			}
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			start := i
			i++
			for i < len(src) && isDepthIdentByte(src[i]) {
				if raw.feed(src[i], limit > 0) {
					return depth, true
				}
				i++
			}
			w := src[start:i]
			if !prevDot && isChainPrefixKeyword(w) {
				if bumpChain() {
					return depth, true
				}
			}
			canRegex = !prevDot && isRegexPrefixKeyword(w)
			prevDot = false
			lineStart = false
		case '/':
			if i+1 < len(src) && src[i+1] == '/' {
				if raw.feedSlice(src[i:i+2], limit > 0) {
					return depth, true
				}
				var over bool
				i, over = skipLineComment(src, i+2, &raw, limit > 0)
				if over {
					return depth, true
				}
				lineStart = true
				continue
			}
			if i+1 < len(src) && src[i+1] == '*' {
				if raw.feedSlice(src[i:i+2], limit > 0) {
					return depth, true
				}
				var crossedNL, over bool
				i, crossedNL, over = skipBlockComment(src, i+2, &raw, limit > 0)
				if over {
					return depth, true
				}
				if crossedNL {
					lineStart = true
				}
				continue
			}
			if raw.feed('/', limit > 0) {
				return depth, true
			}
			if canRegex {
				var over bool
				i, over = skipRegexLiteral(src, i+1, depth, limit, &raw)
				if over {
					return depth, true
				}
				canRegex = false
				prevDot = false
				lineStart = false
				continue
			}
			canRegex = true
			prevDot = false
			lineStart = false
			i++
		case '\'', '"':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			var over bool
			i, over = skipStringLiteral(src, i+1, c, &raw, limit > 0)
			if over {
				return depth, true
			}
			canRegex = false
			prevDot = false
			lineStart = false
		case '`':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			i++
			inTemplate = true
			lineStart = false
		case '(', '[', '{':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if c != '{' && !canRegex {
				if bumpChain() {
					return depth, true
				}
			}
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			if limit > 0 && depth > limit {
				return depth, true
			}
			chainStack = append(chainStack, 0)
			canRegex = true
			prevDot = false
			lineStart = false
			i++
		case ')', ']', '}':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if c == '}' && len(tmplBraces) > 0 && tmplBraces[len(tmplBraces)-1] == depth {
				tmplBraces = tmplBraces[:len(tmplBraces)-1]
				depth--
				if len(chainStack) > 1 {
					chainStack = chainStack[:len(chainStack)-1]
				}
				i++
				inTemplate = true
				lineStart = false
				continue
			}
			if depth > 0 {
				depth--
			}
			if len(chainStack) > 1 {
				chainStack = chainStack[:len(chainStack)-1]
			}
			if c == '}' {
				chainStack[len(chainStack)-1] = 0
			}
			canRegex = false
			prevDot = false
			lineStart = false
			i++
		case ';', ',':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			chainStack[len(chainStack)-1] = 0
			canRegex = true
			prevDot = false
			lineStart = false
			i++
		case '!':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if i+1 < len(src) && src[i+1] == '=' {
				if raw.feed('=', limit > 0) {
					return depth, true
				}
				i += 2
				if i < len(src) && src[i] == '=' {
					if raw.feed('=', limit > 0) {
						return depth, true
					}
					i++
				}
			} else {
				i++
				if bumpChain() {
					return depth, true
				}
			}
			canRegex = true
			prevDot = false
			lineStart = false
		case '~', '?':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			i++
			if bumpChain() {
				return depth, true
			}
			canRegex = true
			prevDot = false
			lineStart = false
		case ':':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			i++
			if bumpChain() {
				return depth, true
			}
			canRegex = true
			prevDot = false
			lineStart = false
		case '=':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if i+1 < len(src) && src[i+1] == '=' {
				if raw.feed('=', limit > 0) {
					return depth, true
				}
				i += 2
				if i < len(src) && src[i] == '=' {
					if raw.feed('=', limit > 0) {
						return depth, true
					}
					i++
				}
			} else if i+1 < len(src) && src[i+1] == '>' {
				if raw.feed('>', limit > 0) {
					return depth, true
				}
				i += 2
				if bumpChain() {
					return depth, true
				}
			} else {
				i++
				if bumpChain() {
					return depth, true
				}
			}
			canRegex = true
			prevDot = false
			lineStart = false
		case '<':
			if i+3 < len(src) && src[i+1] == '!' && src[i+2] == '-' && src[i+3] == '-' {
				if raw.feedSlice(src[i:i+4], limit > 0) {
					return depth, true
				}
				var over bool
				i, over = skipLineComment(src, i+4, &raw, limit > 0)
				if over {
					return depth, true
				}
				lineStart = true
				continue
			}
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if i+1 < len(src) && src[i+1] == '=' {
				if raw.feed('=', limit > 0) {
					return depth, true
				}
				i += 2
				canRegex = true
			} else if i+1 < len(src) && src[i+1] == '/' {
				if raw.feed('/', limit > 0) {
					return depth, true
				}
				i += 2
				canRegex = false
			} else {
				i++
				if bumpChain() {
					return depth, true
				}
				canRegex = true
			}
			prevDot = false
			lineStart = false
		case '>':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if i+1 < len(src) && src[i+1] == '=' {
				if raw.feed('=', limit > 0) {
					return depth, true
				}
				i += 2
			} else {
				i++
			}
			canRegex = true
			prevDot = false
			lineStart = false
		case '*':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if i+1 < len(src) && src[i+1] == '*' {
				if raw.feed('*', limit > 0) {
					return depth, true
				}
				i += 2
				if bumpChain() {
					return depth, true
				}
			} else {
				i++
			}
			canRegex = true
			prevDot = false
			lineStart = false
		case '.':
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if i+2 < len(src) && src[i+1] == '.' && src[i+2] == '.' {
				if raw.feedSlice(src[i+1:i+3], limit > 0) {
					return depth, true
				}
				i += 3
				prevDot = false
				canRegex = true
				lineStart = false
				continue
			}
			i++
			if bumpChain() {
				return depth, true
			}
			prevDot = true
			canRegex = false
			lineStart = false
		case '+', '-':
			if c == '-' && lineStart && i+2 < len(src) && src[i+1] == '-' && src[i+2] == '>' {
				if raw.feedSlice(src[i:i+3], limit > 0) {
					return depth, true
				}
				var over bool
				i, over = skipLineComment(src, i+3, &raw, limit > 0)
				if over {
					return depth, true
				}
				lineStart = true
				continue
			}
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if i+1 < len(src) && src[i+1] == c {
				if raw.feed(c, limit > 0) {
					return depth, true
				}
				canRegex = false
				prevDot = false
				lineStart = false
				i += 2
				continue
			}
			if canRegex {
				if bumpChain() {
					return depth, true
				}
			}
			canRegex = true
			prevDot = false
			lineStart = false
			i++
		default:
			if raw.feed(c, limit > 0) {
				return depth, true
			}
			if isDepthIdentByte(c) {
				start := i
				i++
				for i < len(src) && isDepthIdentByte(src[i]) {
					if raw.feed(src[i], limit > 0) {
						return depth, true
					}
					i++
				}
				w := src[start:i]
				if !prevDot && isChainPrefixKeyword(w) {
					if bumpChain() {
						return depth, true
					}
				}
				canRegex = !prevDot && isRegexPrefixKeyword(w)
				prevDot = false
				lineStart = false
				continue
			}
			canRegex = true
			prevDot = false
			lineStart = false
			i++
		}
	}
	return maxDepth, false
}

// rawFuse tracks zero-lexer bracket depth and expression chain length on every
// byte so lexer-desync inputs cannot bypass maxNesting.
type rawFuse struct {
	depth       int
	chainStack  []int
	inLineComm  bool
	inBlockComm bool
	inQuote     byte
	quoteEsc    bool
	prevSlash   bool
	prevStar    bool
	u2028State  uint8
	ident       [8]byte
	identLen    int
	inIdentSkip bool
}

func (r *rawFuse) bumpChain(checkLimit bool) bool {
	top := len(r.chainStack) - 1
	r.chainStack[top]++
	return checkLimit && r.chainStack[top] > maxRawExprChain
}

func (r *rawFuse) flushIdent(checkLimit bool) bool {
	if r.identLen > 0 && !r.inIdentSkip {
		switch string(r.ident[:r.identLen]) {
		case "new", "typeof", "void", "delete", "await", "yield", "else":
			if r.bumpChain(checkLimit) {
				r.identLen = 0
				r.inIdentSkip = false
				return true
			}
		}
	}
	r.identLen = 0
	r.inIdentSkip = false
	return false
}

func (r *rawFuse) feed(b byte, checkLimit bool) bool {
	switch b {
	case '(', '[', '{':
		r.depth++
		if checkLimit && r.depth > maxRawBracketDepth {
			return true
		}
	case ')', ']', '}':
		if r.depth > 0 {
			r.depth--
		}
	}

	if r.inLineComm {
		switch b {
		case '\n', '\r':
			r.inLineComm = false
			r.u2028State = 0
		case 0xe2:
			r.u2028State = 1
		case 0x80:
			if r.u2028State == 1 {
				r.u2028State = 2
			} else {
				r.u2028State = 0
			}
		case 0xa8, 0xa9:
			if r.u2028State == 2 {
				r.inLineComm = false
			}
			r.u2028State = 0
		default:
			r.u2028State = 0
		}
		return false
	}
	if r.inBlockComm {
		if r.prevStar && b == '/' {
			r.inBlockComm = false
			r.prevStar = false
		} else {
			r.prevStar = b == '*'
		}
		return false
	}
	if r.inQuote != 0 {
		if b == '\n' || b == '\r' {
			r.inQuote = 0
			r.quoteEsc = false
			return false
		}
		if r.quoteEsc {
			r.quoteEsc = false
			return false
		}
		if b == '\\' {
			r.quoteEsc = true
			return false
		}
		if b == r.inQuote {
			r.inQuote = 0
		}
		return false
	}

	if r.prevSlash {
		r.prevSlash = false
		if b == '/' {
			r.inLineComm = true
			r.u2028State = 0
			r.identLen = 0
			r.inIdentSkip = false
			return false
		}
		if b == '*' {
			r.inBlockComm = true
			r.prevStar = false
			r.identLen = 0
			r.inIdentSkip = false
			return false
		}
	}

	if isDepthIdentByte(b) {
		if !r.inIdentSkip {
			if r.identLen < len(r.ident) {
				r.ident[r.identLen] = b
				r.identLen++
			} else {
				r.inIdentSkip = true
			}
		}
		return false
	}
	if r.flushIdent(checkLimit) {
		return true
	}

	switch b {
	case '/':
		r.prevSlash = true
	case '"', '\'':
		r.inQuote = b
		r.quoteEsc = false
	case '(', '[':
		if r.bumpChain(checkLimit) {
			return true
		}
		r.chainStack = append(r.chainStack, 0)
	case ')', ']':
		if len(r.chainStack) > 1 {
			r.chainStack = r.chainStack[:len(r.chainStack)-1]
		}
	case '{':
		r.chainStack[len(r.chainStack)-1] = 0
		r.chainStack = append(r.chainStack, 0)
	case '}':
		if len(r.chainStack) > 1 {
			r.chainStack = r.chainStack[:len(r.chainStack)-1]
		}
		r.chainStack[len(r.chainStack)-1] = 0
	case ';', ',':
		r.chainStack[len(r.chainStack)-1] = 0
	case '!', '~', '?', ':', '=', '.', '<', '*', '+', '-':
		if r.bumpChain(checkLimit) {
			return true
		}
	}
	return false
}

func (r *rawFuse) feedSlice(s []byte, checkLimit bool) bool {
	for _, b := range s {
		if r.feed(b, checkLimit) {
			return true
		}
	}
	return false
}

func skipLineComment(src []byte, i int, raw *rawFuse, checkLimit bool) (int, bool) {
	for i < len(src) {
		c := src[i]
		if raw.feed(c, checkLimit) {
			return i, true
		}
		switch c {
		case '\n':
			return i + 1, false
		case '\r':
			if i+1 < len(src) && src[i+1] == '\n' {
				if raw.feed('\n', checkLimit) {
					return i + 1, true
				}
				return i + 2, false
			}
			return i + 1, false
		case 0xe2:
			if i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] == 0xa8 || src[i+2] == 0xa9) {
				if raw.feedSlice(src[i+1:i+3], checkLimit) {
					return i, true
				}
				return i + 3, false
			}
		}
		i++
	}
	return i, false
}

func skipBlockComment(src []byte, i int, raw *rawFuse, checkLimit bool) (int, bool, bool) {
	crossedNL := false
	for i < len(src) {
		c := src[i]
		if raw.feed(c, checkLimit) {
			return i, crossedNL, true
		}
		switch c {
		case '\n', '\r':
			crossedNL = true
		case 0xe2:
			if i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] == 0xa8 || src[i+2] == 0xa9) {
				crossedNL = true
			}
		case '*':
			if i+1 < len(src) && src[i+1] == '/' {
				if raw.feed('/', checkLimit) {
					return i + 1, crossedNL, true
				}
				return i + 2, crossedNL, false
			}
		}
		i++
	}
	return i, crossedNL, false
}

func skipStringLiteral(src []byte, i int, quote byte, raw *rawFuse, checkLimit bool) (int, bool) {
	for i < len(src) {
		c := src[i]
		if raw.feed(c, checkLimit) {
			return i, true
		}
		switch c {
		case '\\':
			if i+1 < len(src) {
				if raw.feed(src[i+1], checkLimit) {
					return i + 1, true
				}
				i += 2
			} else {
				i++
			}
		case quote, '\n', '\r':
			return i + 1, false
		case 0xe2:
			if i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] == 0xa8 || src[i+2] == 0xa9) {
				if raw.feedSlice(src[i+1:i+3], checkLimit) {
					return i, true
				}
				return i + 3, false
			}
			i++
		default:
			i++
		}
	}
	return i, false
}

func skipRegexLiteral(src []byte, i, baseDepth, limit int, raw *rawFuse) (int, bool) {
	inClass := false
	regexDepth := 0
	checkLimit := limit > 0
	for i < len(src) {
		c := src[i]
		if raw.feed(c, checkLimit) {
			return i, true
		}
		switch {
		case c == '\\':
			if i+1 < len(src) && src[i+1] != '\n' && src[i+1] != '\r' {
				if raw.feed(src[i+1], checkLimit) {
					return i + 1, true
				}
				i += 2
			} else {
				i++
			}
		case c == '\n' || c == '\r':
			return i, false
		case c == 0xe2 && i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] == 0xa8 || src[i+2] == 0xa9):
			return i, false
		case c == '[':
			if !inClass {
				inClass = true
				regexDepth++
				if checkLimit && baseDepth+regexDepth > limit {
					return i, true
				}
			}
			i++
		case c == ']':
			if inClass {
				inClass = false
				if regexDepth > 0 {
					regexDepth--
				}
			}
			i++
		case c == '(' && !inClass:
			regexDepth++
			if checkLimit && baseDepth+regexDepth > limit {
				return i, true
			}
			i++
		case c == ')' && !inClass:
			if regexDepth > 0 {
				regexDepth--
			}
			i++
		case c == '/' && !inClass:
			i++
			for i < len(src) && ((src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z')) {
				if raw.feed(src[i], checkLimit) {
					return i, true
				}
				i++
			}
			return i, false
		default:
			i++
		}
	}
	return i, false
}

func isDepthIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' || c >= 0x80
}

func isChainPrefixKeyword(w []byte) bool {
	switch string(w) {
	case "new", "typeof", "void", "delete", "await", "yield", "else":
		return true
	}
	return false
}

func isRegexPrefixKeyword(w []byte) bool {
	switch string(w) {
	case "return", "case", "throw", "typeof", "void", "delete", "in", "instanceof", "new", "yield", "await", "else", "do":
		return true
	}
	return false
}
