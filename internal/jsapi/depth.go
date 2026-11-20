package jsapi

import (
	"bytes"
	"fmt"
)

const maxEsbuildNesting = 400

func nestingSkipError() string {
	return fmt.Sprintf("parse: nesting over %d, esbuild skipped", maxEsbuildNesting)
}

// maxNesting scans src in O(n) time and reports the maximum bracket nesting
// depth ({, [, (, and template ${), ignoring strings, comments, and regex
// literals. When limit > 0, it stops as soon as depth exceeds limit.
func maxNesting(src []byte, limit int) (int, bool) {
	depth := 0
	maxDepth := 0
	canRegex := true
	prevDot := false
	inTemplate := false
	var tmplBraces []int

	for i := 0; i < len(src); {
		if inTemplate {
			c := src[i]
			switch {
			case c == '\\':
				i += 2
			case c == '`':
				i++
				inTemplate = false
				canRegex = false
				prevDot = false
			case c == '$' && i+1 < len(src) && src[i+1] == '{':
				depth++
				if depth > maxDepth {
					maxDepth = depth
				}
				if limit > 0 && depth > limit {
					return depth, true
				}
				tmplBraces = append(tmplBraces, depth)
				i += 2
				inTemplate = false
				canRegex = true
				prevDot = false
			default:
				i++
			}
			continue
		}

		c := src[i]
		switch c {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			i++
		case '/':
			if i+1 < len(src) && src[i+1] == '/' {
				i += 2
				if nl := bytes.IndexByte(src[i:], '\n'); nl >= 0 {
					i += nl + 1
				} else {
					return maxDepth, false
				}
				continue
			}
			if i+1 < len(src) && src[i+1] == '*' {
				i += 2
				if end := bytes.Index(src[i:], []byte("*/")); end >= 0 {
					i += end + 2
				} else {
					return maxDepth, false
				}
				continue
			}
			if canRegex {
				i = skipRegexLiteral(src, i+1)
				canRegex = false
				prevDot = false
				continue
			}
			canRegex = true
			prevDot = false
			i++
		case '\'', '"':
			i = skipStringLiteral(src, i+1, c)
			canRegex = false
			prevDot = false
		case '`':
			i++
			inTemplate = true
		case '(', '[', '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			if limit > 0 && depth > limit {
				return depth, true
			}
			canRegex = true
			prevDot = false
			i++
		case ')', ']', '}':
			if c == '}' && len(tmplBraces) > 0 && tmplBraces[len(tmplBraces)-1] == depth {
				tmplBraces = tmplBraces[:len(tmplBraces)-1]
				depth--
				i++
				inTemplate = true
				continue
			}
			if depth > 0 {
				depth--
			}
			canRegex = c == '}'
			prevDot = false
			i++
		case '.', '+', '-':
			if (c == '+' || c == '-') && i+1 < len(src) && src[i+1] == c {
				canRegex = false
				prevDot = false
				i += 2
				continue
			}
			prevDot = c == '.'
			canRegex = c != '.'
			i++
		default:
			if isDepthIdentByte(c) {
				start := i
				i++
				for i < len(src) && isDepthIdentByte(src[i]) {
					i++
				}
				canRegex = !prevDot && isRegexPrefixKeyword(src[start:i])
				prevDot = false
				continue
			}
			canRegex = true
			prevDot = false
			i++
		}
	}
	return maxDepth, false
}

func skipStringLiteral(src []byte, i int, quote byte) int {
	for i < len(src) {
		switch src[i] {
		case '\\':
			i += 2
		case quote, '\n', '\r':
			return i + 1
		default:
			i++
		}
	}
	return i
}

func skipRegexLiteral(src []byte, i int) int {
	inClass := false
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\\':
			if i+1 < len(src) && src[i+1] != '\n' && src[i+1] != '\r' {
				i += 2
			} else {
				i++
			}
		case c == '\n' || c == '\r':
			return i
		case c == '[':
			inClass = true
			i++
		case c == ']':
			inClass = false
			i++
		case c == '/' && !inClass:
			i++
			for i < len(src) && ((src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z')) {
				i++
			}
			return i
		default:
			i++
		}
	}
	return i
}

func isDepthIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' || c >= 0x80
}

func isRegexPrefixKeyword(w []byte) bool {
	switch string(w) {
	case "return", "case", "throw", "typeof", "void", "delete", "in", "instanceof", "new", "yield", "await", "of", "else", "do":
		return true
	}
	return false
}
