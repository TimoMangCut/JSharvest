// Package mdsafe escapes untrusted target strings for CommonMark/GFM reports
// and strips C0/C1 terminal control sequences from status logs.
package mdsafe

import (
	"strings"
	"unicode"
)

// StripControls removes C0 (< 0x20 except \t and \n), DEL (0x7f), and C1
// (U+0080..U+009F, such as CSI \u009b) control characters.
func StripControls(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' && r != '\n' {
			return -1
		}
		return r
	}, s)
}

func flattenNewlines(s, repl string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = StripControls(s)
	return strings.ReplaceAll(s, "\n", repl)
}

// InlineCode wraps s in a CommonMark code span outside tables, replacing line
// breaks with ␤ and choosing a backtick fence longer than any run in s.
func InlineCode(s string) string {
	return codeSpan(s, false)
}

// TableCode wraps s in a GFM table-safe code span: pipes are escaped as \|
// because GFM splits table cells before parsing backtick code spans.
func TableCode(s string) string {
	return codeSpan(s, true)
}

func codeSpan(s string, inTable bool) string {
	s = flattenNewlines(s, "␤")
	s = strings.ReplaceAll(s, "\t", " ")
	if inTable {
		s = escapeTableCodePipes(s)
	}
	if s == "" {
		return "` `"
	}
	maxRun, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			cur++
			if cur > maxRun {
				maxRun = cur
			}
		} else {
			cur = 0
		}
	}
	fence := strings.Repeat("`", maxRun+1)
	if s[0] == '`' || s[len(s)-1] == '`' || ((s[0] == ' ' || s[len(s)-1] == ' ') && strings.Trim(s, " ") != "") {
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}

func escapeTableCodePipes(s string) string {
	if !strings.ContainsRune(s, '|') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	bs := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			bs++
			continue
		}
		if c == '|' {
			for range 2*bs + 1 {
				b.WriteByte('\\')
			}
			b.WriteByte('|')
			bs = 0
			continue
		}
		for range bs {
			b.WriteByte('\\')
		}
		bs = 0
		b.WriteByte(c)
	}
	for range bs {
		b.WriteByte('\\')
	}
	return b.String()
}

var (
	inlineTextEscaper = strings.NewReplacer(
		`\`, `\\`,
		`<`, `&lt;`,
		`>`, `&gt;`,
		`[`, `\[`,
		`]`, `\]`,
		"`", "\\`",
	)
	tableTextEscaper = strings.NewReplacer(
		`\`, `\\`,
		`|`, `\|`,
		`<`, `&lt;`,
		`>`, `&gt;`,
		`[`, `\[`,
		`]`, `\]`,
		"`", "\\`",
	)
)

// InlineText sanitizes untrusted text placed inline outside tables (headings,
// bullet items, blockquotes): strips controls, collapses newlines, and escapes
// HTML/link/code delimiters.
func InlineText(s string) string {
	s = flattenNewlines(s, " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return inlineTextEscaper.Replace(s)
}

// TableText sanitizes untrusted text placed inside a GFM table cell.
func TableText(s string) string {
	s = flattenNewlines(s, " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return tableTextEscaper.Replace(s)
}
