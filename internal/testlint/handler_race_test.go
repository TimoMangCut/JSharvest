// Package testlint holds repository-wide checks on the test code itself.
package testlint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestNoUnsyncedWritesInHandlers fails on a test HTTP handler that writes a
// variable captured from its enclosing test without a lock (round 37.1, E):
// net/http serves each request on its own goroutine, so `hits++` in a
// handler races as soon as the code under test sends two requests at once,
// and the crawl and verify now do. Use sync/atomic, or hold a mutex in the
// handler (a closure that calls .Lock() is trusted).
func TestNoUnsyncedWritesInHandlers(t *testing.T) {
	root := repoRoot(t)
	var found []string
	for _, dir := range []string{"internal", "cmd", "testbed"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			found = append(found, scanFile(t, root, path)...)
			return nil
		})
	}
	sort.Strings(found)
	for _, f := range found {
		t.Error(f)
	}
}

func repoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func scanFile(t *testing.T, root, path string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	rel, _ := filepath.Rel(root, path)
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isHandlerCall(call) {
			return true
		}
		for _, arg := range call.Args {
			lit := handlerLit(arg)
			if lit == nil || callsLock(lit.Body) {
				continue
			}
			for _, w := range capturedWrites(lit) {
				out = append(out, fmt.Sprintf("%s:%d: handler writes captured %q without a lock: use sync/atomic or a mutex",
					rel, fset.Position(w.Pos()).Line, w.Name))
			}
		}
		return true
	})
	return out
}

// isHandlerCall: http.HandlerFunc(f), mux.HandleFunc(p, f), http.HandleFunc(p, f).
func isHandlerCall(c *ast.CallExpr) bool {
	switch fn := c.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name == "HandlerFunc" || fn.Sel.Name == "HandleFunc"
	case *ast.Ident:
		return fn.Name == "HandlerFunc"
	}
	return false
}

// handlerLit is the func literal of a handler argument, if it is one.
func handlerLit(e ast.Expr) *ast.FuncLit {
	lit, ok := e.(*ast.FuncLit)
	if !ok || lit.Type.Params == nil || len(lit.Type.Params.List) == 0 {
		return nil
	}
	return lit
}

func callsLock(body *ast.BlockStmt) bool {
	locked := false
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Lock" {
				locked = true
			}
		}
		return !locked
	})
	return locked
}

func rootIdent(e ast.Expr) *ast.Ident {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return x
		case *ast.IndexExpr:
			e = x.X
		case *ast.SelectorExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return nil
		}
	}
}

// capturedWrites are the identifiers a literal writes (x++, x += …, x = …,
// m[k] = v, s[i]++, obj.f = v, *p = v, delete(m, k)) that it does not declare
// itself: variables of the enclosing test.
func capturedWrites(lit *ast.FuncLit) []*ast.Ident {
	local := map[string]bool{}
	for _, fl := range lit.Type.Params.List {
		for _, n := range fl.Names {
			local[n.Name] = true
		}
	}
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if s.Tok == token.DEFINE {
				for _, l := range s.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						local[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range s.Names {
				local[id.Name] = true
			}
		case *ast.RangeStmt:
			if s.Tok == token.DEFINE {
				for _, e := range []ast.Expr{s.Key, s.Value} {
					if id, ok := e.(*ast.Ident); ok {
						local[id.Name] = true
					}
				}
			}
		case *ast.FuncLit:
			if s.Type.Params != nil {
				for _, fl := range s.Type.Params.List {
					for _, n := range fl.Names {
						local[n.Name] = true
					}
				}
			}
		}
		return true
	})
	var out []*ast.Ident
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.IncDecStmt:
			if id := rootIdent(s.X); id != nil && id.Name != "_" && !local[id.Name] {
				out = append(out, id)
			}
		case *ast.AssignStmt:
			if s.Tok == token.DEFINE {
				return true
			}
			for _, l := range s.Lhs {
				if id := rootIdent(l); id != nil && id.Name != "_" && !local[id.Name] {
					out = append(out, id)
				}
			}
		case *ast.CallExpr:
			if fn, ok := s.Fun.(*ast.Ident); ok && fn.Name == "delete" && len(s.Args) >= 1 {
				if id := rootIdent(s.Args[0]); id != nil && id.Name != "_" && !local[id.Name] {
					out = append(out, id)
				}
			}
		}
		return true
	})
	return out
}

func TestHandlerLintFixtures(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		file    string
		wantHit bool
	}{
		{"map_unlocked.go", true},
		{"map_locked.go", false},
		{"rlock_write.go", true},
		{"atomic_safe.go", false},
	}
	for _, tc := range cases {
		path := filepath.Join(root, "internal", "testlint", "testdata", tc.file)
		got := scanFile(t, root, path)
		if (len(got) > 0) != tc.wantHit {
			t.Errorf("%s: got %v, wantHit=%v", tc.file, got, tc.wantHit)
		}
	}
}
