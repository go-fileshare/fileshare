// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The people are replaced while the protocols read them -- see reload.go --
// so the field is read only through the accessors that take its lock. A
// direct read compiles, passes every test that does not reload at the same
// moment, and races: one came back with a rebase, from a branch written
// before the lock existed. So the source is asked, not the race detector.
func TestWhoIsReadOnlyThroughItsAccessors(t *testing.T) {
	allowed := []string{"person", "people", "setPeople", "open"}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	var found, checked int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// share.who() is a method, and is called; the field is not.
			called := map[*ast.SelectorExpr]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
						called[sel] = true
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "who" || called[sel] {
					return true
				}
				checked++
				if slices.Contains(allowed, fn.Name.Name) {
					return true
				}
				found++
				t.Errorf("%s: %s reads the who field directly; use person or people",
					fset.Position(sel.Pos()), fn.Name.Name)
				return true
			})
		}
	}
	if checked == 0 {
		// The control: a scan that finds nothing to check passes forever.
		t.Fatal("found no access to who at all; the scan is not looking")
	}
}
