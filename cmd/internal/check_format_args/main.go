// check_format_args reports arguments passed to sing's format.ToString-based
// variadic APIs (loggers, E.New / E.Cause / E.Extend, F.ToString) whose type
// makes ToString panic "unknown value": the compiler accepts any value, so a
// slice or struct argument only fails when that line runs.
//
// PANIC marks an argument that always panics; DYNAMIC marks an interface or
// type parameter whose concrete type is only known at run time. It is its own
// module so the main module does not depend on golang.org/x/tools:
//
//	cd cmd/internal/check_format_args && go build -o /tmp/check_format_args .
//	cd ../../.. && TAGS=with_quic,with_utls,... /tmp/check_format_args ./...
//
// Run it per GOOS; the exit status is 1 when a PANIC argument is found.
package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

func main() {
	cfg := &packages.Config{
		Mode:       packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports,
		Tests:      true,
		BuildFlags: []string{"-tags", os.Getenv("TAGS")},
	}
	pkgs, err := packages.Load(cfg, os.Args[1:]...)
	if err != nil {
		panic(err)
	}
	seen := map[string]bool{}
	var out []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || call.Ellipsis.IsValid() {
					return true
				}
				sig, ok := pkg.TypesInfo.TypeOf(call.Fun).(*types.Signature)
				if !ok || !sig.Variadic() || !isTarget(pkg.TypesInfo, call) {
					return true
				}
				params := sig.Params()
				last := params.At(params.Len() - 1).Type().(*types.Slice).Elem()
				if iface, ok := last.Underlying().(*types.Interface); !ok || !iface.Empty() {
					return true
				}
				for i := params.Len() - 1; i < len(call.Args); i++ {
					arg := call.Args[i]
					tv := pkg.TypesInfo.Types[arg]
					if verdict := check(tv); verdict != "" {
						pos := pkg.Fset.Position(arg.Pos())
						line := fmt.Sprintf("%s:%d:%d: %s: %s", pos.Filename, pos.Line, pos.Column, verdict, types.TypeString(tv.Type, nil))
						if !seen[line] {
							seen[line] = true
							out = append(out, line)
						}
					}
				}
				return true
			})
		}
	}
	sort.Strings(out)
	failed := false
	for _, line := range out {
		fmt.Println(line)
		failed = failed || strings.Contains(line, ": PANIC: ")
	}
	if failed {
		os.Exit(1)
	}
}

// isTarget reports whether the call formats its variadic args with ToString.
func isTarget(info *types.Info, call *ast.CallExpr) bool {
	var obj types.Object
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		obj = info.Uses[fun.Sel]
	case *ast.Ident:
		obj = info.Uses[fun]
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	path := fn.Pkg().Path()
	name := fn.Name()
	switch {
	case strings.HasSuffix(path, "sing/common/format"):
		return name == "ToString"
	case strings.HasSuffix(path, "sing/common/exceptions"):
		return name == "New" || name == "Cause" || name == "Extend"
	case strings.HasSuffix(path, "sing/common/logger"), strings.HasSuffix(path, "sing-box/log"):
		switch strings.TrimSuffix(name, "Context") {
		case "Trace", "Debug", "Info", "Warn", "Error", "Fatal", "Panic":
			return true
		}
	}
	return false
}

var errorType = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

func hasString(t types.Type) bool {
	for _, tt := range []types.Type{t} {
		ms := types.NewMethodSet(tt)
		for i := 0; i < ms.Len(); i++ {
			m := ms.At(i).Obj().(*types.Func)
			sig := m.Type().(*types.Signature)
			if m.Name() == "String" && sig.Params().Len() == 0 && sig.Results().Len() == 1 {
				if b, ok := sig.Results().At(0).Type().(*types.Basic); ok && b.Kind() == types.String {
					return true
				}
			}
		}
	}
	return false
}

func check(tv types.TypeAndValue) string {
	t := tv.Type
	if t == nil || tv.IsNil() {
		return ""
	}
	if b, ok := t.(*types.Basic); ok && b.Info()&types.IsUntyped != 0 {
		t = types.Default(t)
	}
	t = types.Unalias(t)
	if types.Implements(t, errorType) || hasString(t) {
		return ""
	}
	switch tt := t.(type) {
	case *types.Basic:
		switch tt.Kind() {
		case types.String, types.Bool, types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64,
			types.Int, types.Int8, types.Int16, types.Int32, types.Int64, types.Float32, types.Float64, types.Uintptr:
			return ""
		}
		return "PANIC"
	case *types.Interface:
		return "DYNAMIC"
	case *types.TypeParam:
		return "DYNAMIC"
	}
	if _, ok := t.Underlying().(*types.Interface); ok {
		return "DYNAMIC"
	}
	return "PANIC"
}
