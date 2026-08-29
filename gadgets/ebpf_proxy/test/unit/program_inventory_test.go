// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Inspektor Gadget authors

package ebpfproxy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"testing"
)

func TestUprobeSymbolValidationAllowsRustLegacyMangling(t *testing.T) {
	dir := gadgetDir(t)
	source, err := os.ReadFile(filepath.Join(dir, "go", "program.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"func validUprobeSymbolChar(b byte) bool",
		"validSymbolChar(b) || b == '$'",
		"if !validUprobeSymbolChar(symbol[i])",
	} {
		if !regexp.MustCompile(regexp.QuoteMeta(required)).MatchString(text) {
			t.Fatalf("uprobe Rust-symbol validation is missing %q", required)
		}
	}
}

func gadgetDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestAllCompiledProgramsAreCapabilityControlled(t *testing.T) {
	dir := gadgetDir(t)
	source, err := os.ReadFile(filepath.Join(dir, "program.bpf.c"))
	if err != nil {
		t.Fatal(err)
	}
	goFile, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, "go", "program.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	constants := map[string]string{}
	slices := map[string][]string{}
	var basePrograms, enrichedFamilies []string

	for _, decl := range goFile.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok || len(valueSpec.Names) != 1 || len(valueSpec.Values) != 1 {
				continue
			}
			name := valueSpec.Names[0].Name
			if gen.Tok == token.CONST {
				if lit, ok := valueSpec.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					constants[name], err = strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
				}
				continue
			}
			if gen.Tok != token.VAR {
				continue
			}
			switch value := valueSpec.Values[0].(type) {
			case *ast.CompositeLit:
				if name == "enrichedFamilies" {
					for _, element := range value.Elts {
						enrichedFamilies = append(enrichedFamilies, element.(*ast.Ident).Name)
					}
					continue
				}
				for _, element := range value.Elts {
					lit, ok := element.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					item, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					slices[name] = append(slices[name], item)
				}
			case *ast.CallExpr:
				if name != "allPrograms" || len(value.Args) != 2 {
					continue
				}
				base := value.Args[0].(*ast.CompositeLit)
				for _, element := range base.Elts {
					ident := element.(*ast.Ident)
					basePrograms = append(basePrograms, constants[ident.Name])
				}
				basePrograms = append(basePrograms, slices[value.Args[1].(*ast.Ident).Name]...)
			}
		}
	}

	controlled := map[string]struct{}{}
	var duplicates []string
	for _, program := range basePrograms {
		controlled[program] = struct{}{}
	}
	for _, family := range enrichedFamilies {
		for _, program := range slices[family] {
			if _, exists := controlled[program]; exists {
				duplicates = append(duplicates, program)
			}
			controlled[program] = struct{}{}
		}
	}

	secProgram := regexp.MustCompile(`SEC\("([^"]+)"\)\s*(?:int|long)\s+(?:(?:BPF_[A-Z0-9_]+)\s*\(\s*)?([A-Za-z_][A-Za-z0-9_]*)`)
	compiled := map[string]struct{}{}
	for _, match := range secProgram.FindAllStringSubmatch(string(source), -1) {
		if match[1] != "license" && match[1] != ".maps" {
			compiled[match[2]] = struct{}{}
		}
	}

	var uncontrolled, unknown []string
	for program := range compiled {
		if _, exists := controlled[program]; !exists {
			uncontrolled = append(uncontrolled, program)
		}
	}
	for program := range controlled {
		if _, exists := compiled[program]; !exists {
			unknown = append(unknown, program)
		}
	}
	sort.Strings(duplicates)
	sort.Strings(uncontrolled)
	sort.Strings(unknown)
	if len(duplicates) != 0 || len(uncontrolled) != 0 || len(unknown) != 0 {
		t.Fatalf("capability inventory mismatch: duplicates=%v uncontrolled=%v unknown=%v",
			duplicates, uncontrolled, unknown)
	}
}
