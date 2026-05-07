// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package uprobetracer

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const fixtureSrc = `
#include <stdio.h>
__attribute__((noinline)) void target_fn(int x) { printf("%d\n", x); }
int main(void) { target_fn(42); return 0; }
`

const fixtureSrcOther = `
#include <stdio.h>
#define NONCE 1
__attribute__((noinline)) void target_fn(int x) { printf("%d/%d\n", x, NONCE); }
int main(void) { target_fn(43); return 0; }
`

type fixture struct {
	unstripped string
	stripped   string
	dbg        string
	other      string
}

func buildFixture(t *testing.T) *fixture {
	t.Helper()
	for _, tool := range []string{"gcc", "objcopy", "strip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("toolchain missing: %s", tool)
		}
	}
	dir := t.TempDir()
	srcA := filepath.Join(dir, "a.c")
	srcB := filepath.Join(dir, "b.c")
	if err := os.WriteFile(srcA, []byte(fixtureSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcB, []byte(fixtureSrcOther), 0o644); err != nil {
		t.Fatal(err)
	}

	un := filepath.Join(dir, "target_unstripped")
	st := filepath.Join(dir, "target_stripped")
	dbg := filepath.Join(dir, "target.dbg")
	other := filepath.Join(dir, "target_other")

	mustRun := func(name string, args ...string) {
		c := exec.Command(name, args...)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	mustRun("gcc", "-O2", "-fno-inline", "-g", "-Wl,--build-id=sha1", srcA, "-o", un)
	mustRun("cp", un, st)
	mustRun("strip", "--strip-all", st)
	mustRun("objcopy", "--only-keep-debug", un, dbg)
	mustRun("gcc", "-O2", "-fno-inline", "-g", "-Wl,--build-id=sha1", srcB, "-o", other)

	return &fixture{unstripped: un, stripped: st, dbg: dbg, other: other}
}

func TestResolveSymbol_StrippedAgainstUnstripped(t *testing.T) {
	f := buildFixture(t)
	want, err := ResolveSymbol(f.unstripped, f.unstripped, "target_fn")
	if err != nil {
		t.Fatalf("baseline resolve failed: %v", err)
	}
	got, err := ResolveSymbol(f.stripped, f.unstripped, "target_fn")
	if err != nil {
		t.Fatalf("stripped+unstripped resolve failed: %v", err)
	}
	if got != want {
		t.Fatalf("offset mismatch: got=%#x want=%#x", got, want)
	}
	if got == 0 {
		t.Fatalf("offset is zero")
	}
}

func TestResolveSymbol_StrippedAgainstDbgOnly(t *testing.T) {
	f := buildFixture(t)
	want, err := ResolveSymbol(f.unstripped, f.unstripped, "target_fn")
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	got, err := ResolveSymbol(f.stripped, f.dbg, "target_fn")
	if err != nil {
		t.Fatalf(".dbg resolve failed: %v", err)
	}
	if got != want {
		t.Fatalf(".dbg offset mismatch: got=%#x want=%#x", got, want)
	}
}

func TestResolveSymbol_BuildIDMismatch(t *testing.T) {
	f := buildFixture(t)
	_, err := ResolveSymbol(f.stripped, f.other, "target_fn")
	if !errors.Is(err, ErrBuildIDMismatch) {
		t.Fatalf("expected ErrBuildIDMismatch, got %v", err)
	}
}

func TestResolveSymbol_SymbolNotFound(t *testing.T) {
	f := buildFixture(t)
	_, err := ResolveSymbol(f.stripped, f.unstripped, "nonexistent_symbol")
	if !errors.Is(err, ErrSymbolNotFound) {
		t.Fatalf("expected ErrSymbolNotFound, got %v", err)
	}
}
