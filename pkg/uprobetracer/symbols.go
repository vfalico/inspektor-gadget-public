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
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrBuildIDMismatch: symbols file's GNU build-id differs from target
// binary's. Fatal: silently attaching at the wrong offset would be worse.
var ErrBuildIDMismatch = errors.New("uprobetracer: symbols file build-id does not match target binary")

// ErrSymbolNotFound: symbol absent from .symtab, .debug_info and .dynsym.
var ErrSymbolNotFound = errors.New("uprobetracer: symbol not found in symbols file")

// ErrNoBuildID: file lacks .note.gnu.build-id; refuse rather than guess.
var ErrNoBuildID = errors.New("uprobetracer: missing .note.gnu.build-id")

// ResolveSymbol returns the PIE-safe file offset of symbolName, resolved
// in symbolsPath (an unstripped binary or `objcopy --only-keep-debug`
// companion) after verifying it shares a GNU build-id with targetPath.
// Lookup order: .symtab -> DWARF .debug_info -> .dynsym.
func ResolveSymbol(targetPath, symbolsPath, symbolName string) (uint64, error) {
	tID, err := readBuildID(targetPath)
	if err != nil {
		return 0, fmt.Errorf("reading build-id of target %q: %w", targetPath, err)
	}
	sID, err := readBuildID(symbolsPath)
	if err != nil {
		return 0, fmt.Errorf("reading build-id of symbols %q: %w", symbolsPath, err)
	}
	if !bytes.Equal(tID, sID) {
		return 0, ErrBuildIDMismatch
	}
	tf, err := elf.Open(targetPath)
	if err != nil {
		return 0, fmt.Errorf("opening target %q: %w", targetPath, err)
	}
	defer tf.Close()
	sf, err := elf.Open(symbolsPath)
	if err != nil {
		return 0, fmt.Errorf("opening symbols %q: %w", symbolsPath, err)
	}
	defer sf.Close()
	if va, ok := lookupSymtabVA(sf, symbolName, false); ok {
		if off, ok := vaddrToFileOff(tf, va); ok {
			return off, nil
		}
	}
	if va, ok := lookupDWARFVA(sf, symbolName); ok {
		if off, ok := vaddrToFileOff(tf, va); ok {
			return off, nil
		}
	}
	if va, ok := lookupSymtabVA(sf, symbolName, true); ok {
		if off, ok := vaddrToFileOff(tf, va); ok {
			return off, nil
		}
	}
	return 0, ErrSymbolNotFound
}

// readBuildID extracts the descriptor of a GNU build-id note. Layout
// (LE on x86_64/aarch64): namesz(4) descsz(4) type(4) name("GNU\0",4) desc.
func readBuildID(path string) ([]byte, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := f.Section(".note.gnu.build-id")
	if s == nil {
		return nil, ErrNoBuildID
	}
	data, err := s.Data()
	if err != nil {
		return nil, err
	}
	if len(data) < 16 {
		return nil, fmt.Errorf("short build-id note in %s", path)
	}
	descsz := binary.LittleEndian.Uint32(data[4:8])
	if 16+int(descsz) > len(data) {
		return nil, fmt.Errorf("truncated build-id note in %s", path)
	}
	return data[16 : 16+descsz], nil
}

// lookupSymtabVA returns the symbol's virtual address from .symtab
// (dyn=false) or .dynsym (dyn=true).
func lookupSymtabVA(f *elf.File, name string, dyn bool) (uint64, bool) {
	var syms []elf.Symbol
	var err error
	if dyn {
		syms, err = f.DynamicSymbols()
	} else {
		syms, err = f.Symbols()
	}
	if err != nil {
		return 0, false
	}
	for _, s := range syms {
		if s.Name == name && s.Section != elf.SHN_UNDEF {
			return s.Value, true
		}
	}
	return 0, false
}

// lookupDWARFVA walks DW_TAG_subprogram DIEs for DW_AT_low_pc of name.
// Required when .symtab is empty (e.g. `--only-keep-debug` output).
func lookupDWARFVA(f *elf.File, name string) (uint64, bool) {
	d, err := f.DWARF()
	if err != nil {
		return 0, false
	}
	r := d.Reader()
	for {
		ent, err := r.Next()
		if err != nil || ent == nil {
			return 0, false
		}
		if ent.Tag != dwarf.TagSubprogram {
			continue
		}
		if n, _ := ent.Val(dwarf.AttrName).(string); n != name {
			continue
		}
		if lo, ok := ent.Val(dwarf.AttrLowpc).(uint64); ok {
			return lo, true
		}
		return 0, false
	}
}

// vaddrToFileOff converts a VA to its file offset via PT_LOAD headers.
func vaddrToFileOff(f *elf.File, addr uint64) (uint64, bool) {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && addr >= p.Vaddr && addr < p.Vaddr+p.Memsz {
			return addr - p.Vaddr + p.Off, true
		}
	}
	return 0, false
}
