// Copyright 2026 The Inspektor Gadget authors
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
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// loadDebugSymbols resolves FUNC symbols in a stripped ELF binary by reading
// them from a separate debug-info file located via the build-ID stored in the
// binary's .note.gnu.build-id section.
//
// Looked up at: /usr/lib/debug/.build-id/<aa>/<bbbb...>.debug
//
// The returned map is keyed by symbol name and contains the file offset within
// the original (stripped) binary, suitable for link.UprobeOptions.Address.
//
// This is the standard layout shipped by Debian/Ubuntu *-dbgsym packages
// (e.g. openssh-server-dbgsym for /usr/sbin/sshd) and by Fedora debuginfo
// RPMs.
func loadDebugSymbols(binaryPath string) (map[string]uint64, error) {
	f, err := os.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", binaryPath, err)
	}
	defer f.Close()
	bin, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("parsing ELF %q: %w", binaryPath, err)
	}
	defer bin.Close()

	buildID := readBuildID(bin)
	if buildID == "" {
		return nil, fmt.Errorf("no build-id in %q", binaryPath)
	}

	candidate := filepath.Join("/usr/lib/debug/.build-id",
		buildID[:2], buildID[2:]+".debug")
	df, err := os.Open(candidate)
	if err != nil {
		return nil, fmt.Errorf("opening debug file %q: %w", candidate, err)
	}
	defer df.Close()
	debug, err := elf.NewFile(df)
	if err != nil {
		return nil, fmt.Errorf("parsing debug ELF %q: %w", candidate, err)
	}
	defer debug.Close()

	syms, err := debug.Symbols()
	if err != nil {
		return nil, fmt.Errorf("reading symbols from %q: %w", candidate, err)
	}

	out := make(map[string]uint64, len(syms))
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 {
			continue
		}
		for _, p := range bin.Progs {
			if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
				continue
			}
			if s.Value >= p.Vaddr && s.Value < p.Vaddr+p.Memsz {
				out[s.Name] = s.Value - p.Vaddr + p.Off
				break
			}
		}
	}
	return out, nil
}

// readBuildID returns the hex-encoded NT_GNU_BUILD_ID note from an ELF file,
// or "" if the section is missing or malformed.
func readBuildID(f *elf.File) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil || len(data) < 16 {
		return ""
	}
	namesz := binary.LittleEndian.Uint32(data[0:4])
	descsz := binary.LittleEndian.Uint32(data[4:8])
	nameEnd := 12 + int((namesz+3)&^3)
	if nameEnd+int(descsz) > len(data) {
		return ""
	}
	return hex.EncodeToString(data[nameEnd : nameEnd+int(descsz)])
}
