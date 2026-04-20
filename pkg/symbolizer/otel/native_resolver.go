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

package otel

// Native frame resolution for OTel traces.
//
// The otel-ebpf-profiler symbolizes interpreted-language frames (Python,
// PHP, Ruby, …) directly, but for native frames (C/C++ shared libraries
// such as libcuda.so.1, libcublas.so.12, libtorch_cuda.so) it only
// captures the ELF virtual address and the FrameMapping describing the
// backing file; the FunctionName field is left empty. For CUDA-heavy
// workloads this produces stacks full of nameless frames, which makes
// flamegraphs unreadable.
//
// This file walks the backing ELF file's .dynsym and .symtab sections
// to resolve the captured address to a function name. NVIDIA ships
// stripped libraries (.symtab absent) but .dynsym is always present and
// lists the full public API surface (cuLaunchKernel, cuMemAlloc_v2,
// cublasSgemm, cuStreamSynchronize, ncclAllReduce, …). That covers the
// majority of native frames in GPU workloads.
//
// When ELF resolution fails (address between two exported symbols, or
// file unreadable), we fall back to "basename+0xoffset". When the frame
// has no backing file at all (anonymous JIT mapping), we return the
// empty string and let the caller drop the frame.

import (
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// nativeSymbolCache caches per-file sorted symbol tables across resolve
// calls. The key is the canonical host path of the ELF file.
type nativeSymbolCache struct {
	mu      sync.RWMutex
	entries map[string]*elfSymbols
}

// elfSymbols is the sorted symbol table for one ELF file.
type elfSymbols struct {
	// ok=false means the file has been tried and is not resolvable
	// (missing, unreadable, not an ELF, has no symbols). We cache the
	// negative result too, to avoid repeated open()+parse attempts.
	ok   bool
	syms []elfSym
}

type elfSym struct {
	addr uint64 // st_value
	size uint64 // st_size
	name string
}

func newNativeSymbolCache() *nativeSymbolCache {
	return &nativeSymbolCache{entries: make(map[string]*elfSymbols)}
}

// resolveNative turns one empty-name libpf.Frame into either:
//
//	a resolved function name, e.g. "cuLaunchKernel",
//	a "<basename>+0x<fileoff>" fallback if the ELF is readable but
//	    we cannot find a covering symbol,
//	"" if the frame has no backing file (anonymous/JIT) — the caller
//	    should drop it.
func (c *nativeSymbolCache) resolveNative(tgid uint32, f libpf.Frame) string {
	if !f.Mapping.Valid() {
		return ""
	}
	md := f.Mapping.Value()
	mf := md.File.Value()
	base := mf.FileName.String()
	if base == "" {
		return ""
	}
	addr := uint64(f.AddressOrLineno)
	// File offset of the instruction pointer within the backing file.
	// Start/End are file virtual addresses, FileOffset is the offset of
	// the mapping's first page inside the file.
	if addr < uint64(md.Start) {
		return fmt.Sprintf("%s+0x%x", base, addr)
	}
	fileOffset := addr - uint64(md.Start) + md.FileOffset

	// Try to find a covering symbol by scanning the ELF's symbol tables.
	path, ok := findMappedPath(tgid, base, fileOffset)
	if ok {
		if name := c.lookup(path, addr); name != "" {
			return name
		}
	}
	return fmt.Sprintf("%s+0x%x", base, fileOffset)
}

// lookup returns the nearest-covering symbol at runtimeAddr in the ELF
// file at path, or "" if no covering symbol is found.
func (c *nativeSymbolCache) lookup(path string, runtimeAddr uint64) string {
	c.mu.RLock()
	es, seen := c.entries[path]
	c.mu.RUnlock()
	if !seen {
		es = loadELFSymbols(path)
		c.mu.Lock()
		c.entries[path] = es
		c.mu.Unlock()
	}
	if !es.ok || len(es.syms) == 0 {
		return ""
	}
	// Binary search for the largest addr <= runtimeAddr.
	i := sort.Search(len(es.syms), func(i int) bool {
		return es.syms[i].addr > runtimeAddr
	})
	if i == 0 {
		return ""
	}
	s := es.syms[i-1]
	// Require the address to fall within [addr, addr+size). For
	// size==0 symbols (common for asm stubs) accept any address that
	// is no further than the next symbol.
	if s.size > 0 && runtimeAddr >= s.addr+s.size {
		return ""
	}
	return s.name
}

// loadELFSymbols opens an ELF file and extracts a sorted list of
// defined function/object symbols from .symtab (if present) and
// .dynsym. Stripped NVIDIA libraries have only .dynsym, but that
// already covers their exported API.
func loadELFSymbols(path string) *elfSymbols {
	f, err := os.Open(path)
	if err != nil {
		return &elfSymbols{}
	}
	defer f.Close()
	e, err := elf.NewFile(f)
	if err != nil {
		return &elfSymbols{}
	}
	defer e.Close()

	var syms []elfSym
	append1 := func(ss []elf.Symbol) {
		for _, s := range ss {
			if s.Value == 0 || s.Name == "" {
				continue
			}
			t := elf.ST_TYPE(s.Info)
			if t != elf.STT_FUNC && t != elf.STT_GNU_IFUNC && t != elf.STT_OBJECT {
				continue
			}
			syms = append(syms, elfSym{
				addr: s.Value,
				size: s.Size,
				name: s.Name,
			})
		}
	}
	if ss, err := e.Symbols(); err == nil {
		append1(ss)
	}
	if ss, err := e.DynamicSymbols(); err == nil {
		append1(ss)
	}
	if len(syms) == 0 {
		return &elfSymbols{}
	}
	sort.Slice(syms, func(i, j int) bool { return syms[i].addr < syms[j].addr })
	return &elfSymbols{ok: true, syms: syms}
}

// procfsRoot is the procfs mount point used to inspect target processes.
// Defaults to "/proc"; overridden by OTEL_PROFILER_HOST_PROCFS so the
// resolver works when the gadget DaemonSet runs with hostPID:false and
// the host procfs is bind-mounted at e.g. /host/proc.
var procfsRoot = func() string {
	if v := os.Getenv("OTEL_PROFILER_HOST_PROCFS"); v != "" {
		return v
	}
	return "/proc"
}()

// findMappedPath walks /proc/<tgid>/maps to find a mapping whose
// backing file has the given basename and covers the given file
// offset. Returns the host-visible absolute path (via /proc/<tgid>/
// root/<p>) when the DaemonSet runs with hostPID=true.
func findMappedPath(tgid uint32, basename string, fileOffset uint64) (string, bool) {
	data, err := os.ReadFile(fmt.Sprintf(procfsRoot + "/%d/maps", tgid))
	if err != nil {
		return "", false
	}
	var fallback string
	for _, line := range splitLines(data) {
		// Fields: address perms offset dev inode pathname
		// Example: 7f000-7f100 r-xp 00010000 00:1f 12345 /usr/lib/x86_64-linux-gnu/libcuda.so.1
		addr, perms, off, p, ok := parseMapsLine(line)
		if !ok {
			continue
		}
		_ = addr
		if !perms.x {
			continue
		}
		if p == "" || p[0] != '/' {
			continue
		}
		if baseOf(p) != basename {
			continue
		}
		if fallback == "" {
			fallback = p
		}
		// Prefer a mapping that actually contains fileOffset.
		if fileOffset >= off && fileOffset < off+addr.size {
			return hostPath(tgid, p), true
		}
	}
	if fallback != "" {
		return hostPath(tgid, fallback), true
	}
	return "", false
}

// hostPath prefixes the container-view path with /proc/<tgid>/root so
// files are read from the target mount namespace. Requires hostPID.
func hostPath(tgid uint32, containerPath string) string {
	return fmt.Sprintf(procfsRoot + "/%d/root%s", tgid, containerPath)
}

type mapsAddr struct {
	start, end, size uint64
}
type mapsPerms struct {
	r, w, x, p bool
}

func parseMapsLine(line string) (mapsAddr, mapsPerms, uint64, string, bool) {
	// Minimal hand-roll parser; avoids strings.Split allocations.
	i := 0
	start, i, ok := readHex(line, i)
	if !ok || i >= len(line) || line[i] != '-' {
		return mapsAddr{}, mapsPerms{}, 0, "", false
	}
	i++
	end, i, ok := readHex(line, i)
	if !ok {
		return mapsAddr{}, mapsPerms{}, 0, "", false
	}
	i = skipSpace(line, i)
	if i+4 > len(line) {
		return mapsAddr{}, mapsPerms{}, 0, "", false
	}
	perms := mapsPerms{
		r: line[i] == 'r',
		w: line[i+1] == 'w',
		x: line[i+2] == 'x',
		p: line[i+3] == 'p',
	}
	i = skipSpace(line, i+4)
	off, i, ok := readHex(line, i)
	if !ok {
		return mapsAddr{}, mapsPerms{}, 0, "", false
	}
	// Skip dev and inode.
	i = skipSpace(line, i)
	for i < len(line) && line[i] != ' ' && line[i] != '\t' {
		i++
	}
	i = skipSpace(line, i)
	for i < len(line) && line[i] != ' ' && line[i] != '\t' {
		i++
	}
	i = skipSpace(line, i)
	return mapsAddr{start: start, end: end, size: end - start}, perms, off, line[i:], true
}

func readHex(s string, i int) (uint64, int, bool) {
	var v uint64
	j := i
	for j < len(s) {
		c := s[j]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			goto done
		}
		v = v<<4 | uint64(d)
		j++
	}
done:
	return v, j, j > i
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func splitLines(b []byte) []string {
	lines := make([]string, 0, 64)
	s := 0
	for i, c := range b {
		if c == '\n' {
			lines = append(lines, string(b[s:i]))
			s = i + 1
		}
	}
	if s < len(b) {
		lines = append(lines, string(b[s:]))
	}
	return lines
}

func baseOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
