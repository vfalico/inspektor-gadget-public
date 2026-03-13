// Copyright 2025-2026 The Inspektor Gadget authors
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

package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ExpectedTraceMallocEvent struct {
	Proc      utils.Process `json:"proc"`
	Operation string        `json:"operation"`
	Addr      uint64        `json:"addr"`
	Size      uint64        `json:"size"`
}

// compileTestBinary compiles a C or C++ source file and returns the
// path to the resulting binary.
func compileTestBinary(t *testing.T, src string) string {
	t.Helper()

	dir := t.TempDir()
	bin := filepath.Join(dir, "test_bin")

	var compiler string
	if strings.HasSuffix(src, ".cpp") {
		compiler = "g++"
	} else {
		compiler = "gcc"
	}

	cmd := exec.Command(compiler, "-o", bin, src, "-lpthread")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "compile %s: %s", src, string(out))

	return bin
}

// TestTraceMallocBasic verifies malloc/free events.
func TestTraceMallocBasic(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	src := filepath.Join("testdata", "test_basic.c")
	bin := compileTestBinary(t, src)

	runner := gadgetrunner.NewGadgetRunner[ExpectedTraceMallocEvent](t,
		gadgetrunner.GadgetRunnerOpts[ExpectedTraceMallocEvent]{
			Image:   "trace_malloc",
			Timeout: 10 * time.Second,
			OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
				cmd := exec.Command(bin)
				return cmd.Run()
			},
		},
	)
	runner.RunGadget()

	mallocCount := 0
	freeCount := 0
	for _, ev := range runner.CapturedEvents {
		if ev.Proc.Comm != filepath.Base(bin) {
			continue
		}
		switch ev.Operation {
		case "malloc":
			mallocCount++
			assert.Equal(t, uint64(1024), ev.Size, "malloc size")
		case "free":
			freeCount++
		}
	}
	assert.Equal(t, 10, mallocCount, "expected 10 malloc events")
	assert.Equal(t, 10, freeCount, "expected 10 free events")
}

// TestTraceMallocCppNewDelete verifies C++ new/delete events.
func TestTraceMallocCppNewDelete(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	src := filepath.Join("testdata", "test_cpp.cpp")
	bin := compileTestBinary(t, src)

	runner := gadgetrunner.NewGadgetRunner[ExpectedTraceMallocEvent](t,
		gadgetrunner.GadgetRunnerOpts[ExpectedTraceMallocEvent]{
			Image:   "trace_malloc",
			Timeout: 10 * time.Second,
			OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
				cmd := exec.Command(bin)
				return cmd.Run()
			},
		},
	)
	runner.RunGadget()

	newCount := 0
	deleteCount := 0
	newArrayCount := 0
	deleteArrayCount := 0
	for _, ev := range runner.CapturedEvents {
		if ev.Proc.Comm != filepath.Base(bin) {
			continue
		}
		switch ev.Operation {
		case "op_new":
			newCount++
		case "op_delete":
			deleteCount++
		case "op_new_array":
			newArrayCount++
		case "op_delete_array":
			deleteArrayCount++
		}
	}
	assert.GreaterOrEqual(t, newCount, 5, "expected at least 5 new events")
	assert.GreaterOrEqual(t, deleteCount, 5, "expected at least 5 delete events")
	assert.GreaterOrEqual(t, newArrayCount, 5, "expected at least 5 new[] events")
	assert.GreaterOrEqual(t, deleteArrayCount, 5, "expected at least 5 delete[] events")
}

// TestTraceMallocRealloc verifies realloc generates both free and alloc events.
func TestTraceMallocRealloc(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	src := filepath.Join("testdata", "test_realloc.c")
	bin := compileTestBinary(t, src)

	runner := gadgetrunner.NewGadgetRunner[ExpectedTraceMallocEvent](t,
		gadgetrunner.GadgetRunnerOpts[ExpectedTraceMallocEvent]{
			Image:   "trace_malloc",
			Timeout: 10 * time.Second,
			OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
				cmd := exec.Command(bin)
				return cmd.Run()
			},
		},
	)
	runner.RunGadget()

	reallocCount := 0
	reallocFreeCount := 0
	for _, ev := range runner.CapturedEvents {
		if ev.Proc.Comm != filepath.Base(bin) {
			continue
		}
		switch ev.Operation {
		case "realloc":
			reallocCount++
		case "realloc_free":
			reallocFreeCount++
		}
	}
	assert.GreaterOrEqual(t, reallocCount, 5, "expected realloc events")
	assert.GreaterOrEqual(t, reallocFreeCount, 5, "expected realloc_free events")
}

// TestTraceMallocReallocarray verifies reallocarray events.
func TestTraceMallocReallocarray(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	src := filepath.Join("testdata", "test_reallocarray.c")
	bin := compileTestBinary(t, src)

	runner := gadgetrunner.NewGadgetRunner[ExpectedTraceMallocEvent](t,
		gadgetrunner.GadgetRunnerOpts[ExpectedTraceMallocEvent]{
			Image:   "trace_malloc",
			Timeout: 10 * time.Second,
			OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
				cmd := exec.Command(bin)
				return cmd.Run()
			},
		},
	)
	runner.RunGadget()

	reallocarrayCount := 0
	for _, ev := range runner.CapturedEvents {
		if ev.Proc.Comm != filepath.Base(bin) {
			continue
		}
		if ev.Operation == "reallocarray" {
			reallocarrayCount++
		}
	}
	assert.GreaterOrEqual(t, reallocarrayCount, 5, "expected reallocarray events")
}

// TestTraceMallocMmap verifies mmap/munmap events.
func TestTraceMallocMmap(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	src := filepath.Join("testdata", "test_mmap.c")
	bin := compileTestBinary(t, src)

	runner := gadgetrunner.NewGadgetRunner[ExpectedTraceMallocEvent](t,
		gadgetrunner.GadgetRunnerOpts[ExpectedTraceMallocEvent]{
			Image:   "trace_malloc",
			Timeout: 10 * time.Second,
			OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
				cmd := exec.Command(bin)
				return cmd.Run()
			},
		},
	)
	runner.RunGadget()

	mmapCount := 0
	munmapCount := 0
	for _, ev := range runner.CapturedEvents {
		if ev.Proc.Comm != filepath.Base(bin) {
			continue
		}
		switch ev.Operation {
		case "mmap":
			mmapCount++
		case "munmap":
			munmapCount++
		}
	}
	assert.GreaterOrEqual(t, mmapCount, 5, "expected mmap events")
	assert.GreaterOrEqual(t, munmapCount, 5, "expected munmap events")
}

// TestTraceMallocCaptureStacksParam verifies the capture-stacks parameter.
func TestTraceMallocCaptureStacksParam(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	src := filepath.Join("testdata", "test_basic.c")
	bin := compileTestBinary(t, src)

	// Run with capture-stacks=false
	runner := gadgetrunner.NewGadgetRunner[ExpectedTraceMallocEvent](t,
		gadgetrunner.GadgetRunnerOpts[ExpectedTraceMallocEvent]{
			Image:   "trace_malloc",
			Timeout: 10 * time.Second,
			ParamValues: map[string]string{
				"operator.ebpf.capture-stacks": "false",
			},
			OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
				cmd := exec.Command(bin)
				return cmd.Run()
			},
		},
	)
	runner.RunGadget()

	// Events should still be captured, just without stacks
	eventCount := 0
	for _, ev := range runner.CapturedEvents {
		if ev.Proc.Comm != filepath.Base(bin) {
			continue
		}
		eventCount++
	}
	assert.Greater(t, eventCount, 0, "should still capture events with stacks disabled")
}

// TestTraceMallocDummy is a basic smoke test.
func TestTraceMallocDummy(t *testing.T) {
	gadgettesting.DummyGadgetTest(t, "trace_malloc")
}
