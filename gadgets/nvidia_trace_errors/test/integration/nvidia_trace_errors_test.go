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

// Package tests is the integration-test suite for the nvidia_trace_errors
// gadget. It follows the Inspektor Gadget convention of a single *_test.go
// file in test/integration/, driven via `make nvidia_trace_errors/test-integration`.
//
// A quirk of this gadget is that the test workload must run inside a
// container that has libcuda.so.1 mounted from the host's NVIDIA driver —
// which requires `docker run --gpus=all`. The generic igtesting
// ContainerFactory does not expose a --gpus flag, so this file launches the
// workload container directly via `docker run`. The gadget is still driven
// through the standard igrunner.New("nvidia_trace_errors") helper.
package tests

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// cudaImage has gcc + the libcuda headers/stub; the NVIDIA container runtime
// replaces the stub libcuda.so.1 with the real driver library at run time.
const cudaImage = "nvidia/cuda:12.3.2-devel-ubuntu22.04"

// nvidiaTraceErrorEvent is the JSON shape emitted by the gadget after WASM
// enrichment.
type nvidiaTraceErrorEvent struct {
	utils.CommonData

	Timestamp string        `json:"timestamp"`
	Proc      utils.Process `json:"proc"`

	Source      string `json:"source"`
	ErrorCode   string `json:"error_code"`
	APIID       string `json:"api_id"`
	XIDCode     uint32 `json:"xid_code"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Why         string `json:"why"`
	Suggestion  string `json:"suggestion"`
	ContextInfo string `json:"context_info"`
}

// skipIfNoGPU skips the test when no NVIDIA GPU is available locally. An
// integration run without a GPU can still build the gadget (unit test covers
// that) but cannot exercise real CUDA error paths.
func skipIfNoGPU(t *testing.T) {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		t.Skip("skipping: nvidia-smi not found")
	}
	out, err := exec.Command("nvidia-smi", "--query-gpu=name",
		"--format=csv,noheader").CombinedOutput()
	if err != nil || len(out) == 0 {
		t.Skipf("skipping: nvidia-smi failed: %s", string(out))
	}
}

// startWorkload runs the CUDA C snippet inside a GPU-enabled container. It
// compiles the source with gcc and loops the binary once a second so the
// uprobes have several chances to observe the error return.
func startWorkload(t *testing.T, name, cSource string) {
	t.Helper()
	enc := base64.StdEncoding.EncodeToString([]byte(cSource))
	script := fmt.Sprintf(
		`echo %s | base64 -d > /tmp/t.c && `+
			`gcc -I/usr/local/cuda/include -o /tmp/t /tmp/t.c -lcuda && `+
			`while true; do /tmp/t >/dev/null 2>&1; sleep 1; done`,
		enc,
	)
	// Remove any leftover container from a previous aborted run.
	_ = exec.Command("docker", "rm", "-f", name).Run()

	cmd := exec.Command("docker", "run", "--rm", "-d",
		"--name", name, "--gpus=all", cudaImage,
		"bash", "-c", script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker run: %s", string(out))

	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	// Give the container a moment to finish the one-shot compile before the
	// gadget subscription window opens.
	time.Sleep(3 * time.Second)
}

// runCase starts the workload, runs the gadget with --timeout=15 against just
// that container, and asserts at least one event matches expect.
func runCase(t *testing.T, containerName, cSource string,
	expect *nvidiaTraceErrorEvent,
) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)
	skipIfNoGPU(t)

	startWorkload(t, containerName, cSource)

	commonDataOpts := []utils.CommonDataOption{
		utils.WithContainerImageName(cudaImage),
		utils.WithContainerID(utils.NormalizedStr),
	}
	expect.CommonData = utils.BuildCommonData(containerName, commonDataOpts...)

	runnerOpts := []igrunner.Option{
		igrunner.WithFlags(
			fmt.Sprintf("-r=%s", utils.Runtime),
			fmt.Sprintf("--containername=%s", containerName),
			"--verify-image=false",
			"--timeout=15",
		),
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				normalize := func(e *nvidiaTraceErrorEvent) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeString(&e.Runtime.ContainerID)
					utils.NormalizeString(&e.Timestamp)
					utils.NormalizeProc(&e.Proc)
					utils.NormalizeString(&e.Description)
					utils.NormalizeString(&e.Why)
					utils.NormalizeString(&e.Suggestion)
					utils.NormalizeString(&e.ContextInfo)
					utils.NormalizeString(&e.APIID)
					e.XIDCode = 0
				}
				match.MatchEntries(t, match.JSONMultiObjectMode, output,
					normalize, expect)
			},
		),
	}

	cmd := igrunner.New("nvidia_trace_errors", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{cmd}, t)
}

// TestNvidiaTraceErrors_InvalidDevice triggers CUDA_ERROR_INVALID_DEVICE via
// cuCtxCreate_v2 with an ordinal far outside [0, N).
func TestNvidiaTraceErrors_InvalidDevice(t *testing.T) {
	const src = `
#include <cuda.h>
int main(void) {
    cuInit(0);
    CUcontext ctx;
    cuCtxCreate_v2(&ctx, 0, 9999);
    return 0;
}
`
	runCase(t, "nvte-invdev", src,
		&nvidiaTraceErrorEvent{
			Source:    "SOURCE_CUDA_API",
			ErrorCode: "CUDA_ERROR_INVALID_DEVICE",
			Severity:    "MEDIUM",
			Category:    "device",
			APIID:       utils.NormalizedStr,
			Description: utils.NormalizedStr,
			Why:         utils.NormalizedStr,
			Suggestion:  utils.NormalizedStr,
			ContextInfo: utils.NormalizedStr,
			Proc:        utils.BuildProc("t", 0, 0),
			Timestamp:   utils.NormalizedStr,
		})
}

// TestNvidiaTraceErrors_OOM triggers CUDA_ERROR_OUT_OF_MEMORY via a 256 GiB
// cuMemAlloc_v2 request.
func TestNvidiaTraceErrors_OOM(t *testing.T) {
	const src = `
#include <cuda.h>
int main(void) {
    cuInit(0);
    CUdevice dev;
    cuDeviceGet(&dev, 0);
    CUcontext ctx;
    cuCtxCreate_v2(&ctx, 0, dev);
    CUdeviceptr p;
    cuMemAlloc_v2(&p, 256ULL * 1024 * 1024 * 1024);
    return 0;
}
`
	runCase(t, "nvte-oom", src,
		&nvidiaTraceErrorEvent{
			Source:    "SOURCE_CUDA_API",
			ErrorCode: "CUDA_ERROR_OUT_OF_MEMORY",
			Severity:    "HIGH",
			Category:    "memory",
			APIID:       utils.NormalizedStr,
			Description: utils.NormalizedStr,
			Why:         utils.NormalizedStr,
			Suggestion:  utils.NormalizedStr,
			ContextInfo: utils.NormalizedStr,
			Proc:        utils.BuildProc("t", 0, 0),
			Timestamp:   utils.NormalizedStr,
		})
}

// TestNvidiaTraceErrors_InvalidImage triggers CUDA_ERROR_INVALID_IMAGE by passing
// a non-PTX blob to cuModuleLoadData (driver reports INVALID_IMAGE before
// reaching the PTX JIT path when the blob is plainly malformed).
func TestNvidiaTraceErrors_InvalidImage(t *testing.T) {
	const src = `
#include <cuda.h>
int main(void) {
    cuInit(0);
    CUdevice dev;
    cuDeviceGet(&dev, 0);
    CUcontext ctx;
    cuCtxCreate_v2(&ctx, 0, dev);
    CUmodule m;
    const char *bad = "THIS IS NOT PTX";
    cuModuleLoadData(&m, bad);
    return 0;
}
`
	runCase(t, "nvte-badptx", src,
		&nvidiaTraceErrorEvent{
			Source:    "SOURCE_CUDA_API",
			ErrorCode: "CUDA_ERROR_INVALID_IMAGE",
			Severity:    "MEDIUM",
			Category:    "compilation",
			APIID:       utils.NormalizedStr,
			Description: utils.NormalizedStr,
			Why:         utils.NormalizedStr,
			Suggestion:  utils.NormalizedStr,
			ContextInfo: utils.NormalizedStr,
			Proc:        utils.BuildProc("t", 0, 0),
			Timestamp:   utils.NormalizedStr,
		})
}
