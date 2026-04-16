// Copyright 2024 The Inspektor Gadget authors
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
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type cudaErrorTraceEvent struct {
	utils.CommonData

	Timestamp   string       `json:"timestamp"`
	Proc        utils.Process `json:"proc"`
	ErrorCode   int32        `json:"error_code"`
	ErrorName   string       `json:"error_name"`
	ApiId       uint32       `json:"api_id"`
	ApiName     string       `json:"api_name"`
	Description string       `json:"description"`
	Category    string       `json:"category"`
	Suggestion  string       `json:"suggestion"`
	ContextInfo string       `json:"context_info"`
}

func TestCudaErrorTraceIntegration(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)

	// Skip if no NVIDIA GPU available
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		t.Skip("Skipping CUDA test: nvidia-smi not found, no GPU available")
	}
	out, err := exec.Command("nvidia-smi", "--query-gpu=name", "--format=csv,noheader").Output()
	if err != nil || len(out) == 0 {
		t.Skip("Skipping CUDA test: no NVIDIA GPU detected")
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "creating container factory")

	// Container that triggers a CUDA error (invalid device ordinal)
	cudaErrorContainer := containerFactory.NewContainer(
		"cuda-error-test",
		"nvidia/cuda:12.3.2-base-ubuntu22.04",
		containers.WithContainerImage("nvidia/cuda:12.3.2-base-ubuntu22.04"),
		containers.WithStartAndStop(),
		containers.WithCommand(
			"python3", "-c",
			`import ctypes; libcuda = ctypes.CDLL("libcuda.so.1"); libcuda.cuInit(0); ctx = ctypes.c_void_p(); libcuda.cuCtxCreate_v2(ctypes.byref(ctx), 0, 9999)`,
		),
	)

	var runnerOpts []igrunner.Option
	runnerOpts = append(runnerOpts, igrunner.WithFlags(
		fmt.Sprintf("-r %s", utils.Runtime),
		fmt.Sprintf("--containername %s", cudaErrorContainer.Name()),
	))

	cudaErrorTraceCmd := igrunner.New("cuda_error_trace", runnerOpts...)

	steps := []igtesting.TestStep{
		cudaErrorContainer,
		cudaErrorTraceCmd,
		igtesting.Sleep(2),
	}

	expectedEntry := &cudaErrorTraceEvent{
		CommonData: utils.BuildCommonData(cudaErrorContainer.Name(),
			utils.WithContainerImageName("nvidia/cuda:12.3.2-base-ubuntu22.04", utils.NormalizedStr),
		),
		ErrorCode:   int32(101),
		ErrorName:   "CUDA_ERROR_INVALID_DEVICE",
		Category:    "device",
		Description: "invalid device ordinal",
	}

	normalize := func(e *cudaErrorTraceEvent) {
		utils.NormalizeCommonData(&e.CommonData)
		utils.NormalizeString(&e.Timestamp)
		utils.NormalizeInt(&e.Proc.Pid)
		utils.NormalizeInt(&e.Proc.Tid)
		utils.NormalizeString(&e.Proc.Comm)
		utils.NormalizeString(&e.Suggestion)
		utils.NormalizeString(&e.ContextInfo)
		utils.NormalizeString(&e.ApiName)
		e.ApiId = 0
	}

	match.MatchEntries(t, match.JSONMultiObjectMode, cudaErrorTraceCmd.OutputChannel(),
		normalize, expectedEntry)

	igtesting.RunTestSteps(steps, t)
}
