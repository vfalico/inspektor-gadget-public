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

// Package main is a WASM enricher for the cuda_error_trace gadget.
// It subscribes to the "cuda_errors" datasource and adds human-readable
// fields alongside the raw numeric error_code and api_id fields.
// This follows the trace_dns pattern of code→string mapping at runtime.
//
// Stack trace processing:
//   - The BPF program captures a stack_id via gadget_get_user_stack() when
//     --collect-ustack=true is passed at runtime.
//   - The WASM enricher reads the BPF STACK_TRACE map "ig_ustack" using the
//     WASM GetMap/Lookup API, extracts raw addresses, and formats them into a
//     "stack_frames" string field (e.g. "0x7f1234;0x7f5678;0x401234").
//   - Full symbol resolution (address → function name) is handled by IG's
//     built-in "ustack" operator, which reads /proc/<pid>/maps + ELF symbol
//     tables on the host. The resolved names appear in the "ustack" field
//     visible in table/tree output modes.
package main

import (
	"fmt"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// GADGET_USER_MAX_STACK_DEPTH must match user_stack_map.h
const gadgetUserMaxStackDepth = 127

// stackAddresses is the value type for ig_ustack BPF_MAP_TYPE_STACK_TRACE.
// key: uint32 stack_id, value: [127]uint64 (instruction pointers, 0-terminated).
type stackAddresses [gadgetUserMaxStackDepth]uint64

// ─── Error catalog ────────────────────────────────────────────────────────────
// Maps are embedded at compile time — WASM sandbox has no filesystem access.
// Error codes use the actual CUresult enum values from cuda.h.

// CUresult numeric codes → symbolic names.
var errorNames = map[int32]string{
	1:   "CUDA_ERROR_INVALID_VALUE",
	2:   "CUDA_ERROR_OUT_OF_MEMORY",
	3:   "CUDA_ERROR_NOT_INITIALIZED",
	4:   "CUDA_ERROR_DEINITIALIZED",
	5:   "CUDA_ERROR_PROFILER_DISABLED",
	34:  "CUDA_ERROR_STUB_LIBRARY",
	100: "CUDA_ERROR_NO_DEVICE",
	101: "CUDA_ERROR_INVALID_DEVICE",
	102: "CUDA_ERROR_DEVICE_NOT_LICENSED",
	200: "CUDA_ERROR_INVALID_IMAGE",
	201: "CUDA_ERROR_INVALID_CONTEXT",
	202: "CUDA_ERROR_CONTEXT_ALREADY_CURRENT",
	205: "CUDA_ERROR_MAP_FAILED",
	206: "CUDA_ERROR_UNMAP_FAILED",
	207: "CUDA_ERROR_ARRAY_IS_MAPPED",
	208: "CUDA_ERROR_ALREADY_MAPPED",
	209: "CUDA_ERROR_NO_BINARY_FOR_GPU",
	210: "CUDA_ERROR_ALREADY_ACQUIRED",
	211: "CUDA_ERROR_NOT_MAPPED",
	212: "CUDA_ERROR_NOT_MAPPED_AS_ARRAY",
	213: "CUDA_ERROR_NOT_MAPPED_AS_POINTER",
	214: "CUDA_ERROR_ECC_UNCORRECTABLE",
	215: "CUDA_ERROR_UNSUPPORTED_LIMIT",
	216: "CUDA_ERROR_CONTEXT_ALREADY_IN_USE",
	217: "CUDA_ERROR_PEER_ACCESS_UNSUPPORTED",
	218: "CUDA_ERROR_INVALID_PTX",
	219: "CUDA_ERROR_INVALID_GRAPHICS_CONTEXT",
	220: "CUDA_ERROR_NVLINK_UNCORRECTABLE",
	700: "CUDA_ERROR_ILLEGAL_ADDRESS",
	701: "CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES",
	702: "CUDA_ERROR_LAUNCH_TIMEOUT",
	703: "CUDA_ERROR_LAUNCH_INCOMPATIBLE_TEXTURING",
	719: "CUDA_ERROR_LAUNCH_FAILED",
	999: "CUDA_ERROR_UNKNOWN",
}

// CUresult codes → plain-English description.
var errorDescriptions = map[int32]string{
	1:   "One or more parameters passed to the API call are not within an acceptable range of values",
	2:   "The API call failed because it was unable to allocate enough memory to perform the requested operation",
	3:   "The CUDA driver has not been initialized with cuInit() or that initialization has failed",
	4:   "The CUDA driver is in the process of shutting down",
	5:   "Profiling APIs are called while application is running in visual profiler mode",
	34:  "CUDA was loaded as a stub library; the actual driver is not available",
	100: "No CUDA-capable device is detected by the installed CUDA driver",
	101: "The device ordinal supplied by the user is outside the valid range [0, numDevices-1]",
	102: "The device does not have a valid Grid License",
	200: "The device kernel image is invalid; this can occur when ELF is malformed or doesn't match the device",
	201: "There is no context bound to the current thread; call cuCtxCreate() first",
	202: "The context is already current on the calling thread",
	205: "A map or register operation has failed",
	206: "An unmap or unregister operation has failed",
	207: "The specified array is currently mapped and cannot be destroyed",
	208: "The resource is already mapped",
	209: "There is no kernel image available that is suitable for the device (wrong compute capability)",
	210: "A resource has already been acquired",
	211: "A resource is not mapped",
	212: "A mapped resource is not available for access as an array",
	213: "A mapped resource is not available for access as a pointer",
	214: "An uncorrectable ECC error was detected during execution",
	215: "An attempt to set a limit on a resource that is not supported on the device",
	216: "The context is already in use by another thread",
	217: "Peer access between the two specified devices is not possible",
	218: "A PTX JIT compilation failed; the PTX code may be invalid or incompatible",
	219: "Invalid OpenGL or DirectX graphics context",
	220: "An uncorrectable NVLink error was detected during execution",
	700: "The device encountered a load or store instruction on an invalid memory address (GPU segfault)",
	701: "A kernel launch failed because it used too many registers or shared memory for the device",
	702: "The device kernel took too long to execute (watchdog timeout)",
	703: "A kernel launch used an incompatible texturing mode",
	719: "An exception occurred on the device while executing a kernel (unspecified launch failure)",
	999: "An unknown internal error has occurred",
}

// CUresult codes → error category.
var errorCategories = map[int32]string{
	1: "parameter", 2: "memory", 3: "initialization", 4: "initialization",
	5: "profiling", 34: "initialization",
	100: "device", 101: "device", 102: "device",
	200: "module", 201: "context", 202: "context",
	205: "memory", 206: "memory", 207: "memory", 208: "memory",
	209: "module", 210: "memory", 211: "memory", 212: "memory", 213: "memory",
	214: "hardware", 215: "parameter", 216: "context",
	217: "device", 218: "module", 219: "context", 220: "hardware",
	700: "launch", 701: "launch", 702: "launch", 703: "launch", 719: "launch",
	999: "unknown",
}

// CUresult codes → actionable remediation suggestion.
var errorSuggestions = map[int32]string{
	1:   "Check all API arguments: pointers must be valid, sizes > 0, device ordinals in range, flags valid",
	2:   "Reduce batch size, enable gradient checkpointing, use torch.cuda.empty_cache(), use model parallelism, or use a GPU with more memory",
	3:   "Call cuInit(0) before any other CUDA driver call; check CUDA installation with nvidia-smi",
	4:   "Application is shutting down; ensure CUDA calls complete before exit",
	5:   "Exit Visual Profiler before calling profiling APIs directly",
	34:  "Install the NVIDIA driver; the CUDA stub library is present but no real driver is loaded",
	100: "Install NVIDIA GPU driver; check 'nvidia-smi' works; ensure GPU is visible in PCIe bus",
	101: "Use a device ordinal in [0, N-1] where N = number of GPUs from cuDeviceGetCount(); check CUDA_VISIBLE_DEVICES",
	102: "Obtain a valid NVIDIA Grid/vGPU license for this device",
	200: "Recompile the kernel for the target GPU architecture; check -arch flag matches device sm_XX",
	201: "Create or push a CUDA context with cuCtxCreate() or cuCtxPushCurrent() before this call",
	202: "Context already current; this is usually benign",
	205: "Check that the resource is valid and not already mapped",
	206: "Check that the resource was previously mapped before unmapping",
	207: "Unmap the array before destroying it",
	208: "Unmap the resource before remapping",
	209: "Recompile with -gencode matching the target GPU; use -arch=sm_XX where XX matches your GPU",
	210: "Release the resource before acquiring again",
	211: "Map the resource with cuGraphicsMapResources before accessing",
	212: "Map the resource as an array, not a pointer",
	213: "Map the resource as a pointer, not an array",
	214: "Check GPU health with nvidia-smi; consider RMA if persistent; reduce memory clock with nvidia-smi -ac",
	215: "The requested limit (stack size, heap size, etc.) is not supported on this device",
	216: "Use cuCtxPopCurrent/cuCtxPushCurrent to manage contexts across threads",
	217: "These GPUs cannot do peer access; use staged copies through host memory",
	218: "Check PTX version compatibility; recompile for correct target; check for invalid PTX instructions",
	219: "Ensure the OpenGL/DirectX context is valid and current before interop calls",
	220: "Check NVLink connection health; consider system reboot; check nvidia-smi for link errors",
	700: "Check for out-of-bounds array access in your kernel; use compute-sanitizer to debug",
	701: "Reduce block size, reduce register usage, or reduce shared memory per block",
	702: "Reduce kernel execution time; split into smaller kernels; disable display watchdog (TDR) for compute GPUs",
	703: "Check texture setup matches kernel expectations",
	719: "Use compute-sanitizer to identify the specific error; check for race conditions, invalid memory access",
	999: "Contact NVIDIA support; check nvidia-smi for hardware errors; try rebooting",
}

// CUDA Driver API ID → function name. IDs match program.bpf.c constants.
var apiNames = map[uint32]string{
	1:  "cuMemAlloc_v2",
	2:  "cuMemAllocPitch_v2",
	3:  "cuMemAllocManaged",
	4:  "cuLaunchKernel",
	5:  "cuCtxCreate_v2",
	6:  "cuDeviceGet",
	7:  "cuDeviceGetCount",
	8:  "cuModuleLoad",
	9:  "cuModuleLoadData",
	10: "cuModuleGetFunction",
	11: "cuMemcpyHtoD_v2",
	12: "cuMemcpyDtoH_v2",
	13: "cuStreamCreate",
	14: "cuStreamQuery",
	15: "cuStreamSynchronize",
	16: "cuEventCreate",
	17: "cuEventRecord",
	18: "cuEventQuery",
	19: "cuEventSynchronize",
	20: "cuMemFree_v2",
	21: "cuCtxSynchronize",
	22: "cuInit",
}

// ─── Field handles (populated in gadgetInit) ──────────────────────────────────

var (
	dsErrors api.DataSource

	fErrorCode    api.Field
	fAPIID        api.Field
	fArg1         api.Field
	fArg2         api.Field
	fArg3         api.Field
	fArg4         api.Field
	fArg5         api.Field
	fArg6         api.Field
	fUstackStackID api.Field

	fErrorName   api.Field
	fAPIName     api.Field
	fDesc        api.Field
	fCategory    api.Field
	fSuggestion  api.Field
	fContext     api.Field
	fWhy         api.Field
	fStackFrames api.Field

	// ig_ustack BPF map handle — opened once in gadgetInit, used in enrichEvent.
	// Key: uint32 (stack_id), Value: [127]uint64 (instruction pointers).
	igUstackMap api.Map
	ustackMapOK   bool
	ustackFieldOK bool
)

// ─── Lifecycle ────────────────────────────────────────────────────────────────

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error

	dsErrors, err = api.GetDataSource("cuda_errors")
	if err != nil {
		api.Warnf("failed to get datasource cuda_errors: %v", err)
		return 1
	}

	// Read fields from BPF program
	fErrorCode, err = dsErrors.GetField("error_code")
	if err != nil {
		api.Warnf("failed to get field error_code: %v", err)
		return 1
	}
	fAPIID, err = dsErrors.GetField("api_id")
	if err != nil {
		api.Warnf("failed to get field api_id: %v", err)
		return 1
	}
	fArg1, err = dsErrors.GetField("arg1")
	if err != nil {
		api.Warnf("failed to get field arg1: %v", err)
		return 1
	}
	fArg2, err = dsErrors.GetField("arg2")
	if err != nil {
		api.Warnf("failed to get field arg2: %v", err)
		return 1
	}
	fArg3, err = dsErrors.GetField("arg3")
	if err != nil {
		api.Warnf("failed to get field arg3: %v", err)
		return 1
	}
	fArg4, err = dsErrors.GetField("arg4")
	if err != nil {
		api.Warnf("failed to get field arg4: %v", err)
		return 1
	}
	fArg5, err = dsErrors.GetField("arg5")
	if err != nil {
		api.Warnf("failed to get field arg5: %v", err)
		return 1
	}
	fArg6, err = dsErrors.GetField("arg6")
	if err != nil {
		api.Warnf("failed to get field arg6: %v", err)
		return 1
	}

	// Read the stack_id sub-field from the ustack_raw struct.
	// The gadget_user_stack type exposes sub-fields as "ustack_raw.stack_id".
	fUstackStackID, err = dsErrors.GetField("ustack_raw.stack_id")
	if err != nil {
		// Non-fatal: stack extraction degrades gracefully
		api.Warnf("failed to get field ustack_raw.stack_id (stack extraction disabled): %v", err)
		ustackFieldOK = false
	} else {
		ustackFieldOK = true
	}

	// ig_ustack map is opened lazily in enrichEvent, because the BPF program
	// has not been loaded yet at gadgetInit time. ustackMapOK is set on first use.

	// Add enriched string fields
	fErrorName, err = dsErrors.AddField("error_name", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field error_name: %v", err)
		return 1
	}
	fAPIName, err = dsErrors.AddField("api_name", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field api_name: %v", err)
		return 1
	}
	fDesc, err = dsErrors.AddField("description", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field description: %v", err)
		return 1
	}
	fCategory, err = dsErrors.AddField("category", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field category: %v", err)
		return 1
	}
	fSuggestion, err = dsErrors.AddField("suggestion", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field suggestion: %v", err)
		return 1
	}
	fContext, err = dsErrors.AddField("context_info", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field context_info: %v", err)
		return 1
	}
	fWhy, err = dsErrors.AddField("why", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field why: %v", err)
		return 1
	}
	// stack_frames: semicolon-separated hex instruction pointers extracted
	// from the ig_ustack BPF map. Use with --collect-ustack at runtime.
	// IG's ustack operator additionally resolves these to function names.
	fStackFrames, err = dsErrors.AddField("stack_frames", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field stack_frames: %v", err)
		return 1
	}

	// Subscribe to events with default priority
	dsErrors.Subscribe(enrichEvent, 0)
	return 0
}

// ─── Enrichment callback ──────────────────────────────────────────────────────

func enrichEvent(source api.DataSource, data api.Data) {
	// Read raw numeric fields from BPF
	errCode, err := fErrorCode.Int32(data)
	if err != nil {
		api.Warnf("failed to read error_code: %v", err)
		return
	}
	apiID, err := fAPIID.Uint32(data)
	if err != nil {
		api.Warnf("failed to read api_id: %v", err)
		return
	}
	arg1, _ := fArg1.Uint64(data)
	arg2, _ := fArg2.Uint64(data)
	arg3, _ := fArg3.Uint64(data)
	arg4, _ := fArg4.Uint64(data)
	arg5, _ := fArg5.Uint64(data)
	arg6, _ := fArg6.Uint64(data)

	// Enrich error_name
	if name, ok := errorNames[errCode]; ok {
		fErrorName.SetString(data, name)
	} else {
		fErrorName.SetString(data, fmt.Sprintf("CUDA_ERROR_%d", errCode))
	}

	// Enrich api_name
	apiName := fmt.Sprintf("cuda_api_%d", apiID)
	if name, ok := apiNames[apiID]; ok {
		apiName = name
	}
	fAPIName.SetString(data, apiName)

	// Enrich description
	if desc, ok := errorDescriptions[errCode]; ok {
		fDesc.SetString(data, desc)
	} else {
		fDesc.SetString(data, "Unknown CUDA error")
	}

	// Enrich category
	if cat, ok := errorCategories[errCode]; ok {
		fCategory.SetString(data, cat)
	} else {
		fCategory.SetString(data, "unknown")
	}

	// Enrich suggestion
	if sug, ok := errorSuggestions[errCode]; ok {
		fSuggestion.SetString(data, sug)
	} else {
		fSuggestion.SetString(data, "Consult CUDA documentation for error code")
	}

	// Compute context_info — differs per API
	ctxInfo := formatContextInfo(apiID, arg1, arg2, arg3, arg4, arg5, arg6)
	fContext.SetString(data, ctxInfo)

	// Compute "why" — a synthesis of error + api + context
	why := formatWhy(errCode, apiID, apiName, arg1, arg2, arg3, arg4, arg5, arg6)
	fWhy.SetString(data, why)

	// ── Stack frame extraction ────────────────────────────────────────────
	// Read raw instruction pointer addresses from the ig_ustack BPF map
	// using the stack_id captured by the BPF program. This provides a
	// gadget-internal "stack_frames" field with hex addresses.
	// The IG ustack operator resolves these addresses to function names
	// using /proc/<pid>/maps + ELF symbol tables on the host side.
	if ustackFieldOK {
		stackID, err := fUstackStackID.Uint32(data)
		if err == nil && stackID != 0 {
			frames := extractStackFrames(stackID)
			if frames != "" {
				fStackFrames.SetString(data, frames)
			}
		}
	}
}

// extractStackFrames looks up stack_id in the ig_ustack BPF map and returns
// a semicolon-separated string of non-zero hex instruction pointer addresses.
// Example: "0x7f3b2c1a5d20;0x401234;0x7f3b2c1a1000"
// Returns "" if the stack_id is not found or has no valid frames.
// The ig_ustack map is opened lazily on first call because the BPF program
// is not loaded at gadgetInit time (the map does not exist yet).
func extractStackFrames(stackID uint32) string {
	// Lazy-initialize the ig_ustack map handle on first call.
	if !ustackMapOK {
		m, err := api.GetMap("ig_ustack")
		if err != nil {
				return ""
		}
		igUstackMap = m
		ustackMapOK = true
	}

	var addrs stackAddresses
	if err := igUstackMap.Lookup(stackID, &addrs); err != nil {
		return ""
	}

	parts := make([]string, 0, 16)
	for _, addr := range addrs {
		if addr == 0 {
			break // stack trace is 0-terminated
		}
		parts = append(parts, fmt.Sprintf("0x%x", addr))
	}
	return strings.Join(parts, ";")
}

// formatWhy generates a human-readable explanation combining the error,
// the API call, and the relevant parameters.
func formatWhy(errCode int32, apiID uint32, apiName string, arg1, arg2, arg3, arg4, arg5, arg6 uint64) string {
	switch {
	case errCode == 2 && apiID == 1: // OOM on cuMemAlloc_v2
		return fmt.Sprintf("%s failed: requested %s but GPU does not have enough free memory",
			apiName, humanBytes(arg2))
	case errCode == 2 && apiID == 3: // OOM on cuMemAllocManaged
		return fmt.Sprintf("%s failed: requested %s managed memory but insufficient memory available",
			apiName, humanBytes(arg2))
	case errCode == 101 && apiID == 5: // Invalid device on cuCtxCreate_v2
		return fmt.Sprintf("%s failed: device ordinal %d does not exist (check CUDA_VISIBLE_DEVICES and GPU count)",
			apiName, arg3)
	case errCode == 101 && apiID == 6: // Invalid device on cuDeviceGet
		return fmt.Sprintf("%s failed: device ordinal %d is out of range",
			apiName, arg2)
	case errCode == 100: // No device
		return fmt.Sprintf("%s failed: no CUDA-capable GPU detected; is nvidia driver loaded?",
			apiName)
	case errCode == 3: // Not initialized
		return fmt.Sprintf("%s failed: cuInit() was not called or failed",
			apiName)
	case errCode == 209: // No binary for GPU
		return fmt.Sprintf("%s failed: no compatible GPU binary found; recompile for your GPU's compute capability",
			apiName)
	case errCode == 700: // Illegal address
		return fmt.Sprintf("%s detected an illegal memory access on the GPU (equivalent of a segfault)",
			apiName)
	case errCode == 719: // Launch failed
		return fmt.Sprintf("%s: kernel execution failed with an unspecified error; use compute-sanitizer for details",
			apiName)
	case errCode == 701 && apiID == 4: // Launch out of resources
		return fmt.Sprintf("%s failed: kernel requires too many resources for the GPU; grid=(%d,%d,%d) block=(%d,%d,...)",
			apiName, arg2, arg3, arg4, arg5, arg6)
	default:
		desc := "unknown error"
		if d, ok := errorDescriptions[errCode]; ok {
			desc = d
		}
		return fmt.Sprintf("%s failed with %s (code %d): %s",
			apiName, errorNameOrCode(errCode), errCode, desc)
	}
}

func errorNameOrCode(code int32) string {
	if name, ok := errorNames[code]; ok {
		return name
	}
	return fmt.Sprintf("CUDA_ERROR_%d", code)
}

// formatContextInfo formats API-specific argument context into a human-readable string.
func formatContextInfo(apiID uint32, arg1, arg2, arg3, arg4, arg5, arg6 uint64) string {
	switch apiID {
	case 1: // cuMemAlloc_v2(dptr, bytesize)
		return fmt.Sprintf("requested_bytes=%d (%s)", arg2, humanBytes(arg2))
	case 2: // cuMemAllocPitch_v2(dptr, pitch, widthInBytes, height, elementSizeBytes)
		return fmt.Sprintf("width=%d height=%d element_size=%d", arg3, arg4, arg5)
	case 3: // cuMemAllocManaged(dptr, bytesize, flags)
		return fmt.Sprintf("requested_bytes=%d (%s) flags=0x%x", arg2, humanBytes(arg2), arg3)
	case 4: // cuLaunchKernel(f, gridX, gridY, gridZ, blockX, blockY, ...)
		return fmt.Sprintf("grid=(%d,%d,%d) block=(%d,%d,...)", arg2, arg3, arg4, arg5, arg6)
	case 5: // cuCtxCreate_v2(pctx, flags, dev)
		return fmt.Sprintf("flags=0x%x device=%d", arg2, arg3)
	case 6: // cuDeviceGet(device, ordinal)
		return fmt.Sprintf("ordinal=%d", arg2)
	case 8: // cuModuleLoad(module, fname)
		return fmt.Sprintf("path_ptr=0x%x", arg2)
	case 11: // cuMemcpyHtoD_v2(dst, src, bytes)
		return fmt.Sprintf("transfer_bytes=%d (%s)", arg3, humanBytes(arg3))
	case 12: // cuMemcpyDtoH_v2(dst, src, bytes)
		return fmt.Sprintf("transfer_bytes=%d (%s)", arg3, humanBytes(arg3))
	case 13: // cuStreamCreate(phStream, flags)
		return fmt.Sprintf("flags=0x%x", arg2)
	case 14, 15: // cuStreamQuery/Synchronize(hStream)
		return fmt.Sprintf("stream=0x%x", arg1)
	case 16: // cuEventCreate(phEvent, flags)
		return fmt.Sprintf("flags=0x%x", arg2)
	case 17: // cuEventRecord(hEvent, hStream)
		return fmt.Sprintf("event=0x%x stream=0x%x", arg1, arg2)
	case 18, 19: // cuEventQuery/Synchronize(hEvent)
		return fmt.Sprintf("event=0x%x", arg1)
	case 20: // cuMemFree_v2(dptr)
		return fmt.Sprintf("ptr=0x%x", arg1)
	default:
		return ""
	}
}

// humanBytes formats a byte count as "X.X GB", "X.X MB", etc.
func humanBytes(bytes uint64) string {
	const (
		gb = 1 << 30
		mb = 1 << 20
		kb = 1 << 10
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/gb)
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/mb)
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/kb)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func main() {}
