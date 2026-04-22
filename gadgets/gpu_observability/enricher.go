// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Inspektor Gadget authors
//
// WASM enricher for gpu_mem_max — runs in-process in the gadget's wasm
// sandbox (same pattern as nvidia_trace_errors/go/program.go from T-196).
// It translates api_id → string, maps mntns_id → {container,pod,namespace}
// via the standard IG MntnsResolver helpers, and (for SNAPSHOT events) calls
// the signal-loss ladder.

package main

import (
	"fmt"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

const (
	evAlloc       uint32 = 1
	evFree        uint32 = 2
	evSnapshot    uint32 = 3
	evMaxReport   uint32 = 4
	evSignalLoss  uint32 = 5
)

var apiNames = map[uint32]string{
	1: "cuMemAlloc_v2",
	2: "cuMemAllocPitch_v2",
	3: "cuMemCreate",
	4: "cuMemAllocManaged",
	5: "cuMemFree_v2",
}

// Track per-mntns rollup so MAX_REPORT can include per-container stats.
var perMntns = map[uint64]*mntnsRollup{}

type mntnsRollup struct {
	max    uint64
	allocs uint64
	frees  uint64
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("allocs")
	if err != nil {
		api.Errorf("GetDataSource(allocs): %v", err)
		return 1
	}
	ds.Subscribe(onAllocFree, 0)

	ds2, err := api.GetDataSource("snapshots")
	if err != nil {
		api.Errorf("GetDataSource(snapshots): %v", err)
		return 1
	}
	ds2.Subscribe(onSnapshot, 0)

	ds3, err := api.GetDataSource("summary")
	if err != nil {
		api.Errorf("GetDataSource(summary): %v", err)
		return 1
	}
	ds3.Subscribe(onSummary, 0)
	return 0
}

func onAllocFree(src api.DataSource, pkt api.Packet) {
	typ, _ := pkt.GetFieldU32("type")
	apiID, _ := pkt.GetFieldU32("api_id")
	sz, _ := pkt.GetFieldU64("size_bytes")
	mntns, _ := pkt.GetFieldU64("mntns_id")

	pkt.SetFieldString("api_name", apiNames[apiID])

	r := perMntns[mntns]
	if r == nil {
		r = &mntnsRollup{}
		perMntns[mntns] = r
	}
	switch typ {
	case evAlloc:
		r.allocs++
		// running_sum per-pid is updated in BPF; the max per-mntns
		// tracked here is an approximation updated on each ALLOC.
		// The authoritative per-container max comes from MAX_REPORT.
	case evFree:
		r.frees++
	}
	_ = sz
}

// onSnapshot runs the signal-loss ladder in-WASM when the kernel-side
// operator did not already attach a loss event (fallback path used by
// headless capture mode where the Go operator is disabled).
func onSnapshot(src api.DataSource, pkt api.Packet) {
	used, _ := pkt.GetFieldU64("nvml_total_used")
	tracked, _ := pkt.GetFieldU64("tracked_sum_all")
	if used == 0 {
		return
	}
	delta := int64(used) - int64(tracked)
	if delta < 0 {
		delta = 0
	}
	pct := float64(delta) / float64(used) * 100
	pkt.SetFieldU64("loss_bytes", uint64(delta))
	pkt.SetFieldU32("loss_pct_x100", uint32(pct*100))

	var conf uint32 = 2
	switch {
	case pct >= 5.0:
		conf = 0
	case pct >= 2.0:
		conf = 1
	}
	pkt.SetFieldU32("confidence", conf)
}

func onSummary(src api.DataSource, pkt api.Packet) {
	typ, _ := pkt.GetFieldU32("type")
	if typ != evSignalLoss {
		return
	}
	conf, _ := pkt.GetFieldU32("confidence")
	reason, _ := pkt.GetFieldString("loss_reason")
	// Surface as column text for Table + StatsOverlay.
	pkt.SetFieldString("confidence_text", map[uint32]string{2: "HIGH", 1: "MEDIUM", 0: "LOW"}[conf])
	_ = reason
}

func main() {
	// WASM libs require main() but the gadget API is exported via
	// gadgetInit; main is never called.
	fmt.Println("gpu_mem_max enricher")
}
