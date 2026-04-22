// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Inspektor Gadget authors
//
// operator_nvml_mem is the NVML polling operator for the gpu_mem_max gadget.
// It is a sister of pkg/operators/nvml/operator_nvml.go (introduced in T-196
// for nvidia_trace_errors) adapted for memory: instead of polling
// GetCurrentClocksEventReasons it polls nvmlDeviceGetMemoryInfo_v2 every
// `poll-interval-ms` and emits one SNAPSHOT event per device per tick.
//
// At stop — or every `max-report-every-ms` — it walks the BPF running_sum /
// high_water maps, groups by mntns via the IG mntns resolver, and emits
// one MAX_REPORT event per container.  It also runs the diagnoseReason()
// ladder and emits SIGNAL_LOSS events when |NVML_used - tracked_sum| >
// signal-loss-threshold-pct.

package operators

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const (
	evAlloc       uint32 = 1
	evFree        uint32 = 2
	evSnapshot    uint32 = 3
	evMaxReport   uint32 = 4
	evSignalLoss  uint32 = 5

	confHigh   uint32 = 2
	confMedium uint32 = 1
	confLow    uint32 = 0
)

type nvmlMemOp struct {
	intervalMs     int
	signalThreshPc float64
	maxReportEvery time.Duration

	mu        sync.Mutex
	maxUsed   []uint64 // per-device high-water of nvml.used
	handles   []nvml.Device

	// Access to the BPF maps for running_sum / high_water / map_full.
	// In-tree this is obtained via ebpfOp.GetMap(name); mocked out here
	// so the file compiles without the full IG build system.
	bpfMaps bpfMapAccess

	snapshotsDS datasource.DataSource
	summaryDS   datasource.DataSource
}

type bpfMapAccess interface {
	// Iterate running_sum (key=pid u32, val=u64 bytes)
	EachRunningSum(func(pid uint32, bytes uint64) bool)
	// Iterate high_water (key=pid u32, val=u64 bytes)
	EachHighWater(func(pid uint32, bytes uint64) bool)
	// Read map_full flag ([1]u32).
	MapFullFlag() bool
	// Resolve pid → mntns_id / container / pod / namespace.
	ResolveContainer(pid uint32) (mntns uint64, container, pod, ns string, ok bool)
}

func NewNvmlMemOp() operators.DataOperator { return &nvmlMemOp{} }

func (op *nvmlMemOp) Name() string { return "nvml_mem" }

func (op *nvmlMemOp) Priority() int { return 10 }

func (op *nvmlMemOp) Init(logger logger.Logger) error { return nil }

func (op *nvmlMemOp) Start(ctx context.Context) error {
	if rc := nvml.Init(); rc != nvml.SUCCESS {
		return fmt.Errorf("nvml.Init: %s", nvml.ErrorString(rc))
	}
	nDev, rc := nvml.DeviceGetCount()
	if rc != nvml.SUCCESS {
		return fmt.Errorf("nvml.DeviceGetCount: %s", nvml.ErrorString(rc))
	}
	op.handles = make([]nvml.Device, 0, nDev)
	op.maxUsed = make([]uint64, nDev)
	for i := 0; i < nDev; i++ {
		d, rc := nvml.DeviceGetHandleByIndex(i)
		if rc != nvml.SUCCESS {
			return fmt.Errorf("GetHandleByIndex(%d): %s", i, nvml.ErrorString(rc))
		}
		op.handles = append(op.handles, d)
	}

	tick := time.NewTicker(time.Duration(op.intervalMs) * time.Millisecond)
	maxRep := time.NewTicker(op.maxReportEvery)

	go func() {
		defer tick.Stop()
		defer maxRep.Stop()
		for {
			select {
			case <-ctx.Done():
				op.emitFinalMaxReport()
				nvml.Shutdown()
				return
			case <-tick.C:
				op.snapshot()
			case <-maxRep.C:
				op.emitMaxReport()
			}
		}
	}()
	return nil
}

func (op *nvmlMemOp) Stop() error { return nil }

// snapshot reads NVML + BPF running_sum sum and emits one SNAPSHOT event
// per device.  If the tracked-vs-NVML delta exceeds signalThreshPc, it
// also emits a SIGNAL_LOSS event with a diagnosed reason.
func (op *nvmlMemOp) snapshot() {
	trackedAll := op.sumRunningSum()
	mapFull := op.bpfMaps.MapFullFlag()

	for dev, h := range op.handles {
		var m nvml.Memory_v2
		m.Version = nvml.STRUCT_VERSION(m, 2)
		if rc := nvml.DeviceGetMemoryInfo_v2(h, &m); rc != nvml.SUCCESS {
			continue
		}
		op.mu.Lock()
		if m.Used > op.maxUsed[dev] {
			op.maxUsed[dev] = m.Used
		}
		op.mu.Unlock()

		delta := int64(m.Used) - int64(trackedAll)
		if delta < 0 {
			delta = 0
		}
		pct := 0.0
		if m.Used > 0 {
			pct = float64(delta) / float64(m.Used) * 100
		}

		op.emitSnapshot(dev, &m, trackedAll, op.maxUsed[dev])

		if pct > op.signalThreshPc {
			reason, conf := diagnoseReason(pct, uint64(delta), mapFull, op.sawManagedAlloc())
			op.emitSignalLoss(dev, uint64(delta), pct, reason, conf)
		}
	}
}

// emitMaxReport walks BPF high_water and emits one MAX_REPORT per
// container, attributing the per-pid max to its mntns → container.
func (op *nvmlMemOp) emitMaxReport() {
	type ctKey struct{ mntns uint64 }
	agg := map[ctKey]struct {
		max            uint64
		allocs, frees  uint64
		container, pod string
		namespace      string
	}{}

	op.bpfMaps.EachHighWater(func(pid uint32, bytes uint64) bool {
		m, ct, pod, ns, ok := op.bpfMaps.ResolveContainer(pid)
		if !ok {
			return true
		}
		k := ctKey{m}
		e := agg[k]
		if bytes > e.max {
			e.max = bytes
		}
		e.container, e.pod, e.namespace = ct, pod, ns
		agg[k] = e
		return true
	})

	trackedAll := op.sumRunningSum()
	for _, e := range agg {
		op.emitSummary(evMaxReport, e.container, e.pod, e.namespace,
			e.max, e.allocs, e.frees, trackedAll)
	}
}

func (op *nvmlMemOp) emitFinalMaxReport() { op.emitMaxReport() }

func (op *nvmlMemOp) sumRunningSum() uint64 {
	var s uint64
	op.bpfMaps.EachRunningSum(func(pid uint32, bytes uint64) bool {
		s += bytes
		return true
	})
	return s
}

// sawManagedAlloc heuristically detects cuMemAllocManaged use in the
// current run.  A full impl keeps a flag set by the BPF ret-probe for
// API_cuMemAllocManaged; stub here for documentation.
func (op *nvmlMemOp) sawManagedAlloc() bool { return false }

// diagnoseReason implements the 6-step signal-loss ladder documented in
// architecture.md §3.5.
func diagnoseReason(pct float64, deltaBytes uint64, mapFull, sawManaged bool) (string, uint32) {
	// HIGH<2%, MEDIUM 2-5%, LOW >5%
	conf := confHigh
	switch {
	case pct >= 5.0:
		conf = confLow
	case pct >= 2.0:
		conf = confMedium
	}

	switch {
	case mapFull:
		return "BPF alloc_by_addr map full - increase max_entries", conf
	case sawManaged:
		return "UVM paging (cuMemAllocManaged detected; residency != allocation)", conf
	case fileExists("/proc/driver/nvidia/capabilities/mig/config"):
		return "MIG partitioning - per-device NVML cannot attribute per-partition", conf
	case mpsActive():
		return "CUDA MPS - untracked context sharing", conf
	case deltaBytes < 500*1024*1024:
		return "Likely CUDA context + cuDNN/cuBLAS workspace overhead (~300-500 MB on A100 is normal)", conf
	default:
		return "Unknown - possibly driver-internal reservation or untraced allocator API", conf
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
func mpsActive() bool          { _, err := os.Stat("/tmp/nvidia-mps/pipe/control"); return err == nil }

func (op *nvmlMemOp) emitSnapshot(dev int, m *nvml.Memory_v2, tracked, max uint64) {
	// … fill datasource packet; omitted for brevity …
}

func (op *nvmlMemOp) emitSignalLoss(dev int, deltaBytes uint64, pct float64, reason string, conf uint32) {
	// …
}

func (op *nvmlMemOp) emitSummary(typ uint32, container, pod, ns string,
	max, allocs, frees, trackedAll uint64) {
	// …
}

func init() { operators.Register(NewNvmlMemOp()) }
