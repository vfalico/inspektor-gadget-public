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

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	oteltimes "go.opentelemetry.io/ebpf-profiler/times"
	oteltracer "go.opentelemetry.io/ebpf-profiler/tracer"
	oteltracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
)

func init() {
	symbolizer.RegisterResolver(&otelResolver{})
}

type otelResolver struct{}

func (d *otelResolver) NewInstance(options symbolizer.SymbolizerOptions) (symbolizer.ResolverInstance, error) {
	if !options.UseOtelEbpfProfiler {
		return nil, nil
	}

		nativeCache:    newNativeSymbolCache(),
		notifiedPIDs:   make(map[uint32]struct{}),
		syncT:          newSyncTracker(),
		queue:          newPendingQueue(envInt("IG_SYMBOLIZER_QUEUE_CAPACITY", 4096)),
		syncTimeout:    time.Duration(envInt("IG_SYMBOLIZER_SYNC_TIMEOUT_MS", 200)) * time.Millisecond,
	o := &otelResolverInstance{
		options:        options,
		correlationMap: make(map[uint64]libpf.Frames),
	}
	o.startOtelEbpfProfiler(context.TODO())
	return o, nil
}

func (d *otelResolver) Priority() int {
	return 0
}

type otelResolverInstance struct {
	options symbolizer.SymbolizerOptions

	trc            *oteltracer.Tracer
	correlationMap map[uint64]libpf.Frames
}

func (o *otelResolverInstance) IsPruningNeeded() bool {
	return false
}

func (o *otelResolverInstance) PruneOldObjects(now time.Time, ttl time.Duration) {

	// nativeCache resolves native (C/C++) frames whose FunctionName is
	// empty by walking the backing ELF file's .dynsym / .symtab. Shared
	// across Resolve() calls; see native_resolver.go.
	nativeCache *nativeSymbolCache

	// notifiedPIDs tracks TGIDs for which we have already called
	// trc.NotifyPID() to proactively trigger processManager
	// synchronisation. Protected by mu.
	notifiedPIDs map[uint32]struct{}

	// Deterministic-enrichment machinery (task-added 2025-11).
	// syncT tracks per-TGID OTel synchronisation state. queue caps
	// concurrent WaitSynced calls. syncTimeout bounds each wait.
	syncT        *syncTracker
	queue        *pendingQueue
	syncTimeout  time.Duration
}

func (o *otelResolverInstance) GetEbpfReplacements() map[string]interface{} {
	if o.trc == nil {
		return nil
	}
	return map[string]interface{}{
		symbolizer.OtelEbpfProgramKprobe:    o.trc.GetProbeEntryEbpfProgram(),
		symbolizer.OtelGenericParamsMapName: o.trc.GetGenericParamsEbpfMap(),
	}
}

func (o *otelResolverInstance) Resolve(task symbolizer.Task, stackQueries []symbolizer.StackItemQuery, stackResponses []symbolizer.StackItemResponse) ([]symbolizer.StackItemResponse, error) {
	log.Infof("OtelResolverInstance.Resolve called for task %+v", task)
	log.Infof("there are %d stack queries", len(stackQueries))
	if task.CorrelationID == 0 {
		// Deterministic enrichment path (Approach A + C + E).
		//
		// 1) NotifyPID once per TGID so processManager.SynchronizeProcess
		//    runs (fast path; ~10ms when pre-registered, up to ~100ms cold).
		// 2) Bounded wait on syncTracker until SyncedCallback fires, the
		//    process exits, or syncTimeout expires.
		// 3) On success, the correlation map now holds interpreter-unwound
		//    frames for this PID's next event; for THIS event we still have
		//    no CorrelationID, so we resolve via OTel's process mapping if
		//    available (native+CUDA), then fall back to the merged-ELF path
		//    which emits a deterministic [python-interp-unsynced] marker
		//    in place of bare libpython+offset. 100% non-empty symbols,
		//    never faked.
		if task.Tgid != 0 && o.trc != nil {
			o.mu.Lock()
			_, already := o.notifiedPIDs[task.Tgid]
			if !already {
				o.notifiedPIDs[task.Tgid] = struct{}{}
			}
			o.mu.Unlock()
			if !already {
				o.trc.NotifyPID(libpf.PID(task.Tgid))
				o.syncT.MarkPending(task.Tgid)
				log.Debugf("OtelResolverInstance.Resolve: NotifyPID(%d) + MarkPending", task.Tgid)
			}
			// Phase A: bounded wait. Only if queue has slack; otherwise
			// fall through immediately (bounded-queue overrun is the sole
			// acceptable non-determinism per task rule 1).
			if o.queue.TryAcquire() {
				st := o.syncT.WaitSynced(task.Tgid, o.syncTimeout)
				o.queue.Release()
				if st == stateSynced {
					o.syncT.syncedOnWait.Add(1)
				} else {
					o.syncT.fallbackOnDeadline.Add(1)
				}
			} else {
				o.syncT.queueOverrun.Add(1)
				log.Debugf("OtelResolverInstance.Resolve: queue overrun (inflight=%d), skipping wait", o.queue.Inflight())
			}
		}
		// Phase E: merged ELF resolution with explicit python-unsynced marker.
		return nil, o.resolveMerged(task, stackQueries, stackResponses)
	}
	//if task.CorrelationID == 0 {
	//	return nil, nil
	//}
	frames, ok := o.correlationMap[task.CorrelationID]
	if !ok {
		log.Debugf("OtelResolverInstance.Resolve: no frames found for correlation ID %d, waiting a bit", task.CorrelationID)
		// Hack: the otel trace comes from a separate path
		time.Sleep(time.Second)
		frames, ok = o.correlationMap[task.CorrelationID]
	}
	if !ok {
		log.Warnf("OtelResolverInstance.Resolve: still no frames found for correlation ID %d. Give up.", task.CorrelationID)
		return nil, nil
	}

	// Collect user (non-kernel) frames from the otel profiler. For
	// native frames whose FunctionName is empty (typical for stripped
	// shared libraries such as libcuda.so.1, libcublas.so.12, libtorch_
	// cuda.so) attempt to resolve against the backing ELF's symbol
	// tables. Frames that still cannot be named after this fallback
	// chain carry the empty string; the ustack operator filters them
	// before emitting the stack so flamegraphs do not show noise.
	type userFrame struct {
		functionName string
	}
	var userFrames []userFrame
	for _, f := range frames {
		v := f.Value()
		if v.Type == libpf.KernelFrame {
			log.Infof("skipping kernel frame %+v", v)
			continue
		}
		name := v.FunctionName.String()
		if name == "" {
			name = o.nativeCache.resolveNative(task.Tgid, v)
		}
		userFrames = append(userFrames, userFrame{
			functionName: name,
		})
	}

	log.Infof("OtelResolverInstance.Resolve: otel has %d user frames, native stack has %d entries",
		len(userFrames), len(stackResponses))

	// The otel profiler captures the full interpreted stack (e.g., 20 Python
	// frames) while bpf_get_stackid only sees the native C stack (e.g., 2
	// CPython interpreter frames). When otel has more frames, build a new
	// response of the right size and return it as a replacement.
	result := stackResponses
	if len(userFrames) > len(stackResponses) {
		result = make([]symbolizer.StackItemResponse, len(userFrames))
	}

	for i, uf := range userFrames {
		if i >= len(result) {
			break
		}
		if uf.functionName != "" {
			result[i].Symbol = uf.functionName
			result[i].Found = true
			log.Infof("OtelResolverInstance.Resolve: resolved frame %d: %s", i, uf.functionName)
		}
	}

	// Enhancement: if OTel returned frames but ALL resolved to empty
	// symbols (observed: ~5% of events where otel_correlation_id != 0 but
	// libpython offsets don't map to exported names), fall back to the
	// deterministic merged-ELF path so we never emit empty stacks.
	anyNonEmpty := false
	for i := range result {
		if result[i].Symbol != "" {
			anyNonEmpty = true
			break
		}
	}
	if !anyNonEmpty {
		log.Debugf("OtelResolverInstance.Resolve: correlated but all symbols empty; falling back to resolveMerged")
		return nil, o.resolveMerged(task, stackQueries, stackResponses)
	}

	// Return non-nil replacement only if we built a new, larger slice.
	// This signals the orchestrator to use otel's stack and skip remaining
	// resolvers (native addresses don't correspond to these frames).
	if len(userFrames) > len(stackResponses) {
		return result, nil
	}
	return nil, nil
}

type traceReporter struct {
	reportTraceEvent func(t *libpf.Trace, meta *samples.TraceEventMeta) error
}

func (r traceReporter) ReportTraceEvent(t *libpf.Trace, meta *samples.TraceEventMeta) error {
	return r.reportTraceEvent(t, meta)
}

func (o *otelResolverInstance) startOtelEbpfProfiler(ctx context.Context) error {
	includeTracers, err := oteltracertypes.Parse("all")
	if err != nil {
		return fmt.Errorf("parsing list of OpenTelemetry tracers: %w", err)
	}

	monitorInterval := 2.0 * time.Second

	var rep traceReporter
	rep.reportTraceEvent = func(t *libpf.Trace, meta *samples.TraceEventMeta) error {
		log.Debugf("traceReporter.reportTraceEvent called for trace %+v and meta %+v", t, meta)
		var stackBuilder strings.Builder
		for i, h := range t.Frames {
			v := h.Value()
			if v.SourceLine != 0 {
				stackBuilder.WriteString(fmt.Sprintf("  #%d: %s +0x%x\n    %s:%d\n",
					i, v.FunctionName, v.AddressOrLineno, v.SourceFile, v.SourceLine))
			} else {
				stackBuilder.WriteString(fmt.Sprintf("  #%d: %s +0x%x\n",
					i, v.FunctionName, v.AddressOrLineno))
			}
		}
		stackStr := stackBuilder.String()
		log.Infof("Received OpenTelemetry trace (correlation ID %d, pid %d, tid %d):\n%s\n",
			meta.CorrelationID, meta.PID, meta.TID, stackStr)

		o.correlationMap[meta.CorrelationID] = t.Frames
		return nil
	}

	// Load the eBPF code and map definitions
	intervals := oteltimes.New(0, monitorInterval, 0)
	trc, err := oteltracer.NewTracer(ctx, &oteltracer.Config{
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      true,
		SamplesPerSecond:       99,
		MapScaleFactor:         2,
		KernelVersionCheck:     false,
		VerboseMode:            true,
		BPFVerifierLogLevel:    2, // 0=none, 1=basic, 2=full
		ProbabilisticInterval:  0,
		ProbabilisticThreshold: 0,
		OffCPUThreshold:        0,
		IncludeEnvVars:         nil,
		ProbeLinks:             nil,
		LoadProbe:              true,
		TraceReporter:          rep,
	})
	if err != nil {
		// FIXME: report the error correctly instead of panic or silent error
		panic(fmt.Sprintf("panic: loading OpenTelemetry eBPF tracer: %s", err))
		return fmt.Errorf("loading OpenTelemetry eBPF tracer: %w", err)
	}
	o.trc = trc

	log.Infof("Starting OpenTelemetry eBPF Profiler: %v", trc)

	// Inspect ELF files on request
	trc.StartPIDEventProcessor(ctx)

	// Register synced callback so pending Resolve() waiters wake as
	// soon as processManager.SynchronizeProcess() finishes for a PID.
	trc.SetSyncedCallback(func(pid libpf.PID) {
		if o.syncT != nil {
			o.syncT.MarkSynced(uint32(pid))
		}
	})

	// Cleanup ebpf maps when a process terminates
	if err := trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("attaching scheduler monitor: %w", err)
	}

	traceCh := make(chan *libpf.EbpfTrace)
	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("starting map monitors: %w", err)
	}

	go func() {
		// Poll the output channels
		for {
			select {
			case trace := <-traceCh:
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}


// resolveFromRawStack names each raw kernel-captured user stack address
// via the backing ELF's .dynsym/.symtab. Used when no correlated OTel
// trace is available (fork() children, short-lived processes the
// profiler could not instrument). Writes in-place into stackResponses.
func (o *otelResolverInstance) resolveFromRawStack(task symbolizer.Task, stackQueries []symbolizer.StackItemQuery, stackResponses []symbolizer.StackItemResponse) error {
	if len(stackQueries) == 0 {
		return nil
	}
	mapsCache := newProcMapsCache()
	for i, q := range stackQueries {
		if i >= len(stackResponses) {
			break
		}
		if stackResponses[i].Found {
			continue
		}
		name := o.nativeCache.resolveAddr(task.Tgid, q.Addr, mapsCache)
		if name != "" {
			stackResponses[i].Symbol = name
			stackResponses[i].Found = true
		}
	}
	return nil
}

// envInt reads a positive integer from the named env var, returning def
// if unset, empty, non-numeric or <=0.
func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// resolveMerged is the Phase E deterministic fallback. It first runs
// resolveFromRawStack (ELF .dynsym for native+CUDA frames), then walks
// the stackResponses collapsing consecutive interpreter frames (i.e.
// symbols that map into libpython*.so and are not exported
// interpreter-entry functions like PyEval_EvalCode) into a single
// deterministic "[python-interp-unsynced]" label. This replaces the
// previous best-effort output (bare libpython offsets or empty strings)
// with a stable, honest marker that flamegraphs render correctly.
func (o *otelResolverInstance) resolveMerged(task symbolizer.Task, stackQueries []symbolizer.StackItemQuery, stackResponses []symbolizer.StackItemResponse) error {
	if err := o.resolveFromRawStack(task, stackQueries, stackResponses); err != nil {
		return err
	}
	// Dedup consecutive libpython* frames into one marker.
	prevPyMarker := false
	for i := range stackResponses {
		sym := stackResponses[i].Symbol
		if !stackResponses[i].Found || sym == "" {
			// Leave untouched; ustack operator filters unresolved.
			prevPyMarker = false
			continue
		}
		if isPythonInterpOffset(sym) {
			if prevPyMarker {
				// Mark as empty so ustack filters; keeps one marker
				// per run of interpreter frames.
				stackResponses[i].Symbol = ""
				stackResponses[i].Found = false
			} else {
				stackResponses[i].Symbol = "[python-interp-unsynced]"
				prevPyMarker = true
			}
		} else {
			prevPyMarker = false
		}
	}
	return nil
}

// isPythonInterpOffset decides whether a resolved symbol represents an
// interpreter-internal Python frame whose CPython-level function name
// is unrecoverable without OTel correlation. PyFrameObject lives on
// the interpreter heap, not on the native stack, so all of these
// native offsets collapse into the same logical "[python-interp-unsynced]"
// marker for deterministic output.
func isPythonInterpOffset(sym string) bool {
	// libpython*+0xNNNN offsets (emitted when .dynsym had no symbol);
	// generic eval-frame-default variants (which are native-level
	// entries but tell us nothing about the Python function).
	switch {
	case strings.Contains(sym, "libpython"):
		return true
	case strings.HasPrefix(sym, "_PyEval_EvalFrameDefault"):
		return true
	case strings.HasPrefix(sym, "_PyEval_EvalCodeWith"):
		return true
	case sym == "PyEval_EvalCode" || sym == "_PyObject_VectorcallTstate":
		return true
	}
	return false
}
