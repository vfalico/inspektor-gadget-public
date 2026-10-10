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

package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"cuda_observability/analyzer"
	"cuda_observability/correlator"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

type outputFields struct {
	ds                                                                                        api.DataSource
	typ, phase, reason, preset, digest, canonical                                             api.Field
	pid, activity, timestamp, start, duration, index, count, launches, copies, ttft, interval api.Field
}

var rawTS, rawPID, rawBytes, rawOp, rawResult api.Field
var activityOut, summaryOut, configOut, healthOut outputFields
var markerTS, markerPID, markerTID, markerEpoch, markerIDHi, markerIDLo, markerSequence, markerVersion, markerPhase, markerFlags, markerReason, markerAccepted, markerLossGeneration api.Field
var markerExitTS, markerExitPID, markerExitTID, markerExitEpoch, markerExitLossGeneration api.Field
var markerIntervalOut, markerHealthOut correlationOutputFields
var engine *analyzer.Analyzer
var markerValidator *correlator.Validator
var enabled, markerEnabled, markerCorrelationReady bool
var markerLibraryPath string
var pipelineMu sync.Mutex
var pipelineClosing bool
var rawDecodeErrorOnce sync.Once
var markerDecodeErrorOnce sync.Once
var exitDecodeErrorOnce sync.Once
var stopOnce sync.Once

type correlationOutputFields struct {
	ds                           api.DataSource
	typ, reason, closeReason     api.Field
	pid, tid                     api.Field
	epoch, idHi, idLo, timestamp api.Field
	start, end, duration         api.Field
}

func parseHeuristics(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("heuristics must be true or false: %q", value)
	}
}

func preset(name string) (analyzer.Config, bool) {
	base := analyzer.Config{Preset: name, RequestGapNS: uint64((100 * time.Millisecond).Nanoseconds()), CandidateGapNS: uint64(time.Millisecond.Nanoseconds()), PrefillMinLaunches: 1, DecodeMinLaunches: 1, CandidateMaxCopyBytes: 1048576, StateTimeoutNS: uint64((5 * time.Second).Nanoseconds()), MaxActivityDurationNS: uint64((120 * time.Second).Nanoseconds())}
	switch name {
	case "generic-conservative-v1":
	case "vllm-0.10.2-qwen2.5-0.5b-a100-sequential":
		base.CandidateGapNS = 900000
	case "vllm-0.10.2-qwen2.5-0.5b-a100-sequential-transition-v2":
		base.RequestGapNS = uint64((12500 * time.Microsecond).Nanoseconds())
		base.CandidateGapNS = uint64((300 * time.Microsecond).Nanoseconds())
		base.DedupWindowNS = uint64((2 * time.Millisecond).Nanoseconds())
		base.DecodeMinLaunches = 0
		base.CandidatePreviousOperationMask = (uint64(1) << 0) | (uint64(1) << 4)
		base.CandidateCurrentOperationMask = uint64(1) << 6
	case "vllm-0.10.2-qwen2.5-0.5b-a100-sequential-transition-v3":
		base.RequestGapNS = uint64((12500 * time.Microsecond).Nanoseconds())
		base.CandidateGapNS = uint64((300 * time.Microsecond).Nanoseconds())
		base.DedupWindowNS = uint64((2 * time.Millisecond).Nanoseconds())
		base.DecodeMinLaunches = 0
		base.CandidatePreviousOperationMask = (uint64(1) << 0) | (uint64(1) << 4)
		base.CandidateCurrentOperationMask = uint64(1) << 6
		base.CandidatePairWindowNS = uint64((3 * time.Millisecond).Nanoseconds())
	case "tgi-3.3.6-qwen2.5-0.5b-a100-sequential":
		base.CandidateGapNS = 1050000
		base.DedupWindowNS = 2000000
	case "ollama-0.11.10-qwen2.5-0.5b-q4km-a100-sequential":
		base.CandidateGapNS = 2100000
	case "llamacpp-b6602-qwen2.5-0.5b-q4km-a100-sequential":
		base.CandidateGapNS = 150000
		base.MinActivityOffsetNS = 2000000
	case "ctranslate2-4.6.0-qwen2.5-0.5b-a100-sequential":
		base.CandidateGapNS = 300000
		base.MinActivityOffsetNS = 15000000
	case "exllamav2-0.3.2-qwen2.5-0.5b-exl2-a100-sequential":
		base.CandidateGapNS = 1050000
	case "transformers-4.56.1-qwen2.5-0.5b-a100-sequential":
		base.CandidateGapNS = 700000
		base.MinActivityOffsetNS = 15000000
	default:
		return analyzer.Config{}, false
	}
	return base, true
}
func param(key string) string {
	s, e := api.GetParamValue(key, 128)
	if e != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func resolveMarkerLibrary() (string, error) {
	library := param("request-marker-library")
	if library == "" {
		return "", nil
	}
	if !strings.HasPrefix(library, "/") || strings.Contains(library, ":") {
		return "", fmt.Errorf("request-marker-library must be an absolute path without ':'")
	}
	return library, nil
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	library, err := resolveMarkerLibrary()
	if err != nil {
		api.Errorf("%s", err)
		return 1
	}
	if library == "" {
		return 0
	}
	if !markerCorrelationReady || markerLibraryPath != library {
		api.Errorf("request marker correlation was not initialized for configured library")
		return 1
	}
	api.SetConfig(
		"programs.request_marker_v1.attach_to",
		library+":ig_gpu_request_marker_v1",
	)
	return 0
}

func durationOverride(key string, dst *uint64) error {
	s := param(key)
	if s == "" {
		return nil
	}
	d, e := time.ParseDuration(s)
	if e != nil || d < 0 {
		return fmt.Errorf("%s must be a non-negative duration: %q", key, s)
	}
	*dst = uint64(d)
	return nil
}
func uintOverride(key string, dst *uint64) error {
	s := param(key)
	if s == "" {
		return nil
	}
	v, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		return fmt.Errorf("%s must be uint: %q", key, s)
	}
	*dst = v
	return nil
}
func resolve() (analyzer.Config, error) {
	name := param("preset")
	if name == "" {
		name = "generic-conservative-v1"
	}
	c, ok := preset(name)
	if !ok {
		return c, fmt.Errorf("unknown preset %q", name)
	}
	for _, x := range []struct {
		k string
		p *uint64
	}{{"request-gap", &c.RequestGapNS}, {"candidate-gap", &c.CandidateGapNS}, {"dedup-window", &c.DedupWindowNS}, {"candidate-pair-window", &c.CandidatePairWindowNS}, {"state-timeout", &c.StateTimeoutNS}, {"max-activity-duration", &c.MaxActivityDurationNS}, {"min-activity-offset", &c.MinActivityOffsetNS}} {
		if e := durationOverride(x.k, x.p); e != nil {
			return c, e
		}
	}
	for _, x := range []struct {
		k string
		p *uint64
	}{{"prefill-min-launches", &c.PrefillMinLaunches}, {"prefill-min-copies", &c.PrefillMinCopies}, {"decode-min-launches", &c.DecodeMinLaunches}, {"candidate-max-copy-bytes", &c.CandidateMaxCopyBytes}} {
		if e := uintOverride(x.k, x.p); e != nil {
			return c, e
		}
	}
	if c.RequestGapNS == 0 || c.CandidateGapNS == 0 || c.StateTimeoutNS == 0 || c.MaxActivityDurationNS == 0 {
		return c, fmt.Errorf("gap, timeout and duration values must be >0")
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}
func add(ds api.DataSource, name string, k api.FieldKind) (api.Field, error) {
	return ds.AddField(name, k)
}
func newOutput(name string) (outputFields, error) {
	var o outputFields
	var e error
	o.ds, e = api.NewDataSource(name, api.DataSourceTypeSingle)
	if e != nil {
		return o, e
	}
	for _, x := range []struct {
		n string
		p *api.Field
	}{{"type", &o.typ}, {"phase", &o.phase}, {"close_reason", &o.reason}, {"preset", &o.preset}, {"config_digest", &o.digest}, {"config_canonical", &o.canonical}} {
		*x.p, e = add(o.ds, x.n, api.Kind_String)
		if e != nil {
			return o, e
		}
	}
	for _, x := range []struct {
		n string
		p *api.Field
	}{{"pid", &o.pid}, {"activity_id", &o.activity}, {"timestamp_ns", &o.timestamp}, {"activity_start_ns", &o.start}, {"duration_ns", &o.duration}, {"candidate_index", &o.index}, {"candidate_count", &o.count}, {"launch_count", &o.launches}, {"copy_count", &o.copies}, {"ttft_candidate_ns", &o.ttft}, {"interval_candidate_ns", &o.interval}} {
		*x.p, e = add(o.ds, x.n, api.Kind_Uint64)
		if e != nil {
			return o, e
		}
	}
	return o, nil
}

func newCorrelationOutput(name string) (correlationOutputFields, error) {
	var o correlationOutputFields
	var e error
	o.ds, e = api.NewDataSource(name, api.DataSourceTypeSingle)
	if e != nil {
		return o, e
	}
	for _, x := range []struct {
		n string
		p *api.Field
	}{{"type", &o.typ}, {"reason", &o.reason}, {"close_reason", &o.closeReason}} {
		*x.p, e = add(o.ds, x.n, api.Kind_String)
		if e != nil {
			return o, e
		}
	}
	for _, x := range []struct {
		n string
		p *api.Field
	}{{"pid", &o.pid}, {"tid", &o.tid}, {"process_epoch", &o.epoch}, {"request_id_hi", &o.idHi}, {"request_id_lo", &o.idLo}, {"timestamp_ns", &o.timestamp}, {"start_ns", &o.start}, {"end_ns", &o.end}, {"duration_ns", &o.duration}} {
		*x.p, e = add(o.ds, x.n, api.Kind_Uint64)
		if e != nil {
			return o, e
		}
	}
	return o, nil
}

func emit(o outputFields, r analyzer.Record) error {
	p, e := o.ds.NewPacketSingle()
	if e != nil {
		return e
	}
	d := api.Data(p)
	r.Preset = engine.Config.Preset
	r.ConfigDigest = engine.Config.Digest()
	r.ConfigCanonical = engine.Config.Canonical()
	_ = o.typ.SetString(d, r.Type)
	_ = o.phase.SetString(d, r.Phase)
	_ = o.reason.SetString(d, r.CloseReason)
	_ = o.preset.SetString(d, r.Preset)
	_ = o.digest.SetString(d, r.ConfigDigest)
	_ = o.canonical.SetString(d, r.ConfigCanonical)
	_ = o.pid.SetUint64(d, uint64(r.PID))
	_ = o.activity.SetUint64(d, r.ActivityID)
	_ = o.timestamp.SetUint64(d, r.TimestampNS)
	_ = o.start.SetUint64(d, r.ActivityStartNS)
	_ = o.duration.SetUint64(d, r.DurationNS)
	_ = o.index.SetUint64(d, r.CandidateIndex)
	_ = o.count.SetUint64(d, r.CandidateCount)
	_ = o.launches.SetUint64(d, r.LaunchCount)
	_ = o.copies.SetUint64(d, r.CopyCount)
	_ = o.ttft.SetUint64(d, r.TTFTCandidateNS)
	_ = o.interval.SetUint64(d, r.IntervalCandidateNS)
	return o.ds.EmitAndRelease(api.Packet(p))
}

func emitCorrelation(o correlationOutputFields, r correlator.Record) error {
	p, e := o.ds.NewPacketSingle()
	if e != nil {
		return e
	}
	d := api.Data(p)
	_ = o.typ.SetString(d, r.Type)
	_ = o.reason.SetString(d, r.Reason)
	_ = o.closeReason.SetString(d, r.CloseReason)
	_ = o.pid.SetUint64(d, uint64(r.PID))
	_ = o.tid.SetUint64(d, uint64(r.TID))
	_ = o.epoch.SetUint64(d, r.ProcessEpoch)
	_ = o.idHi.SetUint64(d, r.RequestIDHi)
	_ = o.idLo.SetUint64(d, r.RequestIDLo)
	_ = o.timestamp.SetUint64(d, r.TimestampNS)
	_ = o.start.SetUint64(d, r.StartNS)
	_ = o.end.SetUint64(d, r.EndNS)
	_ = o.duration.SetUint64(d, r.DurationNS)
	return o.ds.EmitAndRelease(api.Packet(p))
}

func emitCorrelationRecords(records []correlator.Record) {
	for _, record := range records {
		if record.Type == "request_epoch" || record.Type == "request_process_exit" {
			continue
		}
		if record.Type == "request_interval" {
			_ = emitCorrelation(markerIntervalOut, record)
			continue
		}
		_ = emitCorrelation(markerHealthOut, record)
	}
}

func recordRoute(typ string) string {
	switch typ {
	case "activity_summary":
		return "summary"
	case "analyzer_health":
		return "health"
	default:
		return "activity"
	}
}
func emitRecord(r analyzer.Record) error {
	switch recordRoute(r.Type) {
	case "summary":
		return emit(summaryOut, r)
	case "health":
		return emit(healthOut, r)
	default:
		return emit(activityOut, r)
	}
}
func emitConfig() error {
	r := analyzer.Record{Type: "effective_config", Preset: engine.Config.Preset, ConfigDigest: engine.Config.Digest()}
	return emit(configOut, r)
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var e error
	markerLibraryPath, e = resolveMarkerLibrary()
	if e != nil {
		api.Errorf("invalid request marker configuration: %s", e)
		return 1
	}
	markerEnabled = markerLibraryPath != ""
	enabled, e = parseHeuristics(param("heuristics"))
	if e != nil {
		api.Errorf("invalid heuristic configuration: %s", e)
		return 1
	}
	if enabled {
		if e = setupHeuristics(); e != nil {
			api.Errorf("initialize CUDA inference heuristics: %s", e)
			return 1
		}
	}
	if markerEnabled {
		if e = setupMarkerCorrelation(); e != nil {
			api.Errorf("initialize request marker correlation: %s", e)
			return 1
		}
	}
	if !enabled && !markerEnabled {
		api.Info("CUDA inference heuristics and request correlation disabled; raw cuda_calls output is unchanged")
	}
	return 0
}

func setupHeuristics() error {
	c, e := resolve()
	if e != nil {
		return e
	}
	engine = analyzer.New(c)
	raw, e := api.GetDataSource("cuda_calls")
	if e != nil {
		return fmt.Errorf("raw datasource: %w", e)
	}
	for _, x := range []struct {
		n string
		p *api.Field
	}{{"timestamp_raw", &rawTS}, {"proc.pid", &rawPID}, {"bytes", &rawBytes}, {"operation_raw", &rawOp}, {"result", &rawResult}} {
		*x.p, e = raw.GetField(x.n)
		if e != nil {
			return fmt.Errorf("raw field %s: %w", x.n, e)
		}
	}
	activityOut, e = newOutput("inference_activity")
	if e != nil {
		return fmt.Errorf("activity output: %w", e)
	}
	summaryOut, e = newOutput("inference_summary")
	if e != nil {
		return fmt.Errorf("summary output: %w", e)
	}
	configOut, e = newOutput("effective_config")
	if e != nil {
		return fmt.Errorf("config output: %w", e)
	}
	healthOut, e = newOutput("analyzer_health")
	if e != nil {
		return fmt.Errorf("health output: %w", e)
	}
	e = raw.Subscribe(func(_ api.DataSource, d api.Data) {
		ts, x := rawTS.Uint64(d)
		if x != nil {
			rawDecodeErrorOnce.Do(func() {
				api.Errorf("decode cuda_calls.timestamp_raw: %s", x)
			})
			return
		}
		pid, x := rawPID.Uint32(d)
		if x != nil {
			rawDecodeErrorOnce.Do(func() {
				api.Errorf("decode cuda_calls.proc.pid: %s", x)
			})
			return
		}
		b, _ := rawBytes.Uint64(d)
		op, _ := rawOp.Uint32(d)
		res, _ := rawResult.Int32(d)
		pipelineMu.Lock()
		if pipelineClosing {
			pipelineMu.Unlock()
			return
		}
		records := engine.Feed(analyzer.Event{PID: pid, TimestampNS: ts, Bytes: b, Operation: op, Result: res})
		pipelineMu.Unlock()
		for _, r := range records {
			_ = emitRecord(r)
		}
	}, 0)
	if e != nil {
		return fmt.Errorf("subscribe: %w", e)
	}
	return nil
}

func setupMarkerCorrelation() error {
	reorderWindowNS := uint64(50 * time.Millisecond)
	stateTimeoutNS := uint64(5 * time.Minute)
	if e := durationOverride("request-marker-reorder-window", &reorderWindowNS); e != nil {
		return e
	}
	if e := durationOverride("request-marker-state-timeout", &stateTimeoutNS); e != nil {
		return e
	}
	if reorderWindowNS == 0 || stateTimeoutNS == 0 {
		return fmt.Errorf("request marker reorder window and state timeout must be >0")
	}
	markerValidator = correlator.New(correlator.Config{
		ReorderWindowNS: reorderWindowNS,
		StateTimeoutNS:  stateTimeoutNS,
	})

	raw, e := api.GetDataSource("request_markers")
	if e != nil {
		return fmt.Errorf("request marker datasource: %w", e)
	}
	for _, x := range []struct {
		n string
		p *api.Field
	}{{"timestamp_raw", &markerTS}, {"proc.pid", &markerPID}, {"proc.tid", &markerTID}, {"process_epoch", &markerEpoch}, {"request_id_hi", &markerIDHi}, {"request_id_lo", &markerIDLo}, {"request_sequence", &markerSequence}, {"protocol_version", &markerVersion}, {"phase_raw", &markerPhase}, {"flags", &markerFlags}, {"reason", &markerReason}, {"transition_accepted", &markerAccepted}, {"loss_generation", &markerLossGeneration}} {
		*x.p, e = raw.GetField(x.n)
		if e != nil {
			return fmt.Errorf("request marker field %s: %w", x.n, e)
		}
	}
	markerIntervalOut, e = newCorrelationOutput("request_intervals")
	if e != nil {
		return fmt.Errorf("request interval output: %w", e)
	}
	markerHealthOut, e = newCorrelationOutput("request_correlation_health")
	if e != nil {
		return fmt.Errorf("request correlation health output: %w", e)
	}
	e = raw.Subscribe(func(_ api.DataSource, d api.Data) {
		timestamp, err := markerTS.Uint64(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.timestamp_raw: %s", err)
			})
			return
		}
		pid, err := markerPID.Uint32(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.proc.pid: %s", err)
			})
			return
		}
		tid, err := markerTID.Uint32(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.proc.tid: %s", err)
			})
			return
		}
		epoch, err := markerEpoch.Uint64(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.process_epoch: %s", err)
			})
			return
		}
		idHi, err := markerIDHi.Uint64(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.request_id_hi: %s", err)
			})
			return
		}
		idLo, err := markerIDLo.Uint64(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.request_id_lo: %s", err)
			})
			return
		}
		requestSequence, err := markerSequence.Uint64(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.request_sequence: %s", err)
			})
			return
		}
		version, err := markerVersion.Uint32(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.protocol_version: %s", err)
			})
			return
		}
		phase, err := markerPhase.Uint32(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.phase_raw: %s", err)
			})
			return
		}
		flags, err := markerFlags.Uint32(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.flags: %s", err)
			})
			return
		}
		reason, err := markerReason.Uint32(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.reason: %s", err)
			})
			return
		}
		accepted, err := markerAccepted.Uint32(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.transition_accepted: %s", err)
			})
			return
		}
		lossGeneration, err := markerLossGeneration.Uint64(d)
		if err != nil {
			markerDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_markers.loss_generation: %s", err)
			})
			return
		}
		pipelineMu.Lock()
		if pipelineClosing {
			pipelineMu.Unlock()
			return
		}
		records := markerValidator.Feed(correlator.Marker{
			PID:             pid,
			TID:             tid,
			TimestampNS:     timestamp,
			ProcessEpoch:    epoch,
			RequestIDHi:     idHi,
			RequestIDLo:     idLo,
			RequestSequence: requestSequence,
			ProtocolVersion: version,
			Phase:           phase,
			Flags:           flags,
			Reason:          reason,
			LossGeneration:  lossGeneration,
			Accepted:        accepted != 0,
		})
		pipelineMu.Unlock()
		emitCorrelationRecords(records)
	}, 0)
	if e != nil {
		return fmt.Errorf("request marker subscribe: %w", e)
	}
	exits, e := api.GetDataSource("request_process_exits")
	if e != nil {
		return fmt.Errorf("request process exit datasource: %w", e)
	}
	for _, x := range []struct {
		n string
		p *api.Field
	}{{"timestamp_raw", &markerExitTS}, {"proc.pid", &markerExitPID}, {"proc.tid", &markerExitTID}, {"process_epoch", &markerExitEpoch}, {"loss_generation", &markerExitLossGeneration}} {
		*x.p, e = exits.GetField(x.n)
		if e != nil {
			return fmt.Errorf("request process exit field %s: %w", x.n, e)
		}
	}
	e = exits.Subscribe(func(_ api.DataSource, d api.Data) {
		timestamp, err := markerExitTS.Uint64(d)
		if err != nil {
			exitDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_process_exits.timestamp_raw: %s", err)
			})
			return
		}
		pid, err := markerExitPID.Uint32(d)
		if err != nil {
			exitDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_process_exits.proc.pid: %s", err)
			})
			return
		}
		tid, err := markerExitTID.Uint32(d)
		if err != nil {
			exitDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_process_exits.proc.tid: %s", err)
			})
			return
		}
		epoch, err := markerExitEpoch.Uint64(d)
		if err != nil {
			exitDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_process_exits.process_epoch: %s", err)
			})
			return
		}
		lossGeneration, err := markerExitLossGeneration.Uint64(d)
		if err != nil {
			exitDecodeErrorOnce.Do(func() {
				api.Errorf("decode request_process_exits.loss_generation: %s", err)
			})
			return
		}
		pipelineMu.Lock()
		if pipelineClosing {
			pipelineMu.Unlock()
			return
		}
		records := markerValidator.FeedProcessExit(pid, tid, epoch, timestamp, lossGeneration)
		pipelineMu.Unlock()
		emitCorrelationRecords(records)
	}, 0)
	if e != nil {
		return fmt.Errorf("request process exit subscribe: %w", e)
	}
	markerCorrelationReady = true
	return nil
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	if enabled {
		if e := emitConfig(); e != nil {
			api.Errorf("emit config: %s", e)
			return 1
		}
		api.Infof("CUDA inference heuristics enabled: %s %s", engine.Config.Preset, engine.Config.Digest())
	}
	if markerEnabled {
		if !markerCorrelationReady {
			api.Errorf("CUDA request marker correlation is enabled but not initialized")
			return 1
		}
		api.Info("CUDA request marker correlation enabled")
	}
	return 0
}

//go:wasmexport gadgetStop
func gadgetStop() int32 {
	stopOnce.Do(func() {
		api.Info("stopping CUDA observability analysis")
		pipelineMu.Lock()
		pipelineClosing = true
		var analyzerRecords []analyzer.Record
		var correlationRecords []correlator.Record
		if enabled {
			analyzerRecords = engine.CloseAll("gadget_stop")
		}
		if markerCorrelationReady {
			correlationRecords = markerValidator.Close()
		}
		pipelineMu.Unlock()
		for _, record := range analyzerRecords {
			_ = emitRecord(record)
		}
		emitCorrelationRecords(correlationRecords)
		api.Info("stopped CUDA observability analysis")
	})
	return 0
}
func main() {}
