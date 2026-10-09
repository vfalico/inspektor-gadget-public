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

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

type outputFields struct {
	ds                                                                                        api.DataSource
	typ, phase, reason, preset, digest, canonical                                             api.Field
	pid, activity, timestamp, start, duration, index, count, launches, copies, ttft, interval api.Field
}

var rawTS, rawPID, rawBytes, rawOp, rawResult api.Field
var activityOut, summaryOut, configOut, healthOut outputFields
var engine *analyzer.Analyzer
var enabled bool
var expiryStop chan struct{}
var clockMu sync.Mutex
var clockRaw uint64
var clockWall time.Time

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
	}{{"request-gap", &c.RequestGapNS}, {"candidate-gap", &c.CandidateGapNS}, {"dedup-window", &c.DedupWindowNS}, {"state-timeout", &c.StateTimeoutNS}, {"max-activity-duration", &c.MaxActivityDurationNS}, {"min-activity-offset", &c.MinActivityOffsetNS}} {
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
	if c.RequestGapNS == 0 || c.CandidateGapNS == 0 || c.DecodeMinLaunches == 0 || c.StateTimeoutNS == 0 || c.MaxActivityDurationNS == 0 {
		return c, fmt.Errorf("gap, timeout, duration and decode-min-launches values must be >0")
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
	enabled, e = parseHeuristics(param("heuristics"))
	if e != nil {
		api.Errorf("invalid heuristic configuration: %s", e)
		return 1
	}
	if !enabled {
		api.Info("CUDA inference heuristics disabled; raw cuda_calls output is unchanged")
		return 0
	}
	c, e := resolve()
	if e != nil {
		api.Errorf("invalid heuristic configuration: %s", e)
		return 1
	}
	engine = analyzer.New(c)
	raw, e := api.GetDataSource("cuda_calls")
	if e != nil {
		api.Errorf("raw datasource: %s", e)
		return 1
	}
	for _, x := range []struct {
		n string
		p *api.Field
	}{{"timestamp_raw", &rawTS}, {"proc.pid", &rawPID}, {"bytes", &rawBytes}, {"operation_raw", &rawOp}, {"result", &rawResult}} {
		*x.p, e = raw.GetField(x.n)
		if e != nil {
			api.Errorf("raw field %s: %s", x.n, e)
			return 1
		}
	}
	activityOut, e = newOutput("inference_activity")
	if e != nil {
		api.Errorf("activity output: %s", e)
		return 1
	}
	summaryOut, e = newOutput("inference_summary")
	if e != nil {
		api.Errorf("summary output: %s", e)
		return 1
	}
	configOut, e = newOutput("effective_config")
	if e != nil {
		api.Errorf("config output: %s", e)
		return 1
	}
	healthOut, e = newOutput("analyzer_health")
	if e != nil {
		api.Errorf("health output: %s", e)
		return 1
	}
	e = raw.Subscribe(func(_ api.DataSource, d api.Data) {
		ts, x := rawTS.Uint64(d)
		if x != nil {
			return
		}
		pid, x := rawPID.Uint32(d)
		if x != nil {
			return
		}
		b, _ := rawBytes.Uint64(d)
		op, _ := rawOp.Uint32(d)
		res, _ := rawResult.Int32(d)
		clockMu.Lock()
		clockRaw, clockWall = ts, time.Now()
		clockMu.Unlock()
		for _, r := range engine.Feed(analyzer.Event{PID: pid, TimestampNS: ts, Bytes: b, Operation: op, Result: res}) {
			_ = emitRecord(r)
		}
	}, 0)
	if e != nil {
		api.Errorf("subscribe: %s", e)
		return 1
	}
	return 0
}

func startExpiry() {
	expiryStop = make(chan struct{})
	period := time.Duration(engine.Config.StateTimeoutNS / 4)
	if period < 10*time.Millisecond {
		period = 10 * time.Millisecond
	}
	if period > time.Second {
		period = time.Second
	}
	go func() {
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				clockMu.Lock()
				now := clockRaw
				if !clockWall.IsZero() {
					now += uint64(time.Since(clockWall))
				}
				clockMu.Unlock()
				for _, r := range engine.Expire(now) {
					_ = emitRecord(r)
				}
			case <-expiryStop:
				return
			}
		}
	}()
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	if enabled {
		if e := emitConfig(); e != nil {
			api.Errorf("emit config: %s", e)
			return 1
		}
		startExpiry()
		api.Infof("CUDA inference heuristics enabled: %s %s", engine.Config.Preset, engine.Config.Digest())
	}
	return 0
}

//go:wasmexport gadgetStop
func gadgetStop() int32 {
	if enabled {
		if expiryStop != nil {
			close(expiryStop)
		}
		for _, r := range engine.CloseAll("gadget_stop") {
			_ = emitRecord(r)
		}
	}
	return 0
}
func main() {}
