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

package correlator

import (
	"container/heap"
	"sort"
	"sync"
)

const (
	ProtocolV1  = uint32(1)
	PhaseReady  = uint32(1)
	PhaseStart  = uint32(2)
	PhaseEnd    = uint32(3)
	PhaseOrphan = uint32(4)
	phaseExit   = uint32(5)

	ReasonNone     = uint32(0)
	ReasonNatural  = uint32(1)
	ReasonAbort    = uint32(2)
	ReasonShutdown = uint32(3)

	MaxProcesses     = 4096
	MaxQueuedMarkers = 65536
)

type Config struct {
	ReorderWindowNS uint64
	StateTimeoutNS  uint64
}

type Marker struct {
	PID             uint32
	TID             uint32
	TimestampNS     uint64
	ProcessEpoch    uint64
	RequestIDHi     uint64
	RequestIDLo     uint64
	RequestSequence uint64
	ProtocolVersion uint32
	Phase           uint32
	Flags           uint32
	Reason          uint32
	LossGeneration  uint64
	Accepted        bool
}

type Record struct {
	Type, Reason, CloseReason               string
	PID, TID                                uint32
	ProcessEpoch, RequestIDHi, RequestIDLo  uint64
	TimestampNS, StartNS, EndNS, DurationNS uint64
	LossGeneration                          uint64
}

type requestID struct {
	hi uint64
	lo uint64
}

type threadKey struct {
	pid uint32
	tid uint32
}

type requestState struct {
	id        requestID
	start     uint64
	end       uint64
	reason    uint32
	ambiguous bool
	loss      uint64
}

type processState struct {
	epoch       uint64
	last        uint64
	ready       bool
	valid       bool
	active      map[requestID]*requestState
	provisional map[requestID]*requestState
}

type queuedMarker struct {
	marker Marker
	seq    uint64
}

type markerHeap []queuedMarker

func (h markerHeap) Len() int { return len(h) }
func (h markerHeap) Less(i, j int) bool {
	if h[i].marker.TimestampNS != h[j].marker.TimestampNS {
		return h[i].marker.TimestampNS < h[j].marker.TimestampNS
	}
	if markerPhaseOrder(h[i].marker.Phase) != markerPhaseOrder(h[j].marker.Phase) {
		return markerPhaseOrder(h[i].marker.Phase) < markerPhaseOrder(h[j].marker.Phase)
	}
	return h[i].seq < h[j].seq
}
func (h markerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *markerHeap) Push(value any) {
	*h = append(*h, value.(queuedMarker))
}
func (h *markerHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

type Validator struct {
	Config Config

	mu        sync.Mutex
	queue     markerHeap
	processes map[threadKey]*processState
	maxSeen   uint64
	nextSeq   uint64
	watermark uint64
	disabled  bool
	closed    bool
}

func New(config Config) *Validator {
	return &Validator{
		Config:    config,
		processes: map[threadKey]*processState{},
	}
}

func markerPhaseOrder(phase uint32) uint32 {
	switch phase {
	case PhaseReady:
		return 0
	case PhaseStart:
		return 1
	case PhaseEnd:
		return 2
	case PhaseOrphan:
		return 3
	case phaseExit:
		return 4
	default:
		return 5
	}
}

func diagnostic(marker Marker, reason string) Record {
	return Record{
		Type:         "request_correlation_health",
		Reason:       reason,
		PID:          marker.PID,
		TID:          marker.TID,
		ProcessEpoch: marker.ProcessEpoch,
		RequestIDHi:  marker.RequestIDHi,
		RequestIDLo:  marker.RequestIDLo,
		TimestampNS:  marker.TimestampNS,
	}
}

func interval(marker Marker, request *requestState) Record {
	closeReason := "natural"
	if request.reason == ReasonAbort {
		closeReason = "abort"
	}
	return Record{
		Type:           "request_interval",
		CloseReason:    closeReason,
		PID:            marker.PID,
		TID:            marker.TID,
		ProcessEpoch:   marker.ProcessEpoch,
		RequestIDHi:    request.id.hi,
		RequestIDLo:    request.id.lo,
		TimestampNS:    request.end,
		StartNS:        request.start,
		EndNS:          request.end,
		DurationNS:     request.end - request.start,
		LossGeneration: request.loss,
	}
}

func (v *Validator) invalidate(marker Marker, reason string) []Record {
	key := threadKey{pid: marker.PID, tid: marker.TID}
	state := v.processes[key]
	if state != nil {
		state.valid = false
		state.active = map[requestID]*requestState{}
		state.provisional = map[requestID]*requestState{}
	}
	return []Record{diagnostic(marker, reason)}
}

func (v *Validator) evictOne(marker Marker) []Record {
	var victim threadKey
	var oldest uint64
	first := true
	for key, state := range v.processes {
		if first || state.last < oldest ||
			(state.last == oldest &&
				(key.pid < victim.pid ||
					(key.pid == victim.pid && key.tid < victim.tid))) {
			victim = key
			oldest = state.last
			first = false
		}
	}
	state := v.processes[victim]
	delete(v.processes, victim)
	return []Record{{
		Type:         "request_correlation_health",
		Reason:       "capacity_eviction",
		PID:          victim.pid,
		TID:          victim.tid,
		ProcessEpoch: state.epoch,
		TimestampNS:  marker.TimestampNS,
	}}
}

func (v *Validator) process(marker Marker) []Record {
	if marker.Phase != phaseExit && !marker.Accepted {
		return v.invalidate(marker, "bpf_rejected_marker")
	}
	if marker.ProtocolVersion != ProtocolV1 {
		return v.invalidate(marker, "unknown_protocol")
	}
	if marker.ProcessEpoch == 0 {
		return v.invalidate(marker, "zero_epoch")
	}
	if marker.Flags != 0 {
		return v.invalidate(marker, "unknown_flags")
	}

	key := threadKey{pid: marker.PID, tid: marker.TID}
	state := v.processes[key]
	if marker.Phase == PhaseReady {
		if marker.RequestIDHi != 0 || marker.RequestIDLo != 0 ||
			marker.RequestSequence != 0 || marker.Reason != ReasonNone {
			return v.invalidate(marker, "invalid_ready")
		}
		out := []Record{}
		if state != nil {
			if state.epoch == marker.ProcessEpoch {
				return v.invalidate(marker, "duplicate_ready")
			}
			out = append(out, diagnostic(marker, "epoch_replaced"))
		} else if len(v.processes) >= MaxProcesses {
			out = append(out, v.evictOne(marker)...)
		}
		v.processes[key] = &processState{
			epoch:       marker.ProcessEpoch,
			last:        marker.TimestampNS,
			ready:       true,
			valid:       true,
			active:      map[requestID]*requestState{},
			provisional: map[requestID]*requestState{},
		}
		out = append(out, Record{
			Type:           "request_epoch",
			Reason:         "ready",
			PID:            marker.PID,
			ProcessEpoch:   marker.ProcessEpoch,
			TimestampNS:    marker.TimestampNS,
			LossGeneration: marker.LossGeneration,
		})
		return out
	}

	if state == nil || !state.ready {
		if marker.Phase == phaseExit {
			return []Record{diagnostic(marker, "stale_process_exit")}
		}
		return v.invalidate(marker, "marker_before_ready")
	}
	if marker.Phase == phaseExit {
		if state.epoch != marker.ProcessEpoch {
			return []Record{diagnostic(marker, "stale_process_exit")}
		}
		delete(v.processes, key)
		out := []Record{{
			Type:         "request_process_exit",
			Reason:       "process_exit",
			PID:          marker.PID,
			ProcessEpoch: marker.ProcessEpoch,
			TimestampNS:  marker.TimestampNS,
		}}
		if len(state.active) != 0 || len(state.provisional) != 0 {
			out = append(out, Record{
				Type:         "request_correlation_health",
				Reason:       "process_exit_with_open_requests",
				PID:          marker.PID,
				ProcessEpoch: marker.ProcessEpoch,
				TimestampNS:  marker.TimestampNS,
			})
		}
		return out
	}
	if !state.valid {
		return []Record{diagnostic(marker, "invalid_epoch_marker")}
	}
	if state.epoch != marker.ProcessEpoch {
		return v.invalidate(marker, "epoch_mismatch")
	}
	state.last = marker.TimestampNS
	id := requestID{hi: marker.RequestIDHi, lo: marker.RequestIDLo}
	if id.hi == 0 && id.lo == 0 {
		return v.invalidate(marker, "zero_request_id")
	}

	switch marker.Phase {
	case PhaseStart:
		if marker.RequestSequence != 0 || marker.Reason != ReasonNone {
			return v.invalidate(marker, "invalid_start_reason")
		}
		if _, ok := state.active[id]; ok {
			return v.invalidate(marker, "duplicate_start")
		}
		if _, ok := state.provisional[id]; ok {
			return v.invalidate(marker, "reused_request_id")
		}
		request := &requestState{
			id:    id,
			start: marker.TimestampNS,
			loss:  marker.LossGeneration,
		}
		if len(state.active) != 0 {
			request.ambiguous = true
			for _, active := range state.active {
				active.ambiguous = true
			}
		}
		state.active[id] = request
		if request.ambiguous {
			return v.invalidate(marker, "overlapping_requests")
		}
	case PhaseEnd:
		if marker.Reason != ReasonNatural && marker.Reason != ReasonAbort {
			return v.invalidate(marker, "invalid_end_reason")
		}
		request := state.active[id]
		if request == nil {
			if _, ok := state.provisional[id]; ok {
				return v.invalidate(marker, "duplicate_end")
			}
			return v.invalidate(marker, "end_without_start")
		}
		delete(state.active, id)
		if marker.TimestampNS < request.start {
			return v.invalidate(marker, "end_before_start")
		}
		request.end = marker.TimestampNS
		request.reason = marker.Reason
		if marker.LossGeneration != request.loss {
			return v.invalidate(marker, "cuda_event_loss")
		}
		if request.ambiguous {
			return []Record{diagnostic(marker, "ambiguous_request_end")}
		}
		state.provisional[id] = request
	case PhaseOrphan:
		if marker.Reason != ReasonShutdown {
			return v.invalidate(marker, "invalid_orphan_reason")
		}
		if state.active[id] == nil {
			return v.invalidate(marker, "orphan_without_start")
		}
		delete(state.active, id)
		return []Record{diagnostic(marker, "orphaned_request")}
	default:
		return v.invalidate(marker, "unknown_phase")
	}
	return nil
}

func (v *Validator) finalize(watermark uint64) []Record {
	keys := make([]threadKey, 0, len(v.processes))
	for key := range v.processes {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pid != keys[j].pid {
			return keys[i].pid < keys[j].pid
		}
		return keys[i].tid < keys[j].tid
	})
	out := []Record{}
	for _, key := range keys {
		state := v.processes[key]
		if !state.valid {
			continue
		}
		ids := make([]requestID, 0, len(state.provisional))
		for id, request := range state.provisional {
			if request.end <= watermark {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool {
			left := state.provisional[ids[i]]
			right := state.provisional[ids[j]]
			if left.end != right.end {
				return left.end < right.end
			}
			if ids[i].hi != ids[j].hi {
				return ids[i].hi < ids[j].hi
			}
			return ids[i].lo < ids[j].lo
		})
		for _, id := range ids {
			request := state.provisional[id]
			out = append(out, interval(Marker{
				PID:          key.pid,
				TID:          key.tid,
				ProcessEpoch: state.epoch,
			}, request))
			delete(state.provisional, id)
		}
	}
	return out
}

func (v *Validator) drain(watermark uint64) []Record {
	out := []Record{}
	for v.queue.Len() != 0 && v.queue[0].marker.TimestampNS <= watermark {
		item := heap.Pop(&v.queue).(queuedMarker)
		out = append(out, v.process(item.marker)...)
	}
	out = append(out, v.finalize(watermark)...)
	return out
}

func (v *Validator) Feed(marker Marker) []Record {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.disabled {
		return nil
	}
	if v.closed {
		return nil
	}
	if v.watermark != 0 && marker.TimestampNS <= v.watermark {
		if marker.Phase == phaseExit {
			return []Record{diagnostic(marker, "stale_process_exit")}
		}
		return v.invalidate(marker, "reorder_window_exceeded")
	}
	if v.queue.Len() >= MaxQueuedMarkers {
		v.disabled = true
		v.queue = nil
		v.processes = map[threadKey]*processState{}
		return []Record{diagnostic(marker, "marker_capacity")}
	}
	if marker.TimestampNS > v.maxSeen {
		v.maxSeen = marker.TimestampNS
	}
	v.nextSeq++
	heap.Push(&v.queue, queuedMarker{marker: marker, seq: v.nextSeq})
	if v.maxSeen <= v.Config.ReorderWindowNS {
		return nil
	}
	watermark := v.maxSeen - v.Config.ReorderWindowNS
	out := v.drain(watermark)
	v.watermark = watermark
	return out
}

func (v *Validator) Advance(now uint64) []Record {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.disabled {
		return nil
	}
	if now > v.maxSeen {
		v.maxSeen = now
	}
	watermark := uint64(0)
	if now > v.Config.ReorderWindowNS {
		watermark = now - v.Config.ReorderWindowNS
	}
	out := v.drain(watermark)
	if watermark > v.watermark {
		v.watermark = watermark
	}
	for key, state := range v.processes {
		if !state.valid || len(state.active) == 0 {
			continue
		}
		if now >= state.last && now-state.last >= v.Config.StateTimeoutNS {
			out = append(out, Record{
				Type:         "request_correlation_health",
				Reason:       "request_timeout",
				PID:          key.pid,
				TID:          key.tid,
				ProcessEpoch: state.epoch,
				TimestampNS:  now,
			})
			state.valid = false
			state.active = map[requestID]*requestState{}
			state.provisional = map[requestID]*requestState{}
		}
	}
	return out
}

func (v *Validator) FeedProcessExit(pid, tid uint32, epoch, timestamp, lossGeneration uint64) []Record {
	return v.Feed(Marker{
		PID:             pid,
		TID:             tid,
		TimestampNS:     timestamp,
		ProcessEpoch:    epoch,
		ProtocolVersion: ProtocolV1,
		Phase:           phaseExit,
		Reason:          ReasonShutdown,
		LossGeneration:  lossGeneration,
		Accepted:        true,
	})
}

func (v *Validator) Close() []Record {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	out := []Record{}
	for v.queue.Len() != 0 {
		item := heap.Pop(&v.queue).(queuedMarker)
		out = append(out, v.process(item.marker)...)
	}
	out = append(out, v.finalize(^uint64(0))...)
	for key, state := range v.processes {
		ids := make([]requestID, 0, len(state.active))
		for id := range state.active {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			if ids[i].hi != ids[j].hi {
				return ids[i].hi < ids[j].hi
			}
			return ids[i].lo < ids[j].lo
		})
		for _, id := range ids {
			out = append(out, Record{
				Type:         "request_correlation_health",
				Reason:       "gadget_shutdown",
				PID:          key.pid,
				TID:          key.tid,
				ProcessEpoch: state.epoch,
				RequestIDHi:  id.hi,
				RequestIDLo:  id.lo,
				TimestampNS:  v.maxSeen,
			})
		}
	}
	v.processes = map[threadKey]*processState{}
	return out
}
