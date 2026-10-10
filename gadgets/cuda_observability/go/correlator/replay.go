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
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"cuda_observability/analyzer"
)

const RequestContextActiveValid = uint32(2)

type TaggedCUDAEvent struct {
	PID                   uint32
	TID                   uint32
	CaptureSequence       uint64
	TimestampNS           uint64
	Bytes                 uint64
	Operation             uint32
	Result                int32
	ProcessEpoch          uint64
	RequestIDHi           uint64
	RequestIDLo           uint64
	RequestSequence       uint64
	LossGeneration        uint64
	RequestLossGeneration uint64
	ContextState          uint32
}

type RequestKey struct {
	PID          uint32
	TID          uint32
	ProcessEpoch uint64
	RequestIDHi  uint64
	RequestIDLo  uint64
}

type CapturedMarker struct {
	CaptureSequence uint64
	Marker          Marker
}

type CaptureFooter struct {
	Generation            uint64
	CUDACompleted         uint64
	CUDAEmitted           uint64
	MarkerInvocations     uint64
	MarkerAccepted        uint64
	MarkerRejected        uint64
	MarkerEmitted         uint64
	MarkerReserveFailures uint64
	StateInsertFailures   uint64
	ExitAttempts          uint64
	ExitEmitted           uint64
	ExitReserveFailures   uint64
}

type CUDAStatsSummary struct {
	CompletedCalls        uint64
	UnmatchedReturns      uint64
	ReserveFailures       uint64
	PendingUpdateFailures uint64
}

type CheckedRequestCapture struct {
	Markers               []CapturedMarker
	CUDAEvents            []TaggedCUDAEvent
	Footer                *CaptureFooter
	CUDAStats             CUDAStatsSummary
	MarkerReserveFailures uint64
}

type CheckedReplayResult struct {
	Interval                 Record
	Records                  []analyzer.Record
	SelectedEventCount       uint64
	SelectedProjectionSHA256 string
}

func sameRequest(event TaggedCUDAEvent, key RequestKey) bool {
	return event.PID == key.PID &&
		event.TID == key.TID &&
		event.ProcessEpoch == key.ProcessEpoch &&
		event.RequestIDHi == key.RequestIDHi &&
		event.RequestIDLo == key.RequestIDLo
}

func checkedAdd(left, right uint64) (uint64, error) {
	sum := left + right
	if sum < left {
		return 0, fmt.Errorf("capture counter overflow")
	}
	return sum, nil
}

func validateCaptureSequence(markers []CapturedMarker, events []TaggedCUDAEvent) error {
	seen := make(map[uint64]struct{}, len(markers)+len(events))
	var previous uint64
	for index, captured := range markers {
		if captured.CaptureSequence == 0 {
			return fmt.Errorf("marker capture sequence must be nonzero")
		}
		if index != 0 && captured.CaptureSequence <= previous {
			return fmt.Errorf("markers are not in capture order")
		}
		if _, ok := seen[captured.CaptureSequence]; ok {
			return fmt.Errorf("duplicate capture sequence %d", captured.CaptureSequence)
		}
		seen[captured.CaptureSequence] = struct{}{}
		previous = captured.CaptureSequence
	}
	previous = 0
	for index, event := range events {
		if event.CaptureSequence == 0 {
			return fmt.Errorf("CUDA capture sequence must be nonzero")
		}
		if index != 0 && event.CaptureSequence <= previous {
			return fmt.Errorf("CUDA events are not in capture order")
		}
		if _, ok := seen[event.CaptureSequence]; ok {
			return fmt.Errorf("duplicate capture sequence %d", event.CaptureSequence)
		}
		seen[event.CaptureSequence] = struct{}{}
		previous = event.CaptureSequence
	}
	return nil
}

func validatePristineAccounting(capture CheckedRequestCapture) error {
	if capture.Footer == nil {
		return fmt.Errorf("capture footer is required")
	}
	footer := capture.Footer
	// Terminal map snapshots are diagnostic only: Inspektor Gadget can iterate
	// them while producers are still active, so cross-counter equality is not a
	// request-completeness proof. Any observed failure still fails closed.
	if footer.Generation != 0 {
		return fmt.Errorf("capture is not pristine: loss generation %d", footer.Generation)
	}
	if footer.StateInsertFailures != 0 ||
		footer.MarkerReserveFailures != 0 ||
		footer.ExitReserveFailures != 0 ||
		capture.MarkerReserveFailures != 0 ||
		capture.CUDAStats.UnmatchedReturns != 0 ||
		capture.CUDAStats.ReserveFailures != 0 ||
		capture.CUDAStats.PendingUpdateFailures != 0 {
		return fmt.Errorf("capture contains instrumentation loss or state failures")
	}
	if footer.MarkerRejected != 0 {
		return fmt.Errorf("capture contains %d rejected markers", footer.MarkerRejected)
	}
	return nil
}

func selectedProjectionSHA256(events []TaggedCUDAEvent) string {
	var projection bytes.Buffer
	projection.WriteString("cuda-observability-request-events-v1\x00")
	for _, event := range events {
		for _, value := range [...]uint64{
			uint64(event.PID),
			uint64(event.TID),
			event.TimestampNS,
			event.Bytes,
			uint64(event.Operation),
			uint64(uint32(event.Result)),
			event.ProcessEpoch,
			event.RequestIDHi,
			event.RequestIDLo,
			event.RequestSequence,
			event.LossGeneration,
			event.RequestLossGeneration,
			uint64(event.ContextState),
		} {
			_ = binary.Write(&projection, binary.BigEndian, value)
		}
	}
	return analyzer.SHA256Hex(projection.Bytes())
}

// ReplayPristineCheckedRequest assumes its caller supplied one honestly
// ordered, exactly-once event stream. Request completeness comes from accepted
// lifecycle markers, stable loss generation, and the terminal request-local
// sequence, not from non-quiescent terminal map snapshots.
func ReplayPristineCheckedRequest(config analyzer.Config, key RequestKey, capture CheckedRequestCapture) (CheckedReplayResult, error) {
	if err := validateCaptureSequence(capture.Markers, capture.CUDAEvents); err != nil {
		return CheckedReplayResult{}, err
	}
	if err := validatePristineAccounting(capture); err != nil {
		return CheckedReplayResult{}, err
	}

	validator := New(Config{})
	var startSequence, endSequence, finalRequestSequence uint64
	var validationRecords []Record
	for _, captured := range capture.Markers {
		marker := captured.Marker
		if marker.LossGeneration != 0 {
			return CheckedReplayResult{}, fmt.Errorf("marker at capture sequence %d has loss generation %d", captured.CaptureSequence, marker.LossGeneration)
		}
		if marker.PID == key.PID &&
			marker.TID == key.TID &&
			marker.ProcessEpoch == key.ProcessEpoch &&
			marker.RequestIDHi == key.RequestIDHi &&
			marker.RequestIDLo == key.RequestIDLo {
			switch marker.Phase {
			case PhaseStart:
				if startSequence != 0 {
					return CheckedReplayResult{}, fmt.Errorf("duplicate request START marker")
				}
				startSequence = captured.CaptureSequence
			case PhaseEnd, PhaseOrphan:
				if endSequence != 0 {
					return CheckedReplayResult{}, fmt.Errorf("duplicate request terminal marker")
				}
				endSequence = captured.CaptureSequence
				finalRequestSequence = marker.RequestSequence
			}
		}
		validationRecords = append(validationRecords, validator.Feed(marker)...)
	}
	validationRecords = append(validationRecords, validator.Close()...)
	var intervals []Record
	for _, record := range validationRecords {
		switch record.Type {
		case "request_interval":
			if record.PID == key.PID &&
				record.TID == key.TID &&
				record.ProcessEpoch == key.ProcessEpoch &&
				record.RequestIDHi == key.RequestIDHi &&
				record.RequestIDLo == key.RequestIDLo {
				intervals = append(intervals, record)
			}
		case "request_correlation_health":
			return CheckedReplayResult{}, fmt.Errorf("request correlation health failure: %s", record.Reason)
		}
	}
	if startSequence == 0 || endSequence == 0 || startSequence >= endSequence {
		return CheckedReplayResult{}, fmt.Errorf("request capture boundaries are missing or invalid")
	}
	if len(intervals) != 1 {
		return CheckedReplayResult{}, fmt.Errorf("expected one validated request interval, got %d", len(intervals))
	}
	interval := intervals[0]

	selected := make([]TaggedCUDAEvent, 0)
	for _, event := range capture.CUDAEvents {
		exact := sameRequest(event, key)
		inside := event.TimestampNS >= interval.StartNS && event.TimestampNS < interval.EndNS
		if exact && !inside {
			return CheckedReplayResult{}, fmt.Errorf("request-tagged CUDA event outside marker boundaries at capture sequence %d", event.CaptureSequence)
		}
		if event.PID == key.PID && inside {
			if !exact ||
				event.ContextState != RequestContextActiveValid ||
				event.LossGeneration != 0 ||
				event.RequestLossGeneration != 0 {
				return CheckedReplayResult{}, fmt.Errorf("unattributable same-process CUDA event at capture sequence %d", event.CaptureSequence)
			}
		}
		if !exact {
			continue
		}
		selected = append(selected, event)
	}
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].CaptureSequence < selected[j].CaptureSequence
	})
	for index, event := range selected {
		expected := uint64(index + 1)
		if event.RequestSequence != expected {
			return CheckedReplayResult{}, fmt.Errorf("request sequence mismatch: got %d, want %d", event.RequestSequence, expected)
		}
		if index != 0 && event.TimestampNS < selected[index-1].TimestampNS {
			return CheckedReplayResult{}, fmt.Errorf("request CUDA timestamps are not monotonic")
		}
	}
	if uint64(len(selected)) != finalRequestSequence {
		return CheckedReplayResult{}, fmt.Errorf("terminal request sequence mismatch: selected=%d terminal=%d", len(selected), finalRequestSequence)
	}
	if finalRequestSequence == 0 {
		return CheckedReplayResult{
			Interval:                 interval,
			Records:                  nil,
			SelectedEventCount:       0,
			SelectedProjectionSHA256: selectedProjectionSHA256(nil),
		}, nil
	}
	records, err := ReplayRequest(config, key, selected)
	if err != nil {
		return CheckedReplayResult{}, err
	}
	return CheckedReplayResult{
		Interval:                 interval,
		Records:                  records,
		SelectedEventCount:       uint64(len(selected)),
		SelectedProjectionSHA256: selectedProjectionSHA256(selected),
	}, nil
}

func ReplayRequest(config analyzer.Config, key RequestKey, events []TaggedCUDAEvent) ([]analyzer.Record, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("request has no tagged CUDA events")
	}
	ordered := append([]TaggedCUDAEvent(nil), events...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].RequestSequence < ordered[j].RequestSequence
	})
	lossGeneration := ordered[0].RequestLossGeneration
	if ordered[0].RequestSequence == 0 {
		return nil, fmt.Errorf("request sequence must be nonzero")
	}
	previousSequence := ordered[0].RequestSequence - 1
	engine := analyzer.New(config)
	var records []analyzer.Record
	for _, event := range ordered {
		if event.PID != key.PID ||
			event.TID != key.TID ||
			event.ProcessEpoch != key.ProcessEpoch ||
			event.RequestIDHi != key.RequestIDHi ||
			event.RequestIDLo != key.RequestIDLo {
			return nil, fmt.Errorf("mixed request identity at sequence %d", event.RequestSequence)
		}
		if event.ContextState != RequestContextActiveValid {
			return nil, fmt.Errorf("invalid request context state %d at sequence %d", event.ContextState, event.RequestSequence)
		}
		if event.RequestLossGeneration != lossGeneration ||
			event.LossGeneration != lossGeneration {
			return nil, fmt.Errorf("loss generation changed at sequence %d", event.RequestSequence)
		}
		if event.RequestSequence != previousSequence+1 {
			return nil, fmt.Errorf("request sequence gap: got %d after %d", event.RequestSequence, previousSequence)
		}
		previousSequence = event.RequestSequence
		records = append(records, engine.Feed(analyzer.Event{
			PID:         event.PID,
			TimestampNS: event.TimestampNS,
			Bytes:       event.Bytes,
			Operation:   event.Operation,
			Result:      event.Result,
		})...)
	}
	records = append(records, engine.CloseAll("request_end")...)
	return records, nil
}
