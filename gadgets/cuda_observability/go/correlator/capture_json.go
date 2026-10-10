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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type captureProcess struct {
	PID uint32 `json:"pid"`
	TID uint32 `json:"tid"`
}

type captureObject struct {
	Type                  string  `json:"type"`
	OperationRaw          *uint32 `json:"operation_raw"`
	PhaseRaw              *uint32 `json:"phase_raw"`
	Proc                  captureProcess
	TimestampRaw          uint64          `json:"timestamp_raw"`
	Bytes                 uint64          `json:"bytes"`
	Result                int32           `json:"result"`
	ProcessEpoch          uint64          `json:"process_epoch"`
	RequestProcessEpoch   uint64          `json:"request_process_epoch"`
	RequestIDHi           uint64          `json:"request_id_hi"`
	RequestIDLo           uint64          `json:"request_id_lo"`
	RequestSequence       uint64          `json:"request_sequence"`
	LossGeneration        uint64          `json:"loss_generation"`
	RequestLossGeneration uint64          `json:"request_loss_generation"`
	RequestContextState   uint32          `json:"request_context_state"`
	TransitionAccepted    uint32          `json:"transition_accepted"`
	ProtocolVersion       uint32          `json:"protocol_version"`
	Flags                 uint32          `json:"flags"`
	Reason                json.RawMessage `json:"reason"`
}

type captureArrayRow struct {
	OperationRaw          *uint32 `json:"operation_raw"`
	Calls                 uint64  `json:"calls"`
	RawEmitted            uint64  `json:"raw_emitted"`
	IntentionalOmissions  uint64  `json:"intentionally_omitted"`
	UnmatchedReturns      uint64  `json:"unmatched_returns"`
	ReserveFailures       uint64  `json:"reserve_failures"`
	PendingUpdateFailures uint64  `json:"pending_update_failures"`

	Generation            *uint64 `json:"generation"`
	CUDACompleted         uint64  `json:"cuda_completed"`
	CUDAEmitted           uint64  `json:"cuda_emitted"`
	CUDAOmitted           uint64  `json:"cuda_omitted"`
	MarkerInvocations     uint64  `json:"marker_invocations"`
	MarkerAccepted        uint64  `json:"marker_accepted"`
	MarkerRejected        uint64  `json:"marker_rejected"`
	MarkerEmitted         uint64  `json:"marker_emitted"`
	MarkerReserveFailures uint64  `json:"marker_reserve_failures"`
	StateInsertFailures   uint64  `json:"state_insert_failures"`
	ExitAttempts          uint64  `json:"exit_attempts"`
	ExitEmitted           uint64  `json:"exit_emitted"`
	ExitReserveFailures   uint64  `json:"exit_reserve_failures"`
}

func addCounter(total *uint64, value uint64) error {
	next, err := checkedAdd(*total, value)
	if err != nil {
		return err
	}
	*total = next
	return nil
}

func requireRowKeys(fields map[string]json.RawMessage, expected ...string) error {
	if len(fields) != len(expected) {
		return fmt.Errorf("unexpected aggregate row fields")
	}
	for _, key := range expected {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing aggregate row field %q", key)
		}
	}
	return nil
}

func addFooter(total *CaptureFooter, row captureArrayRow) error {
	for _, item := range []struct {
		total *uint64
		value uint64
	}{
		{&total.Generation, *row.Generation},
		{&total.CUDACompleted, row.CUDACompleted},
		{&total.CUDAEmitted, row.CUDAEmitted},
		{&total.CUDAOmitted, row.CUDAOmitted},
		{&total.MarkerInvocations, row.MarkerInvocations},
		{&total.MarkerAccepted, row.MarkerAccepted},
		{&total.MarkerRejected, row.MarkerRejected},
		{&total.MarkerEmitted, row.MarkerEmitted},
		{&total.MarkerReserveFailures, row.MarkerReserveFailures},
		{&total.StateInsertFailures, row.StateInsertFailures},
		{&total.ExitAttempts, row.ExitAttempts},
		{&total.ExitEmitted, row.ExitEmitted},
		{&total.ExitReserveFailures, row.ExitReserveFailures},
	} {
		if err := addCounter(item.total, item.value); err != nil {
			return err
		}
	}
	return nil
}

func parseCaptureArray(line []byte, capture *CheckedRequestCapture) error {
	var rows []json.RawMessage
	if err := json.Unmarshal(line, &rows); err != nil {
		return fmt.Errorf("decode capture array: %w", err)
	}
	operationKeys := map[uint32]struct{}{}
	footerSeen := false
	markerStatsSeen := false
	for _, raw := range rows {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return fmt.Errorf("decode aggregate row fields: %w", err)
		}
		var row captureArrayRow
		if err := json.Unmarshal(raw, &row); err != nil {
			return fmt.Errorf("decode aggregate row: %w", err)
		}
		switch {
		case row.Generation != nil:
			if footerSeen {
				return fmt.Errorf("duplicate capture footer in one snapshot")
			}
			footerSeen = true
			if row.OperationRaw != nil {
				return fmt.Errorf("mixed capture footer and CUDA statistics row")
			}
			if err := requireRowKeys(fields,
				"cuda_completed", "cuda_emitted", "cuda_omitted", "exit_attempts",
				"exit_emitted", "exit_reserve_failures", "generation", "key",
				"marker_accepted", "marker_emitted", "marker_invocations",
				"marker_rejected", "marker_reserve_failures",
				"state_insert_failures",
			); err != nil {
				return err
			}
			if capture.Footer == nil {
				capture.Footer = &CaptureFooter{}
			}
			if err := addFooter(capture.Footer, row); err != nil {
				return err
			}
		case row.OperationRaw != nil:
			if err := requireRowKeys(fields,
				"calls", "duration_ns", "errors", "operation", "operation_raw",
				"intentionally_omitted", "pending_update_failures", "raw_emitted",
				"requested_bytes",
				"reserve_failures", "unmatched_returns",
			); err != nil {
				return err
			}
			if _, ok := operationKeys[*row.OperationRaw]; ok {
				return fmt.Errorf("duplicate CUDA statistics bucket %d in one snapshot", *row.OperationRaw)
			}
			operationKeys[*row.OperationRaw] = struct{}{}
			if err := addCounter(&capture.CUDAStats.CompletedCalls, row.Calls); err != nil {
				return err
			}
			if err := addCounter(&capture.CUDAStats.RawEmitted, row.RawEmitted); err != nil {
				return err
			}
			if err := addCounter(&capture.CUDAStats.IntentionalOmissions, row.IntentionalOmissions); err != nil {
				return err
			}
			if err := addCounter(&capture.CUDAStats.UnmatchedReturns, row.UnmatchedReturns); err != nil {
				return err
			}
			if err := addCounter(&capture.CUDAStats.ReserveFailures, row.ReserveFailures); err != nil {
				return err
			}
			if err := addCounter(&capture.CUDAStats.PendingUpdateFailures, row.PendingUpdateFailures); err != nil {
				return err
			}
		default:
			if err := requireRowKeys(fields, "key", "reserve_failures"); err != nil {
				return err
			}
			if markerStatsSeen {
				return fmt.Errorf("duplicate marker reserve-failure summary in one snapshot")
			}
			markerStatsSeen = true
			if err := addCounter(&capture.MarkerReserveFailures, row.ReserveFailures); err != nil {
				return err
			}
		}
	}
	return nil
}

// ParseJSONLCapture decodes the complete output of one `ig run -o json`
// invocation. Line order is retained within each datasource only; independent
// datasource flushes do not establish a cross-datasource order. Complete
// terminal map snapshots from independent attachments are summed; callers must
// supply an honest, exactly-once stream because snapshots have no attachment ID.
func ParseJSONLCapture(reader io.Reader) (CheckedRequestCapture, error) {
	var capture CheckedRequestCapture
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var lineNumber uint64
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if line[0] == '[' {
			if err := parseCaptureArray(line, &capture); err != nil {
				return CheckedRequestCapture{}, fmt.Errorf("line %d: %w", lineNumber, err)
			}
			continue
		}
		if line[0] != '{' {
			return CheckedRequestCapture{}, fmt.Errorf("line %d: expected JSON object or array", lineNumber)
		}
		var object captureObject
		if err := json.Unmarshal(line, &object); err != nil {
			return CheckedRequestCapture{}, fmt.Errorf("line %d: decode object: %w", lineNumber, err)
		}
		switch {
		case object.OperationRaw != nil && object.Type == "":
			capture.CUDAEvents = append(capture.CUDAEvents, TaggedCUDAEvent{
				PID:                   object.Proc.PID,
				TID:                   object.Proc.TID,
				CaptureSequence:       lineNumber,
				TimestampNS:           object.TimestampRaw,
				Bytes:                 object.Bytes,
				Operation:             *object.OperationRaw,
				Result:                object.Result,
				ProcessEpoch:          object.RequestProcessEpoch,
				RequestIDHi:           object.RequestIDHi,
				RequestIDLo:           object.RequestIDLo,
				RequestSequence:       object.RequestSequence,
				LossGeneration:        object.LossGeneration,
				RequestLossGeneration: object.RequestLossGeneration,
				ContextState:          object.RequestContextState,
			})
		case object.PhaseRaw != nil && object.Type == "":
			var reason uint32
			if len(object.Reason) != 0 {
				if err := json.Unmarshal(object.Reason, &reason); err != nil {
					return CheckedRequestCapture{}, fmt.Errorf("line %d: decode marker reason: %w", lineNumber, err)
				}
			}
			capture.Markers = append(capture.Markers, CapturedMarker{
				CaptureSequence: lineNumber,
				Marker: Marker{
					PID:             object.Proc.PID,
					TID:             object.Proc.TID,
					TimestampNS:     object.TimestampRaw,
					ProcessEpoch:    object.ProcessEpoch,
					RequestIDHi:     object.RequestIDHi,
					RequestIDLo:     object.RequestIDLo,
					RequestSequence: object.RequestSequence,
					ProtocolVersion: object.ProtocolVersion,
					Phase:           *object.PhaseRaw,
					Flags:           object.Flags,
					Reason:          reason,
					LossGeneration:  object.LossGeneration,
					Accepted:        object.TransitionAccepted != 0,
				},
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return CheckedRequestCapture{}, fmt.Errorf("read capture: %w", err)
	}
	return capture, nil
}
