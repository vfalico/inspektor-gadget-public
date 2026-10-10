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
	"strings"
	"testing"
)

func TestParseJSONLCaptureAcceptsNumericMarkerAndStringDerivedReasons(t *testing.T) {
	input := strings.NewReader(
		`{"proc":{"pid":7,"tid":8},"timestamp_raw":100,"process_epoch":11,"request_id_hi":13,"request_id_lo":17,"request_sequence":0,"protocol_version":1,"phase_raw":2,"flags":0,"reason":0,"transition_accepted":1,"loss_generation":0}` + "\n" +
			`{"type":"request_interval","reason":"natural"}` + "\n")
	capture, err := ParseJSONLCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.Markers) != 1 || capture.Markers[0].Marker.Reason != ReasonNone ||
		!capture.Markers[0].Marker.Accepted {
		t.Fatalf("markers=%#v", capture.Markers)
	}
}

func TestParseJSONLCaptureAggregatesIndependentMapSnapshots(t *testing.T) {
	input := strings.NewReader(
		`[{"cuda_completed":2,"cuda_emitted":2,"cuda_omitted":0,"exit_attempts":0,"exit_emitted":0,"exit_reserve_failures":0,"generation":0,"key":0,"marker_accepted":2,"marker_emitted":2,"marker_invocations":2,"marker_rejected":0,"marker_reserve_failures":0,"state_insert_failures":0}]` + "\n" +
			`[{"cuda_completed":3,"cuda_emitted":2,"cuda_omitted":1,"exit_attempts":1,"exit_emitted":1,"exit_reserve_failures":0,"generation":0,"key":0,"marker_accepted":1,"marker_emitted":1,"marker_invocations":1,"marker_rejected":0,"marker_reserve_failures":0,"state_insert_failures":0}]` + "\n" +
			`[{"calls":2,"duration_ns":7,"errors":0,"intentionally_omitted":0,"operation":"CUDA_OP_LAUNCH_KERNEL","operation_raw":0,"pending_update_failures":0,"raw_emitted":2,"requested_bytes":0,"reserve_failures":0,"unmatched_returns":0}]` + "\n" +
			`[{"calls":3,"duration_ns":11,"errors":0,"intentionally_omitted":1,"operation":"CUDA_OP_LAUNCH_KERNEL","operation_raw":0,"pending_update_failures":0,"raw_emitted":2,"requested_bytes":0,"reserve_failures":0,"unmatched_returns":0}]` + "\n")
	capture, err := ParseJSONLCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	if capture.Footer == nil ||
		capture.Footer.CUDACompleted != 5 ||
		capture.Footer.CUDAOmitted != 1 ||
		capture.Footer.MarkerAccepted != 3 ||
		capture.Footer.ExitAttempts != 1 ||
		capture.CUDAStats.CompletedCalls != 5 ||
		capture.CUDAStats.RawEmitted != 4 ||
		capture.CUDAStats.IntentionalOmissions != 1 {
		t.Fatalf("capture=%#v", capture)
	}
}

func TestParseJSONLCaptureRejectsUnknownAggregateRow(t *testing.T) {
	_, err := ParseJSONLCapture(strings.NewReader(`[{"future_counter":1}]` + "\n"))
	if err == nil || !strings.Contains(err.Error(), "unexpected aggregate row fields") {
		t.Fatalf("err=%v", err)
	}
}
