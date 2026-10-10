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

	"cuda_observability/analyzer"
)

func pristineCapture(event TaggedCUDAEvent, markerSequences [3]uint64) (RequestKey, CheckedRequestCapture) {
	key := RequestKey{
		PID:          7,
		TID:          8,
		ProcessEpoch: 11,
		RequestIDHi:  13,
		RequestIDLo:  17,
	}
	ready := marker(90, PhaseReady)
	ready.RequestIDHi = 0
	ready.RequestIDLo = 0
	start := marker(100, PhaseStart)
	end := marker(200, PhaseEnd)
	end.Reason = ReasonNatural
	end.RequestSequence = 1
	return key, CheckedRequestCapture{
		Markers: []CapturedMarker{
			{CaptureSequence: markerSequences[0], Marker: ready},
			{CaptureSequence: markerSequences[1], Marker: start},
			{CaptureSequence: markerSequences[2], Marker: end},
		},
		CUDAEvents: []TaggedCUDAEvent{event},
		Footer: &CaptureFooter{
			CUDACompleted:     1,
			CUDAEmitted:       1,
			MarkerInvocations: 3,
			MarkerAccepted:    3,
			MarkerEmitted:     3,
		},
		CUDAStats: CUDAStatsSummary{CompletedCalls: 1},
	}
}

func requestEvent(timestamp, captureSequence uint64) TaggedCUDAEvent {
	return TaggedCUDAEvent{
		PID:             7,
		TID:             8,
		CaptureSequence: captureSequence,
		TimestampNS:     timestamp,
		Operation:       0,
		ProcessEpoch:    11,
		RequestIDHi:     13,
		RequestIDLo:     17,
		RequestSequence: 1,
		ContextState:    RequestContextActiveValid,
	}
}

func TestPristineReplayUsesHalfOpenMarkerInterval(t *testing.T) {
	key, capture := pristineCapture(requestEvent(100, 3), [3]uint64{1, 2, 4})
	result, err := ReplayPristineCheckedRequest(analyzer.Config{}, key, capture)
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedEventCount != 1 || result.SelectedProjectionSHA256 == "" {
		t.Fatalf("result=%#v", result)
	}

	for _, timestamp := range []uint64{99, 200, 201} {
		key, capture := pristineCapture(requestEvent(timestamp, 3), [3]uint64{1, 2, 4})
		_, err := ReplayPristineCheckedRequest(analyzer.Config{}, key, capture)
		if err == nil || !strings.Contains(err.Error(), "outside marker boundaries") {
			t.Fatalf("timestamp=%d err=%v", timestamp, err)
		}
	}
}

func TestPristineReplayRejectsAlternateThreadInsideInterval(t *testing.T) {
	event := requestEvent(150, 3)
	event.TID = 9
	event.RequestIDHi = 0
	event.RequestIDLo = 0
	event.ProcessEpoch = 0
	event.RequestSequence = 0
	event.ContextState = 1
	key, capture := pristineCapture(event, [3]uint64{1, 2, 4})
	_, err := ReplayPristineCheckedRequest(analyzer.Config{}, key, capture)
	if err == nil || !strings.Contains(err.Error(), "unattributable same-process CUDA event") {
		t.Fatalf("err=%v", err)
	}
}

func TestPristineReplayRejectsLifecycleFromAlternateThread(t *testing.T) {
	key, capture := pristineCapture(requestEvent(150, 3), [3]uint64{1, 2, 4})
	for index := range capture.Markers {
		capture.Markers[index].Marker.TID = 9
	}
	_, err := ReplayPristineCheckedRequest(analyzer.Config{}, key, capture)
	if err == nil || !strings.Contains(err.Error(), "boundaries are missing") {
		t.Fatalf("err=%v", err)
	}
}

func TestPristineReplayIgnoresLegalDatasourceInterleaving(t *testing.T) {
	keyA, captureA := pristineCapture(requestEvent(150, 4), [3]uint64{1, 2, 3})
	keyB, captureB := pristineCapture(requestEvent(150, 2), [3]uint64{1, 3, 4})

	resultA, err := ReplayPristineCheckedRequest(analyzer.Config{}, keyA, captureA)
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := ReplayPristineCheckedRequest(analyzer.Config{}, keyB, captureB)
	if err != nil {
		t.Fatal(err)
	}
	if resultA.SelectedProjectionSHA256 != resultB.SelectedProjectionSHA256 {
		t.Fatalf("digests differ: %s != %s", resultA.SelectedProjectionSHA256, resultB.SelectedProjectionSHA256)
	}
}

func TestPristineReplayUsesTerminalRequestSequenceNotRacyTotals(t *testing.T) {
	key, capture := pristineCapture(requestEvent(150, 3), [3]uint64{1, 2, 4})
	capture.Footer.CUDACompleted = 99
	capture.Footer.CUDAEmitted = 98
	capture.Footer.MarkerInvocations = 100
	capture.Footer.MarkerAccepted = 97
	capture.Footer.MarkerEmitted = 96
	capture.CUDAStats.CompletedCalls = 101

	result, err := ReplayPristineCheckedRequest(analyzer.Config{}, key, capture)
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedEventCount != 1 {
		t.Fatalf("result=%#v", result)
	}
}

func TestPristineReplayRejectsTerminalSequenceMismatch(t *testing.T) {
	key, capture := pristineCapture(requestEvent(150, 3), [3]uint64{1, 2, 4})
	capture.Markers[2].Marker.RequestSequence = 2
	_, err := ReplayPristineCheckedRequest(analyzer.Config{}, key, capture)
	if err == nil || !strings.Contains(err.Error(), "terminal request sequence mismatch") {
		t.Fatalf("err=%v", err)
	}
}

func TestPristineReplayAcceptsZeroCUDARequest(t *testing.T) {
	key, capture := pristineCapture(requestEvent(150, 3), [3]uint64{1, 2, 4})
	capture.CUDAEvents = nil
	capture.Markers[2].Marker.RequestSequence = 0

	result, err := ReplayPristineCheckedRequest(analyzer.Config{}, key, capture)
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedEventCount != 0 || len(result.Records) != 0 ||
		result.SelectedProjectionSHA256 == "" {
		t.Fatalf("result=%#v", result)
	}
}
