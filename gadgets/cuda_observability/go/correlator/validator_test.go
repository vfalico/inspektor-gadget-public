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

import "testing"

func marker(timestamp uint64, phase uint32) Marker {
	return Marker{
		PID:             7,
		TID:             8,
		TimestampNS:     timestamp,
		ProcessEpoch:    11,
		RequestIDHi:     13,
		RequestIDLo:     17,
		ProtocolVersion: ProtocolV1,
		Phase:           phase,
		Reason:          ReasonNone,
		Accepted:        true,
	}
}

func recordsOfType(records []Record, typ string) []Record {
	out := []Record{}
	for _, record := range records {
		if record.Type == typ {
			out = append(out, record)
		}
	}
	return out
}

func TestReorderedLifecycleFinalizesAfterWatermark(t *testing.T) {
	validator := New(Config{ReorderWindowNS: 11, StateTimeoutNS: 1000})
	ready := marker(100, PhaseReady)
	ready.RequestIDHi = 0
	ready.RequestIDLo = 0
	end := marker(120, PhaseEnd)
	end.Reason = ReasonNatural
	start := marker(110, PhaseStart)

	validator.Feed(ready)
	validator.Feed(end)
	validator.Feed(start)
	records := validator.Advance(131)
	intervals := recordsOfType(records, "request_interval")
	if len(intervals) != 1 {
		t.Fatalf("intervals=%#v records=%#v", intervals, records)
	}
	if intervals[0].StartNS != 110 || intervals[0].EndNS != 120 ||
		intervals[0].CloseReason != "natural" {
		t.Fatalf("interval=%#v", intervals[0])
	}
}

func TestRejectedKernelTransitionCannotSatisfyLifecycle(t *testing.T) {
	validator := New(Config{})
	ready := marker(100, PhaseReady)
	ready.RequestIDHi = 0
	ready.RequestIDLo = 0
	ready.Accepted = false

	records := validator.Feed(ready)
	records = append(records, validator.Close()...)
	health := recordsOfType(records, "request_correlation_health")
	if len(health) != 1 || health[0].Reason != "bpf_rejected_marker" {
		t.Fatalf("records=%#v", records)
	}
	if len(recordsOfType(records, "request_epoch")) != 0 {
		t.Fatalf("rejected transition created epoch: %#v", records)
	}
}

func TestDuplicateEndInvalidatesProvisionalInterval(t *testing.T) {
	validator := New(Config{ReorderWindowNS: 10, StateTimeoutNS: 1000})
	ready := marker(100, PhaseReady)
	ready.RequestIDHi = 0
	ready.RequestIDLo = 0
	end := marker(120, PhaseEnd)
	end.Reason = ReasonNatural
	duplicate := end
	duplicate.TimestampNS = 121

	validator.Feed(ready)
	validator.Feed(marker(110, PhaseStart))
	validator.Feed(end)
	validator.Feed(duplicate)
	records := validator.Advance(132)
	if got := recordsOfType(records, "request_interval"); len(got) != 0 {
		t.Fatalf("duplicate end finalized intervals: %#v", got)
	}
	health := recordsOfType(records, "request_correlation_health")
	if len(health) != 1 || health[0].Reason != "duplicate_end" {
		t.Fatalf("health=%#v", health)
	}
}

func TestOverlapSuppressesIntervals(t *testing.T) {
	validator := New(Config{ReorderWindowNS: 1, StateTimeoutNS: 1000})
	ready := marker(100, PhaseReady)
	ready.RequestIDHi = 0
	ready.RequestIDLo = 0
	secondStart := marker(111, PhaseStart)
	secondStart.RequestIDHi = 19
	secondStart.RequestIDLo = 23
	firstEnd := marker(120, PhaseEnd)
	firstEnd.Reason = ReasonNatural
	secondEnd := secondStart
	secondEnd.TimestampNS = 121
	secondEnd.Phase = PhaseEnd
	secondEnd.Reason = ReasonNatural

	validator.Feed(ready)
	validator.Feed(marker(110, PhaseStart))
	validator.Feed(secondStart)
	validator.Feed(firstEnd)
	validator.Feed(secondEnd)
	records := validator.Advance(123)
	if got := recordsOfType(records, "request_interval"); len(got) != 0 {
		t.Fatalf("overlap finalized intervals: %#v", got)
	}
}

func TestUnknownFlagsFailClosed(t *testing.T) {
	validator := New(Config{ReorderWindowNS: 1, StateTimeoutNS: 1000})
	ready := marker(100, PhaseReady)
	ready.RequestIDHi = 0
	ready.RequestIDLo = 0
	start := marker(110, PhaseStart)
	start.Flags = 1

	validator.Feed(ready)
	validator.Feed(start)
	records := validator.Advance(112)
	health := recordsOfType(records, "request_correlation_health")
	if len(health) != 1 || health[0].Reason != "unknown_flags" {
		t.Fatalf("health=%#v", health)
	}
}

func TestOpenRequestTimesOutWithoutSyntheticClose(t *testing.T) {
	validator := New(Config{ReorderWindowNS: 1, StateTimeoutNS: 20})
	ready := marker(100, PhaseReady)
	ready.RequestIDHi = 0
	ready.RequestIDLo = 0

	validator.Feed(ready)
	validator.Feed(marker(110, PhaseStart))
	records := validator.Advance(131)
	if got := recordsOfType(records, "request_interval"); len(got) != 0 {
		t.Fatalf("timeout finalized intervals: %#v", got)
	}
	health := recordsOfType(records, "request_correlation_health")
	if len(health) != 1 || health[0].Reason != "request_timeout" {
		t.Fatalf("health=%#v", health)
	}
}
