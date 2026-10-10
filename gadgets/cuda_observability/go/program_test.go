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

import "testing"

func TestParseHeuristicsStrict(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
		err  bool
	}{{"", false, false}, {"false", false, false}, {"TRUE", true, false}, {"yes", false, true}, {"0", false, true}} {
		got, err := parseHeuristics(tc.in)
		if got != tc.want || (err != nil) != tc.err {
			t.Fatalf("parseHeuristics(%q)=(%v,%v), want (%v,error=%v)", tc.in, got, err, tc.want, tc.err)
		}
	}
}

func TestEmitRoutingCoversAllRecordKinds(t *testing.T) {
	// Keep the datasource-routing contract explicit: summaries and health events
	// must not be delivered through the activity datasource.
	for _, tc := range []struct{ typ, want string }{
		{"activity_summary", "summary"},
		{"analyzer_health", "health"},
		{"decode_candidate", "activity"},
	} {
		got := recordRoute(tc.typ)
		if got != tc.want {
			t.Fatalf("route(%s)=%s want %s", tc.typ, got, tc.want)
		}
	}
}

func TestTransitionPresetsFreezePairCoalescing(t *testing.T) {
	const v2 = "vllm-0.10.2-qwen2.5-0.5b-a100-sequential-transition-v2"
	const v3 = "vllm-0.10.2-qwen2.5-0.5b-a100-sequential-transition-v3"
	const v4 = "vllm-0.10.2-qwen2.5-0.5b-a100-sequential-transition-v4"
	previous, ok := preset(v2)
	if !ok {
		t.Fatalf("missing preset %q", v2)
	}
	if previous.CandidatePairWindowNS != 0 {
		t.Fatalf("v2 preset changed: %#v", previous)
	}
	current, ok := preset(v3)
	if !ok {
		t.Fatalf("missing preset %q", v3)
	}
	if current.RequestGapNS != 12_500_000 ||
		current.CandidateGapNS != 300_000 ||
		current.DedupWindowNS != 2_000_000 ||
		current.PrefillMinLaunches != 1 ||
		current.PrefillMinCopies != 0 ||
		current.DecodeMinLaunches != 0 ||
		current.CandidateMaxCopyBytes != 1_048_576 ||
		current.MinActivityOffsetNS != 0 ||
		current.StateTimeoutNS != 5_000_000_000 ||
		current.MaxActivityDurationNS != 120_000_000_000 ||
		current.CandidatePreviousOperationMask != 17 ||
		current.CandidateCurrentOperationMask != 64 ||
		current.CandidatePairWindowNS != 3_000_000 {
		t.Fatalf("unexpected v3 preset: %#v", current)
	}
	const wantCanonical = "preset=" + v3 +
		";request_gap_ns=12500000" +
		";candidate_gap_ns=300000" +
		";dedup_window_ns=2000000" +
		";prefill_min_launches=1" +
		";prefill_min_copies=0" +
		";decode_min_launches=0" +
		";candidate_max_copy_bytes=1048576" +
		";min_activity_offset_ns=0" +
		";state_timeout_ns=5000000000" +
		";max_activity_duration_ns=120000000000" +
		";candidate_previous_operation_mask=17" +
		";candidate_current_operation_mask=64" +
		";candidate_pair_window_ns=3000000"
	if got := current.Canonical(); got != wantCanonical {
		t.Fatalf("canonical=%q want=%q", got, wantCanonical)
	}
	if err := current.Validate(); err != nil {
		t.Fatalf("v3 preset validation: %v", err)
	}
	next, ok := preset(v4)
	if !ok {
		t.Fatalf("missing preset %q", v4)
	}
	if next.RequestGapNS != current.RequestGapNS ||
		next.CandidateGapNS != current.CandidateGapNS ||
		next.DedupWindowNS != current.DedupWindowNS ||
		next.PrefillMinLaunches != current.PrefillMinLaunches ||
		next.PrefillMinCopies != current.PrefillMinCopies ||
		next.DecodeMinLaunches != current.DecodeMinLaunches ||
		next.CandidateMaxCopyBytes != current.CandidateMaxCopyBytes ||
		next.MinActivityOffsetNS != current.MinActivityOffsetNS ||
		next.StateTimeoutNS != current.StateTimeoutNS ||
		next.MaxActivityDurationNS != current.MaxActivityDurationNS ||
		next.CandidatePreviousOperationMask != current.CandidatePreviousOperationMask ||
		next.CandidateCurrentOperationMask != current.CandidateCurrentOperationMask ||
		next.CandidatePairWindowNS != 6_000_000 {
		t.Fatalf("unexpected v4 preset: %#v", next)
	}
	const wantV4Canonical = "preset=" + v4 +
		";request_gap_ns=12500000" +
		";candidate_gap_ns=300000" +
		";dedup_window_ns=2000000" +
		";prefill_min_launches=1" +
		";prefill_min_copies=0" +
		";decode_min_launches=0" +
		";candidate_max_copy_bytes=1048576" +
		";min_activity_offset_ns=0" +
		";state_timeout_ns=5000000000" +
		";max_activity_duration_ns=120000000000" +
		";candidate_previous_operation_mask=17" +
		";candidate_current_operation_mask=64" +
		";candidate_pair_window_ns=6000000"
	if got := next.Canonical(); got != wantV4Canonical {
		t.Fatalf("v4 canonical=%q want=%q", got, wantV4Canonical)
	}
	if err := next.Validate(); err != nil {
		t.Fatalf("v4 preset validation: %v", err)
	}
}
