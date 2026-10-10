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

package analyzer

import (
	"encoding/json"
	"strings"
	"testing"
)

func cfg() Config {
	return Config{Preset: "test", RequestGapNS: 100, CandidateGapNS: 10, DedupWindowNS: 0, PrefillMinLaunches: 1, DecodeMinLaunches: 1, CandidateMaxCopyBytes: 1024, StateTimeoutNS: 1000, MaxActivityDurationNS: 10000}
}
func collect(a *Analyzer, es ...Event) []Record {
	var out []Record
	for _, e := range es {
		out = append(out, a.Feed(e)...)
	}
	return out
}
func count(rs []Record, typ string) int {
	n := 0
	for _, r := range rs {
		if r.Type == typ {
			n++
		}
	}
	return n
}

func TestFirstDecodeAndIntervals(t *testing.T) {
	a := New(cfg())
	rs := collect(a, Event{PID: 1, TimestampNS: 1, Operation: 0}, Event{PID: 1, TimestampNS: 2, Operation: 0}, Event{PID: 1, TimestampNS: 20, Operation: 0}, Event{PID: 1, TimestampNS: 40, Operation: 0})
	if count(rs, "first_decode_candidate") != 1 || count(rs, "decode_candidate") != 1 {
		t.Fatalf("records: %#v", rs)
	}
	if rs[len(rs)-1].IntervalCandidateNS != 18 {
		t.Fatalf("interval=%d", rs[len(rs)-1].IntervalCandidateNS)
	}
}
func TestRequestGapClosesBeforeNewEvent(t *testing.T) {
	a := New(cfg())
	rs := collect(a, Event{PID: 2, TimestampNS: 1, Operation: 0}, Event{PID: 2, TimestampNS: 10, Operation: 0}, Event{PID: 2, TimestampNS: 200, Operation: 0})
	if count(rs, "activity_summary") != 1 || count(rs, "activity_boundary") != 2 {
		t.Fatalf("records: %#v", rs)
	}
}
func TestTGIAnchoredDedup(t *testing.T) {
	c := cfg()
	c.CandidateGapNS = 5
	c.DedupWindowNS = 20
	a := New(c)
	rs := collect(a, Event{PID: 3, TimestampNS: 1, Operation: 0}, Event{PID: 3, TimestampNS: 10, Operation: 0}, Event{PID: 3, TimestampNS: 20, Operation: 0}, Event{PID: 3, TimestampNS: 40, Operation: 0})
	if count(rs, "first_decode_candidate") != 1 {
		t.Fatalf("dedup failed: %#v", rs)
	}
}
func TestOverrideChangesClassification(t *testing.T) {
	lo := cfg()
	lo.CandidateGapNS = 10
	hi := lo
	hi.CandidateGapNS = 30
	es := []Event{{PID: 1, TimestampNS: 1, Operation: 0}, {PID: 1, TimestampNS: 20, Operation: 0}, {PID: 1, TimestampNS: 40, Operation: 0}}
	rlo := collect(New(lo), es...)
	rhi := collect(New(hi), es...)
	if count(rlo, "first_decode_candidate") == count(rhi, "first_decode_candidate") {
		t.Fatalf("override did not change classification: low=%#v high=%#v", rlo, rhi)
	}
	if lo.Digest() == hi.Digest() {
		t.Fatal("digests equal")
	}
}
func TestPrefillLaunchThresholdGatesFirstCandidate(t *testing.T) {
	lo := cfg()
	hi := lo
	hi.PrefillMinLaunches = 3
	es := []Event{{PID: 1, TimestampNS: 1, Operation: 0}, {PID: 1, TimestampNS: 20, Operation: 0}}
	if count(collect(New(lo), es...), "first_decode_candidate") != 1 {
		t.Fatal("permissive threshold did not qualify")
	}
	if count(collect(New(hi), es...), "first_decode_candidate") != 0 {
		t.Fatal("strict launch threshold did not gate")
	}
}
func TestPrefillCopyThresholdGatesFirstCandidate(t *testing.T) {
	c := cfg()
	c.PrefillMinCopies = 1
	without := []Event{{PID: 1, TimestampNS: 1, Operation: 0}, {PID: 1, TimestampNS: 20, Operation: 0}}
	with := []Event{{PID: 1, TimestampNS: 1, Operation: 3, Bytes: 8}, {PID: 1, TimestampNS: 2, Operation: 0}, {PID: 1, TimestampNS: 20, Operation: 0}}
	if count(collect(New(c), without...), "first_decode_candidate") != 0 {
		t.Fatal("copy threshold did not gate")
	}
	if count(collect(New(c), with...), "first_decode_candidate") != 1 {
		t.Fatal("qualifying copy did not permit candidate")
	}
}
func TestStateTimeoutOnEventAndPeriodicExpiry(t *testing.T) {
	c := cfg()
	c.StateTimeoutNS = 10
	c.RequestGapNS = 1000
	a := New(c)
	rs := collect(a, Event{PID: 1, TimestampNS: 1, Operation: 0}, Event{PID: 1, TimestampNS: 20, Operation: 0})
	var timedOut bool
	for _, r := range rs {
		if r.Type == "activity_summary" && r.CloseReason == "state_timeout" {
			timedOut = true
		}
	}
	if count(rs, "activity_summary") != 1 || count(rs, "activity_boundary") != 2 || !timedOut {
		t.Fatalf("event timeout records: %#v", rs)
	}
	b := New(c)
	collect(b, Event{PID: 2, TimestampNS: 100, Operation: 0})
	expired := b.Expire(110)
	if count(expired, "activity_summary") != 1 || expired[len(expired)-1].CloseReason != "state_timeout" || b.ActiveStates() != 0 {
		t.Fatalf("periodic expiry: %#v active=%d", expired, b.ActiveStates())
	}
}
func TestStateBoundAndDeterministicEviction(t *testing.T) {
	a := New(cfg())
	var last []Record
	for i := 0; i <= MaxActiveStates; i++ {
		last = a.Feed(Event{PID: uint32(i + 1), TimestampNS: uint64(i + 1), Operation: 0})
	}
	if got := a.ActiveStates(); got != MaxActiveStates {
		t.Fatalf("active=%d want=%d", got, MaxActiveStates)
	}
	if count(last, "analyzer_health") != 1 || count(last, "activity_summary") != 1 {
		t.Fatalf("eviction records: %#v", last)
	}
	var health Record
	for _, r := range last {
		if r.Type == "analyzer_health" {
			health = r
		}
	}
	if health.PID != 1 || health.CloseReason != "capacity_eviction" {
		t.Fatalf("non-deterministic victim: %#v", health)
	}
}
func TestErrorAndOversizeCopyIgnored(t *testing.T) {
	a := New(cfg())
	rs := collect(a, Event{PID: 1, TimestampNS: 1, Operation: 0, Result: 1}, Event{PID: 1, TimestampNS: 2, Operation: 3, Bytes: 2048})
	if len(rs) != 0 {
		t.Fatalf("unexpected %#v", rs)
	}
}
func TestSHA256KnownVector(t *testing.T) {
	if got := sha256Hex("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256=%s", got)
	}
}

func TestCanonicalContainsEveryEffectiveThreshold(t *testing.T) {
	c := cfg()
	got := c.Canonical()
	for _, key := range []string{"request_gap_ns=", "candidate_gap_ns=", "dedup_window_ns=", "prefill_min_launches=", "prefill_min_copies=", "decode_min_launches=", "candidate_max_copy_bytes=", "min_activity_offset_ns=", "state_timeout_ns=", "max_activity_duration_ns="} {
		if !strings.Contains(got, key) {
			t.Fatalf("canonical config missing %s: %s", key, got)
		}
	}
}

func TestConfigJSONContract(t *testing.T) {
	const raw = `{"request_gap_ns":100,"candidate_gap_ns":10,"dedup_window_ns":2,"prefill_min_launches":3,"prefill_min_copies":1,"decode_min_launches":4,"candidate_max_copy_bytes":1024,"min_activity_offset_ns":5,"state_timeout_ns":1000,"max_activity_duration_ns":10000}`
	var got Config
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.RequestGapNS != 100 || got.CandidateGapNS != 10 || got.DedupWindowNS != 2 || got.PrefillMinLaunches != 3 || got.PrefillMinCopies != 1 || got.DecodeMinLaunches != 4 || got.CandidateMaxCopyBytes != 1024 || got.MinActivityOffsetNS != 5 || got.StateTimeoutNS != 1000 || got.MaxActivityDurationNS != 10000 {
		t.Fatalf("incomplete JSON config: %#v", got)
	}
}

func transitionCfg() Config {
	c := cfg()
	c.CandidatePreviousOperationMask = (uint64(1) << 0) | (uint64(1) << 4)
	c.CandidateCurrentOperationMask = uint64(1) << 6
	return c
}

func pairCfg() Config {
	c := transitionCfg()
	c.DecodeMinLaunches = 0
	c.CandidatePairWindowNS = 25
	return c
}

func TestOperationTransitionGateAllowsConfiguredPairs(t *testing.T) {
	for _, events := range [][]Event{
		{{PID: 1, TimestampNS: 1, Operation: 0}, {PID: 1, TimestampNS: 2, Operation: 0}, {PID: 1, TimestampNS: 20, Operation: 6}},
		{{PID: 1, TimestampNS: 1, Operation: 0}, {PID: 1, TimestampNS: 2, Operation: 4, Bytes: 8}, {PID: 1, TimestampNS: 20, Operation: 6}},
	} {
		if got := count(collect(New(transitionCfg()), events...), "first_decode_candidate"); got != 1 {
			t.Fatalf("allowed transition emitted %d candidates for %#v", got, events)
		}
	}
}

func TestOperationTransitionGateRejectsOtherPairs(t *testing.T) {
	for _, events := range [][]Event{
		{{PID: 1, TimestampNS: 1, Operation: 1}, {PID: 1, TimestampNS: 2, Operation: 1}, {PID: 1, TimestampNS: 20, Operation: 6}},
		{{PID: 1, TimestampNS: 1, Operation: 0}, {PID: 1, TimestampNS: 2, Operation: 0}, {PID: 1, TimestampNS: 20, Operation: 5}},
	} {
		if got := count(collect(New(transitionCfg()), events...), "first_decode_candidate"); got != 0 {
			t.Fatalf("disallowed transition emitted %d candidates for %#v", got, events)
		}
	}
}

func TestOperationTransitionGateDoesNotSynthesizeTerminalCandidate(t *testing.T) {
	a := New(transitionCfg())
	collect(a, Event{PID: 1, TimestampNS: 1, Operation: 0}, Event{PID: 1, TimestampNS: 2, Operation: 0})
	if got := count(a.CloseAll("test"), "first_decode_candidate"); got != 0 {
		t.Fatalf("close emitted %d transition candidates", got)
	}
}

func TestOperationTransitionGateDoesNotCrossActivityBoundary(t *testing.T) {
	a := New(transitionCfg())
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 200, Operation: 6},
	)
	if got := count(rs, "first_decode_candidate"); got != 0 {
		t.Fatalf("cross-boundary transition emitted %d candidates: %#v", got, rs)
	}
	if got := count(rs, "activity_boundary"); got != 2 {
		t.Fatalf("activity boundaries=%d records=%#v", got, rs)
	}
}

func TestRejectedTransitionResetsPeriodLaunches(t *testing.T) {
	c := transitionCfg()
	c.DecodeMinLaunches = 2
	a := New(c)
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 5},
		Event{PID: 1, TimestampNS: 21, Operation: 0},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
	)
	if got := count(rs, "first_decode_candidate"); got != 0 {
		t.Fatalf("rejected transition leaked launch evidence: %#v", rs)
	}
}

func TestOperationTransitionMaskValidation(t *testing.T) {
	c := cfg()
	c.CandidatePreviousOperationMask = 1
	if err := c.Validate(); err == nil {
		t.Fatal("one-sided operation mask accepted")
	}
	c.CandidateCurrentOperationMask = uint64(1) << 8
	if err := c.Validate(); err == nil {
		t.Fatal("unsupported operation mask accepted")
	}
	c.CandidateCurrentOperationMask = 1
	if err := c.Validate(); err != nil {
		t.Fatalf("valid operation masks rejected: %v", err)
	}
	c.CandidatePreviousOperationMask = (uint64(1) << 0) | (uint64(1) << 4)
	c.CandidateCurrentOperationMask = uint64(1) << 6
	c.DecodeMinLaunches = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("transition-v2 zero launch gate rejected: %v", err)
	}
	c.CandidatePreviousOperationMask |= uint64(1) << 1
	if err := c.Validate(); err == nil {
		t.Fatal("broad zero-launch operation mask accepted")
	}
	c = cfg()
	c.DecodeMinLaunches = 0
	if err := c.Validate(); err == nil {
		t.Fatal("zero launch gate accepted without transition masks")
	}
	c = transitionCfg()
	c.CandidatePairWindowNS = 25
	if err := c.Validate(); err == nil {
		t.Fatal("pair coalescing accepted with launch-count gate")
	}
	c.DecodeMinLaunches = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("valid pair coalescing rejected: %v", err)
	}
	c.CandidatePreviousOperationMask = 1
	if err := c.Validate(); err == nil {
		t.Fatal("pair coalescing accepted with non-transition-v2 masks")
	}
}

func TestDisabledOperationMasksPreserveLegacyCanonicalForm(t *testing.T) {
	c := cfg()
	if strings.Contains(c.Canonical(), "operation_mask") {
		t.Fatalf("legacy canonical form changed: %s", c.Canonical())
	}
	c = transitionCfg()
	got := c.Canonical()
	for _, key := range []string{"candidate_previous_operation_mask=", "candidate_current_operation_mask="} {
		if !strings.Contains(got, key) {
			t.Fatalf("transition canonical form missing %s: %s", key, got)
		}
	}
}

func TestOperationTransitionCanDisableLaunchCountGate(t *testing.T) {
	events := []Event{
		{PID: 1, TimestampNS: 1, Operation: 0},
		{PID: 1, TimestampNS: 20, Operation: 5},
		{PID: 1, TimestampNS: 21, Operation: 4, Bytes: 8},
		{PID: 1, TimestampNS: 40, Operation: 6},
	}
	enabled := transitionCfg()
	enabled.DecodeMinLaunches = 0
	if got := count(collect(New(enabled), events...), "first_decode_candidate"); got != 1 {
		t.Fatalf("zero launch gate emitted %d candidates", got)
	}
	required := transitionCfg()
	required.DecodeMinLaunches = 1
	if got := count(collect(New(required), events...), "first_decode_candidate"); got != 0 {
		t.Fatalf("launch gate emitted %d candidates without an intervening launch", got)
	}
}

func TestCandidatePairCoalescesLaunchIntoLaterDtoH(t *testing.T) {
	a := New(pairCfg())
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 21, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
	)
	if got := count(rs, "first_decode_candidate"); got != 1 {
		t.Fatalf("coalesced candidates=%d records=%#v", got, rs)
	}
	candidate := rs[len(rs)-1]
	if candidate.TimestampNS != 21 || candidate.TTFTCandidateNS != 20 || candidate.LaunchCount != 2 {
		t.Fatalf("replacement did not preserve factual DtoH opportunity: %#v", candidate)
	}
}

func TestCandidatePairWindowBoundaryIsInclusive(t *testing.T) {
	within := collect(New(pairCfg()),
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 27, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
	)
	if got := count(within, "first_decode_candidate"); got != 1 || within[len(within)-1].TimestampNS != 27 {
		t.Fatalf("equal-window pair did not replace: %#v", within)
	}
	beyond := collect(New(pairCfg()),
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 28, Operation: 4, Bytes: 8},
	)
	if got := count(beyond, "first_decode_candidate"); got != 1 || beyond[len(beyond)-1].TimestampNS != 2 {
		t.Fatalf("expired launch was not committed first: %#v", beyond)
	}
}

func TestTransitionV4PairWindowBoundary(t *testing.T) {
	c := pairCfg()
	c.CandidatePairWindowNS = 6_000_000
	c.RequestGapNS = 10_000_000
	c.StateTimeoutNS = 10_000_000
	c.MaxActivityDurationNS = 20_000_000
	within := collect(New(c),
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 6_000_002, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 6_000_020, Operation: 6},
	)
	if got := count(within, "first_decode_candidate"); got != 1 ||
		within[len(within)-1].TimestampNS != 6_000_002 {
		t.Fatalf("6ms pair did not replace: %#v", within)
	}
	beyond := collect(New(c),
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 6_000_003, Operation: 4, Bytes: 8},
	)
	if got := count(beyond, "first_decode_candidate"); got != 1 ||
		beyond[len(beyond)-1].TimestampNS != 2 {
		t.Fatalf("6ms+1 pair did not preserve launch: %#v", beyond)
	}
}

func TestCandidatePairDoesNotSynthesizeTerminalDtoH(t *testing.T) {
	a := New(pairCfg())
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 4, Bytes: 8},
	)
	rs = append(rs, a.CloseAll("request_end")...)
	if count(rs, "first_decode_candidate") != 0 ||
		count(rs, "decode_candidate") != 0 {
		t.Fatalf("terminal DtoH synthesized a candidate: %#v", rs)
	}
}

func TestCandidatePairIgnoresNonCandidateOperations(t *testing.T) {
	a := New(pairCfg())
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 21, Operation: 5},
		Event{PID: 1, TimestampNS: 22, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
	)
	if got := count(rs, "first_decode_candidate"); got != 1 || rs[len(rs)-1].TimestampNS != 22 {
		t.Fatalf("non-candidate operation broke adjacency: %#v", rs)
	}
}

func TestCandidatePairConflictFlushesBeforeNewLaunch(t *testing.T) {
	a := New(pairCfg())
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 21, Operation: 0},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
	)
	if got := count(rs, "first_decode_candidate"); got != 1 {
		t.Fatalf("first pending launch was not flushed: %#v", rs)
	}
	if rs[len(rs)-1].TimestampNS != 2 {
		t.Fatalf("wrong launch committed on conflict: %#v", rs)
	}
	closed := a.CloseAll("test")
	if count(closed, "decode_candidate") != 0 || count(closed, "analyzer_health") != 1 {
		t.Fatalf("second unresolved launch was not dropped: %#v", closed)
	}
}

func TestCandidatePairDropsUnresolvedLaunchAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		close  func(*Analyzer) []Record
		reason string
	}{
		{name: "close_all", close: func(a *Analyzer) []Record { return a.CloseAll("replay_end") }, reason: "unresolved_launch_replay_end"},
		{name: "expire", close: func(a *Analyzer) []Record { return a.Expire(2000) }, reason: "unresolved_launch_state_timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(pairCfg())
			collect(a,
				Event{PID: 1, TimestampNS: 1, Operation: 0},
				Event{PID: 1, TimestampNS: 2, Operation: 0},
				Event{PID: 1, TimestampNS: 20, Operation: 6},
			)
			rs := tc.close(a)
			if count(rs, "first_decode_candidate") != 0 || count(rs, "analyzer_health") != 1 {
				t.Fatalf("unresolved launch boundary records: %#v", rs)
			}
			if rs[0].CloseReason != tc.reason {
				t.Fatalf("health reason=%q want=%q records=%#v", rs[0].CloseReason, tc.reason, rs)
			}
		})
	}
}

func TestCandidatePairDropsUnresolvedLaunchOnEventBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		nextAt    uint64
		reason    string
		healthAt  uint64
		summaryAt uint64
	}{
		{
			name:      "request_gap",
			configure: func(c *Config) {},
			nextAt:    200,
			reason:    "request_gap",
			healthAt:  20,
			summaryAt: 20,
		},
		{
			name: "max_duration",
			configure: func(c *Config) {
				c.RequestGapNS = 1000
				c.MaxActivityDurationNS = 30
			},
			nextAt:    40,
			reason:    "max_duration",
			healthAt:  20,
			summaryAt: 20,
		},
		{
			name: "state_timeout",
			configure: func(c *Config) {
				c.RequestGapNS = 1000
				c.StateTimeoutNS = 30
			},
			nextAt:    60,
			reason:    "state_timeout",
			healthAt:  60,
			summaryAt: 60,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := pairCfg()
			tc.configure(&c)
			a := New(c)
			collect(a,
				Event{PID: 1, TimestampNS: 1, Operation: 0},
				Event{PID: 1, TimestampNS: 2, Operation: 0},
				Event{PID: 1, TimestampNS: 20, Operation: 6},
			)
			rs := a.Feed(Event{PID: 1, TimestampNS: tc.nextAt, Operation: 0})
			if len(rs) != 3 {
				t.Fatalf("boundary records=%d want=3: %#v", len(rs), rs)
			}
			health, summary, boundary := rs[0], rs[1], rs[2]
			if health.Type != "analyzer_health" ||
				health.CloseReason != "unresolved_launch_"+tc.reason ||
				health.ActivityID != 1 ||
				health.TimestampNS != tc.healthAt {
				t.Fatalf("health record: %#v", health)
			}
			if summary.Type != "activity_summary" ||
				summary.CloseReason != tc.reason ||
				summary.ActivityID != 1 ||
				summary.TimestampNS != tc.summaryAt ||
				summary.CandidateCount != 0 {
				t.Fatalf("summary record: %#v", summary)
			}
			if boundary.Type != "activity_boundary" ||
				boundary.ActivityID != 2 ||
				boundary.TimestampNS != tc.nextAt {
				t.Fatalf("new boundary record: %#v", boundary)
			}
		})
	}
}

func TestCandidatePairDropsUnresolvedLaunchOnCapacityEviction(t *testing.T) {
	c := pairCfg()
	c.StateTimeoutNS = 1 << 62
	c.RequestGapNS = 1 << 62
	c.MaxActivityDurationNS = 1 << 62
	a := New(c)
	collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
	)
	for pid := uint32(2); pid <= MaxActiveStates; pid++ {
		collect(a, Event{PID: pid, TimestampNS: uint64(pid + 19), Operation: 0})
	}
	rs := a.Feed(Event{PID: MaxActiveStates + 1, TimestampNS: MaxActiveStates + 20, Operation: 0})
	if len(rs) != 4 {
		t.Fatalf("eviction records=%d want=4: %#v", len(rs), rs)
	}
	if rs[0].Type != "analyzer_health" ||
		rs[0].CloseReason != "unresolved_launch_capacity_eviction" ||
		rs[0].PID != 1 ||
		rs[0].ActivityID != 1 ||
		rs[0].CandidateCount != 0 {
		t.Fatalf("unresolved health: %#v", rs[0])
	}
	if rs[1].Type != "activity_summary" ||
		rs[1].CloseReason != "capacity_eviction" ||
		rs[1].PID != 1 ||
		rs[1].CandidateCount != 0 {
		t.Fatalf("eviction summary: %#v", rs[1])
	}
	if rs[2].Type != "analyzer_health" ||
		rs[2].CloseReason != "capacity_eviction" ||
		rs[2].PID != 1 {
		t.Fatalf("capacity health: %#v", rs[2])
	}
	if rs[3].Type != "activity_boundary" || rs[3].PID != MaxActiveStates+1 {
		t.Fatalf("replacement boundary: %#v", rs[3])
	}
}

func TestCandidatePairCoalescesBeforeAnchoredDedup(t *testing.T) {
	c := pairCfg()
	c.CandidatePairWindowNS = 35
	c.DedupWindowNS = 25
	a := New(c)
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 21, Operation: 0},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
		Event{PID: 1, TimestampNS: 50, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 60, Operation: 6},
	)
	if count(rs, "first_decode_candidate") != 1 || count(rs, "decode_candidate") != 1 {
		t.Fatalf("candidate counts: %#v", rs)
	}
	candidate := rs[len(rs)-1]
	if candidate.TimestampNS != 50 ||
		candidate.CandidateIndex != 2 ||
		candidate.IntervalCandidateNS != 48 {
		t.Fatalf("replacement was deduplicated before coalescing: %#v", candidate)
	}
}

func TestCandidatePairPreservesReplacementSnapshotsAndIndexes(t *testing.T) {
	a := New(pairCfg())
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 21, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
		Event{PID: 1, TimestampNS: 41, Operation: 0},
		Event{PID: 1, TimestampNS: 60, Operation: 6},
		Event{PID: 1, TimestampNS: 61, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 80, Operation: 6},
	)
	var candidates []Record
	for _, r := range rs {
		if r.Type == "first_decode_candidate" || r.Type == "decode_candidate" {
			candidates = append(candidates, r)
		}
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates=%#v", candidates)
	}
	first, second := candidates[0], candidates[1]
	if first.TimestampNS != 21 ||
		first.CandidateIndex != 1 ||
		first.CandidateCount != 1 ||
		first.LaunchCount != 2 ||
		first.CopyCount != 1 {
		t.Fatalf("first replacement snapshot: %#v", first)
	}
	if second.TimestampNS != 61 ||
		second.CandidateIndex != 2 ||
		second.CandidateCount != 2 ||
		second.LaunchCount != 3 ||
		second.CopyCount != 2 ||
		second.IntervalCandidateNS != 40 {
		t.Fatalf("second replacement snapshot: %#v", second)
	}
}

func TestDisabledCandidatePairPreservesExactTransitionRecords(t *testing.T) {
	c := transitionCfg()
	c.DecodeMinLaunches = 0
	a := New(c)
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 21, Operation: 0},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
		Event{PID: 1, TimestampNS: 200, Operation: 0},
	)
	want := []Record{
		{Type: "activity_boundary", Phase: "prefill_candidate", CloseReason: "start", PID: 1, ActivityID: 1, TimestampNS: 1, ActivityStartNS: 1},
		{Type: "first_decode_candidate", Phase: "decode_candidate", PID: 1, ActivityID: 1, TimestampNS: 2, ActivityStartNS: 1, CandidateIndex: 1, CandidateCount: 1, LaunchCount: 1, CopyCount: 1, TTFTCandidateNS: 1},
		{Type: "decode_candidate", Phase: "decode_candidate", PID: 1, ActivityID: 1, TimestampNS: 21, ActivityStartNS: 1, CandidateIndex: 2, CandidateCount: 2, LaunchCount: 2, CopyCount: 1, IntervalCandidateNS: 19},
		{Type: "activity_summary", Phase: "decode_candidate", CloseReason: "request_gap", PID: 1, ActivityID: 1, TimestampNS: 40, ActivityStartNS: 1, DurationNS: 39, CandidateCount: 2, LaunchCount: 2, CopyCount: 1},
		{Type: "activity_boundary", Phase: "prefill_candidate", CloseReason: "start", PID: 1, ActivityID: 2, TimestampNS: 200, ActivityStartNS: 200},
	}
	if len(rs) != len(want) {
		t.Fatalf("records=%d want=%d: %#v", len(rs), len(want), rs)
	}
	for i := range want {
		if rs[i] != want[i] {
			t.Fatalf("record %d=%#v want=%#v", i, rs[i], want[i])
		}
	}
}

func TestCandidatePairStateIsIsolatedByPID(t *testing.T) {
	a := New(pairCfg())
	rs := collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
		Event{PID: 2, TimestampNS: 1, Operation: 0},
		Event{PID: 2, TimestampNS: 2, Operation: 4, Bytes: 8},
		Event{PID: 2, TimestampNS: 20, Operation: 6},
		Event{PID: 1, TimestampNS: 21, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
	)
	if got := count(rs, "first_decode_candidate"); got != 2 {
		t.Fatalf("cross-PID state contamination: %#v", rs)
	}
	for _, r := range rs {
		if r.Type == "first_decode_candidate" {
			if r.PID == 1 && r.TimestampNS != 21 {
				t.Fatalf("PID 1 candidate=%#v", r)
			}
			if r.PID == 2 && r.TimestampNS != 2 {
				t.Fatalf("PID 2 candidate=%#v", r)
			}
		}
	}
}

func TestCandidatePairTimestampRegressionDoesNotMutatePending(t *testing.T) {
	a := New(pairCfg())
	collect(a,
		Event{PID: 1, TimestampNS: 1, Operation: 0},
		Event{PID: 1, TimestampNS: 2, Operation: 0},
		Event{PID: 1, TimestampNS: 20, Operation: 6},
	)
	if rs := a.Feed(Event{PID: 1, TimestampNS: 19, Operation: 4, Bytes: 8}); len(rs) != 0 {
		t.Fatalf("timestamp regression emitted records: %#v", rs)
	}
	rs := collect(a,
		Event{PID: 1, TimestampNS: 21, Operation: 4, Bytes: 8},
		Event{PID: 1, TimestampNS: 40, Operation: 6},
	)
	if got := count(rs, "first_decode_candidate"); got != 1 || rs[len(rs)-1].TimestampNS != 21 {
		t.Fatalf("timestamp regression mutated pending state: %#v", rs)
	}
}

func TestCandidatePairCanonicalIsDefaultOff(t *testing.T) {
	c := transitionCfg()
	if strings.Contains(c.Canonical(), "candidate_pair_window_ns") {
		t.Fatalf("disabled pair coalescing changed canonical config: %s", c.Canonical())
	}
	c.DecodeMinLaunches = 0
	c.CandidatePairWindowNS = 2_500_000
	if !strings.Contains(c.Canonical(), "candidate_pair_window_ns=2500000") {
		t.Fatalf("enabled pair coalescing missing from canonical config: %s", c.Canonical())
	}
}
