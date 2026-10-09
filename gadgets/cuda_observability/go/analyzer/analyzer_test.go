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
