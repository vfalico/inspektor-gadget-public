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
	"encoding/binary"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MaxActiveStates is the hard upper bound for per-process heuristic state.
const MaxActiveStates = 4096

// Config contains only parameters that materially affect the state machine.
type Config struct {
	Preset                string `json:"preset,omitempty"`
	RequestGapNS          uint64 `json:"request_gap_ns"`
	CandidateGapNS        uint64 `json:"candidate_gap_ns"`
	DedupWindowNS         uint64 `json:"dedup_window_ns"`
	PrefillMinLaunches    uint64 `json:"prefill_min_launches"`
	PrefillMinCopies      uint64 `json:"prefill_min_copies"`
	DecodeMinLaunches     uint64 `json:"decode_min_launches"`
	CandidateMaxCopyBytes uint64 `json:"candidate_max_copy_bytes"`
	MinActivityOffsetNS   uint64 `json:"min_activity_offset_ns"`
	StateTimeoutNS        uint64 `json:"state_timeout_ns"`
	MaxActivityDurationNS uint64 `json:"max_activity_duration_ns"`
}

type Event struct {
	PID                uint32
	TimestampNS, Bytes uint64
	Operation          uint32
	Result             int32
}

type Record struct {
	Type, Phase, CloseReason, Preset, ConfigDigest, ConfigCanonical                                              string
	PID                                                                                                          uint32
	ActivityID, TimestampNS, ActivityStartNS, DurationNS, CandidateIndex, CandidateCount, LaunchCount, CopyCount uint64
	TTFTCandidateNS, IntervalCandidateNS                                                                         uint64
}

type state struct {
	id, start, last, candidateAt, candidates, launches, copies, periodLaunches uint64
	phase                                                                      string
}

type Analyzer struct {
	Config Config
	mu     sync.Mutex
	states map[uint32]*state
	nextID uint64
}

func New(c Config) *Analyzer { return &Analyzer{Config: c, states: map[uint32]*state{}} }

func (c Config) Canonical() string {
	var b strings.Builder
	add := func(k string, v uint64) {
		b.WriteByte(';')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.FormatUint(v, 10))
	}
	b.WriteString("preset=")
	b.WriteString(c.Preset)
	add("request_gap_ns", c.RequestGapNS)
	add("candidate_gap_ns", c.CandidateGapNS)
	add("dedup_window_ns", c.DedupWindowNS)
	add("prefill_min_launches", c.PrefillMinLaunches)
	add("prefill_min_copies", c.PrefillMinCopies)
	add("decode_min_launches", c.DecodeMinLaunches)
	add("candidate_max_copy_bytes", c.CandidateMaxCopyBytes)
	add("min_activity_offset_ns", c.MinActivityOffsetNS)
	add("state_timeout_ns", c.StateTimeoutNS)
	add("max_activity_duration_ns", c.MaxActivityDurationNS)
	return b.String()
}

// sha256Hex is a compact FIPS 180-4 SHA-256 implementation. Keeping it local avoids
// the standard crypto package's large Wasm lookup tables and the vanilla IG 16 MiB limit.
func sha256Hex(s string) string {
	h := [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	k := [64]uint32{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}
	msg := append([]byte(nil), []byte(s)...)
	bitLen := uint64(len(msg)) * 8
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	var tail [8]byte
	binary.BigEndian.PutUint64(tail[:], bitLen)
	msg = append(msg, tail[:]...)
	var w [64]uint32
	for off := 0; off < len(msg); off += 64 {
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(msg[off+i*4:])
		}
		for i := 16; i < 64; i++ {
			s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ (w[i-15] >> 3)
			s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ (w[i-2] >> 10)
			w[i] = w[i-16] + s0 + w[i-7] + s1
		}
		a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
		for i := 0; i < 64; i++ {
			s1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
			ch := (e & f) ^ ((^e) & g)
			t1 := hh + s1 + ch + k[i] + w[i]
			s0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			t2 := s0 + maj
			hh, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
		}
		for i, v := range [...]uint32{a, b, c, d, e, f, g, hh} {
			h[i] += v
		}
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i, v := range h {
		for j := 0; j < 4; j++ {
			x := byte(v >> uint(24-8*j))
			out[(i*4+j)*2] = hex[x>>4]
			out[(i*4+j)*2+1] = hex[x&15]
		}
	}
	return string(out)
}
func (c Config) Digest() string { return sha256Hex(c.Canonical()) }

func isLaunch(op uint32) bool { return op == 0 || op == 1 || op == 2 }
func isCopy(op uint32) bool   { return op == 3 || op == 4 }
func selected(e Event, c Config) bool {
	if e.Result != 0 {
		return false
	}
	if isCopy(e.Operation) && c.CandidateMaxCopyBytes > 0 && e.Bytes > c.CandidateMaxCopyBytes {
		return false
	}
	return e.Operation <= 7
}

func (a *Analyzer) start(e Event) *state {
	a.nextID++
	s := &state{id: a.nextID, start: e.TimestampNS, last: e.TimestampNS, phase: "prefill_candidate"}
	a.states[e.PID] = s
	return s
}

func (a *Analyzer) candidate(pid uint32, s *state, at uint64) []Record {
	if at < s.start+a.Config.MinActivityOffsetNS || s.periodLaunches < a.Config.DecodeMinLaunches {
		s.periodLaunches = 0
		return nil
	}
	// Prefill gates apply only to the transition into the first decode candidate.
	if s.candidateAt == 0 && (s.launches < a.Config.PrefillMinLaunches || s.copies < a.Config.PrefillMinCopies) {
		s.periodLaunches = 0
		return nil
	}
	// Anchored de-duplication: never move the retained candidate timestamp.
	if s.candidateAt != 0 && at-s.candidateAt < a.Config.DedupWindowNS {
		s.periodLaunches = 0
		return nil
	}
	s.candidates++
	r := Record{Type: "decode_candidate", Phase: "decode_candidate", PID: pid, ActivityID: s.id, TimestampNS: at, ActivityStartNS: s.start, CandidateIndex: s.candidates, CandidateCount: s.candidates, LaunchCount: s.launches, CopyCount: s.copies}
	if s.candidateAt == 0 {
		r.Type = "first_decode_candidate"
		r.TTFTCandidateNS = at - s.start
		s.phase = "decode_candidate"
	} else {
		r.IntervalCandidateNS = at - s.candidateAt
	}
	s.candidateAt = at
	s.periodLaunches = 0
	return []Record{r}
}

func (a *Analyzer) close(pid uint32, s *state, reason string, at uint64) Record {
	if at < s.last {
		at = s.last
	}
	delete(a.states, pid)
	return Record{Type: "activity_summary", Phase: s.phase, CloseReason: reason, PID: pid, ActivityID: s.id, TimestampNS: at, ActivityStartNS: s.start, DurationNS: at - s.start, CandidateCount: s.candidates, LaunchCount: s.launches, CopyCount: s.copies}
}

func (a *Analyzer) evictOne(at uint64) []Record {
	var victim uint32
	var oldest uint64
	first := true
	for pid, s := range a.states {
		if first || s.last < oldest || (s.last == oldest && pid < victim) {
			victim, oldest, first = pid, s.last, false
		}
	}
	s := a.states[victim]
	out := a.candidate(victim, s, s.last)
	out = append(out, a.close(victim, s, "capacity_eviction", at))
	out = append(out, Record{Type: "analyzer_health", CloseReason: "capacity_eviction", PID: victim, ActivityID: s.id, TimestampNS: at})
	return out
}

// Feed consumes factual CUDA host-call returns in nondecreasing per-process time.
func (a *Analyzer) Feed(e Event) []Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !selected(e, a.Config) {
		return nil
	}
	s := a.states[e.PID]
	out := []Record{}
	if s != nil && e.TimestampNS < s.last {
		return nil
	}
	if s != nil && e.TimestampNS-s.last >= a.Config.StateTimeoutNS {
		out = append(out, a.candidate(e.PID, s, s.last)...)
		out = append(out, a.close(e.PID, s, "state_timeout", e.TimestampNS))
		s = nil
	} else if s != nil && (e.TimestampNS-s.last >= a.Config.RequestGapNS || e.TimestampNS-s.start >= a.Config.MaxActivityDurationNS) {
		reason := "request_gap"
		if e.TimestampNS-s.start >= a.Config.MaxActivityDurationNS {
			reason = "max_duration"
		}
		out = append(out, a.candidate(e.PID, s, s.last)...)
		out = append(out, a.close(e.PID, s, reason, s.last))
		s = nil
	}
	if s == nil {
		if len(a.states) >= MaxActiveStates {
			out = append(out, a.evictOne(e.TimestampNS)...)
		}
		s = a.start(e)
		out = append(out, Record{Type: "activity_boundary", Phase: "prefill_candidate", CloseReason: "start", PID: e.PID, ActivityID: s.id, TimestampNS: e.TimestampNS, ActivityStartNS: e.TimestampNS})
	} else if e.TimestampNS-s.last >= a.Config.CandidateGapNS {
		out = append(out, a.candidate(e.PID, s, s.last)...)
	}
	if isLaunch(e.Operation) {
		s.launches++
		s.periodLaunches++
	}
	if isCopy(e.Operation) {
		s.copies++
	}
	s.last = e.TimestampNS
	return out
}

// Expire closes inactive states using the same monotonic timestamp domain as Event.
func (a *Analyzer) Expire(now uint64) []Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	pids := make([]int, 0, len(a.states))
	for pid, s := range a.states {
		if now >= s.last && now-s.last >= a.Config.StateTimeoutNS {
			pids = append(pids, int(pid))
		}
	}
	sort.Ints(pids)
	out := []Record{}
	for _, pi := range pids {
		pid := uint32(pi)
		s := a.states[pid]
		out = append(out, a.candidate(pid, s, s.last)...)
		out = append(out, a.close(pid, s, "state_timeout", now))
	}
	return out
}

func (a *Analyzer) ActiveStates() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.states)
}

func (a *Analyzer) CloseAll(reason string) []Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	pids := make([]int, 0, len(a.states))
	for p := range a.states {
		pids = append(pids, int(p))
	}
	sort.Ints(pids)
	out := []Record{}
	for _, pi := range pids {
		p := uint32(pi)
		s := a.states[p]
		out = append(out, a.candidate(p, s, s.last)...)
		out = append(out, a.close(p, s, reason, s.last))
	}
	return out
}
