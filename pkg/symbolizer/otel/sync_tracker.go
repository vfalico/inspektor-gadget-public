// Copyright 2025 The Inspektor Gadget authors
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

package otel

import (
	"sync"
	"sync/atomic"
	"time"
)

// SyncTracker tracks which TGIDs the OTel profiler has finished
// synchronising (PyFrameObject offsets, ELF mappings, interpreter state)
// and provides a per-PID condition variable so Resolve() callers can
// block up to a deadline until the "synced" transition occurs.
//
// Three terminal states exist: synced (OTel finished), exited (process
// died before sync), or neither (deadline expires -> timeout). The
// waiter code must handle all three.
type pidState uint8

const (
	stateUnknown pidState = iota
	statePending
	stateSynced
	stateExited
)

type syncTracker struct {
	mu sync.Mutex
	// per-TGID wait condition; constructed on first MarkPending/WaitSynced.
	entries map[uint32]*syncEntry

	// queueOverrun counts events that could not wait because the bounded
	// queue was full (see pendingQueue). Exposed for metrics.
	queueOverrun atomic.Uint64
	// syncedOnWait counts events where WaitSynced returned stateSynced.
	syncedOnWait atomic.Uint64
	// fallbackOnDeadline counts events where WaitSynced returned
	// stateUnknown/statePending (deadline) or stateExited.
	fallbackOnDeadline atomic.Uint64
}

type syncEntry struct {
	state   pidState
	markedAt time.Time
	// cond signals waiters on any state change.
	cond *sync.Cond
}

func newSyncTracker() *syncTracker {
	return &syncTracker{entries: make(map[uint32]*syncEntry)}
}

// MarkPending marks TGID as having had NotifyPID() enqueued; used to
// let WaitSynced know a synchronisation is in flight (so it may wait).
func (s *syncTracker) MarkPending(tgid uint32) {
	s.mu.Lock()
	e := s.entries[tgid]
	if e == nil {
		e = &syncEntry{}
		e.cond = sync.NewCond(&s.mu)
		s.entries[tgid] = e
	}
	if e.state == stateUnknown {
		e.state = statePending
		e.markedAt = time.Now()
	}
	s.mu.Unlock()
}

// MarkSynced transitions TGID to stateSynced and wakes all waiters.
func (s *syncTracker) MarkSynced(tgid uint32) {
	s.mu.Lock()
	e := s.entries[tgid]
	if e == nil {
		e = &syncEntry{}
		e.cond = sync.NewCond(&s.mu)
		s.entries[tgid] = e
	}
	if e.state != stateSynced {
		e.state = stateSynced
		e.cond.Broadcast()
	}
	s.mu.Unlock()
}

// MarkExited transitions TGID to stateExited and wakes all waiters
// (short-lived process: don't make them wait for the full deadline).
func (s *syncTracker) MarkExited(tgid uint32) {
	s.mu.Lock()
	if e, ok := s.entries[tgid]; ok {
		e.state = stateExited
		e.cond.Broadcast()
	}
	s.mu.Unlock()
}

// IsSynced returns true if OTel's processManager has successfully
// synchronised this TGID.
func (s *syncTracker) IsSynced(tgid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[tgid]; ok {
		return e.state == stateSynced
	}
	return false
}

// WaitSynced blocks for up to `timeout` waiting for TGID to reach
// stateSynced. Returns the final state. If called on an unknown TGID
// it is treated as statePending and inserted (caller is expected to
// have called MarkPending, but we defend in depth).
func (s *syncTracker) WaitSynced(tgid uint32, timeout time.Duration) pidState {
	s.mu.Lock()
	e := s.entries[tgid]
	if e == nil {
		e = &syncEntry{state: statePending, markedAt: time.Now(), cond: sync.NewCond(&s.mu)}
		s.entries[tgid] = e
	}
	if e.state == stateSynced || e.state == stateExited {
		st := e.state
		s.mu.Unlock()
		return st
	}
	// Arrange a cond broadcaster on deadline expiry.
	done := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		s.mu.Lock()
		close(done)
		e.cond.Broadcast()
		s.mu.Unlock()
	})
	defer timer.Stop()
	// Loop until state change OR deadline fired.
	for e.state == statePending {
		select {
		case <-done:
			st := e.state
			s.mu.Unlock()
			return st
		default:
		}
		e.cond.Wait()
	}
	st := e.state
	s.mu.Unlock()
	return st
}

// Gc evicts entries older than ttl (guards against SIGKILL-racing
// MarkExited misses). Called periodically by the background sweeper.
func (s *syncTracker) Gc(ttl time.Duration) int {
	cutoff := time.Now().Add(-ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for tgid, e := range s.entries {
		if e.state != statePending && !e.markedAt.IsZero() && e.markedAt.Before(cutoff) {
			delete(s.entries, tgid)
			n++
		}
	}
	return n
}

// Metrics returns a snapshot of counters — for logging / Prom scrape.
func (s *syncTracker) Metrics() (overrun, synced, fallback uint64) {
	return s.queueOverrun.Load(), s.syncedOnWait.Load(), s.fallbackOnDeadline.Load()
}
