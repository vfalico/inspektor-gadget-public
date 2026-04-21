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

import "sync/atomic"

// pendingQueue is a simple counting semaphore used by the deterministic
// enrichment path to cap concurrent WaitSynced() calls. When full, the
// caller must fall back immediately (merged ELF resolution) instead of
// waiting — that preserves the 100% non-empty-symbols invariant while
// protecting the process from unbounded queue growth under stress.
type pendingQueue struct {
	inflight atomic.Int64
	capacity int64
}

func newPendingQueue(capacity int) *pendingQueue {
	if capacity <= 0 {
		capacity = 4096
	}
	return &pendingQueue{capacity: int64(capacity)}
}

// TryAcquire reserves one slot. Returns false if the queue is full; the
// caller should then fall back to the merged-ELF path and increment the
// overrun counter.
func (q *pendingQueue) TryAcquire() bool {
	// We use a monotonically growing counter checked against capacity.
	// Race with Release is benign: worst case we go 1 over cap momentarily.
	if q.inflight.Load() >= q.capacity {
		return false
	}
	q.inflight.Add(1)
	return true
}

func (q *pendingQueue) Release() {
	q.inflight.Add(-1)
}

func (q *pendingQueue) Inflight() int64 { return q.inflight.Load() }
