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
// See the License for the specific language governing permissions and
// limitations under the License.

package gadgets

import (
	"os"
	"strconv"
	"time"
)

// PerfWakeupEventsFromEnv returns the perf-buffer wakeup batch size, honoring
// the IG_PERF_WAKEUP_EVENTS override. 0 restores the legacy per-event wakeup
// behavior (wake the consumer on every sample).
func PerfWakeupEventsFromEnv() int {
	if v, ok := os.LookupEnv("IG_PERF_WAKEUP_EVENTS"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return PerfWakeupEvents
}

// PerfBufferPagesFromEnv returns the per-CPU perf buffer size in pages, honoring
// the IG_PERF_BUFFER_PAGES override. The value must be a power of two >= 1
// (perf ring buffers require a power-of-two page count); invalid values fall
// back to the PerfBufferPages default.
func PerfBufferPagesFromEnv() int {
	if v, ok := os.LookupEnv("IG_PERF_BUFFER_PAGES"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && (n&(n-1)) == 0 {
			return n
		}
	}
	return PerfBufferPages
}

// PerfFlushInterval returns the cadence of the bounded perf-buffer flush timer,
// honoring the IG_PERF_FLUSH_INTERVAL_MS override. A return value of 0 disables
// the timer entirely (pure wakeup batching with no latency bound).
func PerfFlushInterval() time.Duration {
	ms := PerfFlushIntervalMs
	if v, ok := os.LookupEnv("IG_PERF_FLUSH_INTERVAL_MS"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ms = n
		}
	}
	return time.Duration(ms) * time.Millisecond
}
