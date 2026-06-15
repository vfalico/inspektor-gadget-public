// Copyright 2023 The Inspektor Gadget authors
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

const (
	PinPath = "/sys/fs/bpf/gadget"

	PerfBufferPages = 64

	// PerfWakeupEvents batches perf-buffer wakeups so the single epoll consumer
	// is not woken on every sample. Critical on high-core-count nodes lacking
	// BPF ring buffer (kernel < 5.8, e.g. Ubuntu 20.04 / 5.4 FIPS), where IG
	// falls back to the legacy per-CPU perf buffer. 0 = legacy per-event wakeup.
	// Overridable at runtime with IG_PERF_WAKEUP_EVENTS.
	PerfWakeupEvents = 64

	// PerfFlushIntervalMs bounds the extra latency introduced by PerfWakeupEvents
	// batching: a background timer flushes partially-filled per-CPU perf buffers
	// at this cadence so low-rate buffers do not stall until they fill. 0 disables
	// the timer (pure batching). Overridable with IG_PERF_FLUSH_INTERVAL_MS.
	PerfFlushIntervalMs = 200

	// Constant used to enable filtering by mount namespace inode id in eBPF.
	// Keep in syn with variable defined in include/gadget/mntns_filter.h.
	FilterByMntNsName = "gadget_filter_by_mntns"

	// Name of the map that stores the mount namespace inode id to filter on.
	// Keep in syn with name used in include/gadget/mntns_filter.h.
	MntNsFilterMapName = "gadget_mntns_filter_map"
)
