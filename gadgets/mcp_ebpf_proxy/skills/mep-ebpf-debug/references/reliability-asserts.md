# Reliability asserts — absence_assert (proof-of-absence) and per_key_rollup

Most tracers answer "what happened?". These two answer the harder questions
"what SHOULD have happened but DIDN'T?" (`absence_assert`) and "what is the
aggregate shape of this flow?" (`per_key_rollup`) — without shipping every event.

## 1. `absence_assert` — proof that a periodic write stopped (datasource `mep_absence`)

A keepalive, SSE stream, heartbeat, or health-ping is *supposed* to write on the
socket every N ms. When it silently stops, a normal tracer shows **nothing** — and
"no events" is ambiguous (idle vs dead). `absence_assert` turns that silence into an
affirmative **verdict**: it knows the expected period and flags when the observed gap
exceeds it.

| field | meaning |
|---|---|
| `verdict` | the assertion result: e.g. PASS (writes within period) / FAIL/STALE (gap exceeded) — the whole point of the capability |
| `saddr/daddr/sport/dport` | the flow being asserted on |
| `state` | TCP state of that socket |
| `last_write_gap_ns` | time since the last write on this flow |
| `expected_period_ns` | the period you armed (`--absence_period_ns`) |
| `observed_max_gap_ns` | worst gap seen in the window |
| `write_count` | how many writes actually occurred |
| `closing_evts` | count of close/shutdown/RST seen on the flow (did it stop because it *closed*?) |

### How to arm it
- Provide the expected cadence via the absence period param (nanoseconds) and scope
  to the host/flow (`--host`, `--pid`). `period=0` disables the assertion and emits
  **observational INFO rows only** (gaps reported, no verdict) — use that first to
  learn the natural cadence, then arm the real threshold.
- To record the *writes* it measures against, run it over a window where the traffic
  is (or should be) live; pair with `net_trace` if you also want the payload volume.

### Reading it
- `verdict=FAIL` with `observed_max_gap_ns >> expected_period_ns` and
  `closing_evts=0` → the writer **silently stalled** while the socket stayed open
  (app-level hang: the thread that pumps the heartbeat is stuck — cross-check with
  `epoll_timer`/`call_depth`).
- `verdict=FAIL` with `closing_evts>0` → it stopped because the flow **closed/RST**
  (a connection problem, not a stuck writer — pivot to `sock_state`).
- `write_count` climbing with `verdict=PASS` → the periodic writer is healthy;
  you've *ruled out* the heartbeat as the fault (a proof-of-presence, equally useful).

This is the capability that answers "prove the SSE stream is dead" rather than
"I don't see any SSE events (…which could just mean quiet)".

## 2. `per_key_rollup` — per-flow counters & inter-event gaps (datasource `net_rollup`)

Instead of one row per packet (which floods and truncates), `per_key_rollup`
aggregates **per 4-tuple key** in-kernel and emits compact rollup rows:

| field | meaning |
|---|---|
| `saddr/daddr/sport/dport` | the flow key |
| `count` | events aggregated for this flow |
| `bytes_sum` | total bytes over the flow |
| `gap_min_ns` / `gap_max_ns` / `gap_sum_ns` | inter-event gap distribution (min/max/total) — the *timing shape* without per-event rows |
| `retrans_count` | retransmits on the flow |
| `rst_count` | RSTs on the flow |
| `closing_evts` | close/shutdown events |
| `last_state` | last TCP state seen |
| `first_ts_raw` / `last_ts_raw` | flow window |
| `pid` / `comm` | owning task |

### Why it's the anti-truncation tool
A chatty flow that would blow the output budget as 50k individual rows collapses to
**one rollup row per connection** carrying the same decision content: how many, how
many bytes, the gap distribution (is it steady or bursty?), and the error counters
(`retrans_count`/`rst_count`). `gap_max_ns` spiking while `gap_min_ns` stays small =
a flow that mostly flows but periodically **stalls** — the exact signal you'd
otherwise reconstruct by eyeballing thousands of timestamps.

### Reading it
- Rank flows by `retrans_count`/`rst_count` → the unhealthy connections, ranked, in
  a handful of rows.
- `bytes_sum` + `count` → mean event size; a tiny mean with huge `count` = chatty
  small-write pattern (Nagle/latency territory).
- `gap_sum_ns / count` → mean cadence; compare against an SLA without per-event data.

## Choosing between them
- You have an EXPECTED cadence and want a verdict when it's violated →
  `absence_assert`.
- You want the aggregate health/timing of one or many flows cheaply →
  `per_key_rollup`.
- Combined: `per_key_rollup` finds the flow with the worst `gap_max_ns`;
  `absence_assert` on that flow's period converts the suspicion into a PASS/FAIL.
