# Event loop, recursion & stack depth — epoll_timer, call_depth, stack watermark

These capabilities target the "it's not crashing, it's *stuck* or *spinning*" class:
a stalled event loop, a call that recursed without returning, or a stack creeping
toward overflow. All three are about **control-flow depth and timer/epoll causality**,
not data.

## 1. `epoll_timer` — event-loop causal chain (datasource `mep_timer`)

Traces the timer/epoll machinery an event loop is built on: `timerfd`, `hrtimer`,
and `epoll_wait` readiness. This is how you see *why an event loop went quiet* or
*why it's waking with nothing to do*.

| field | meaning |
|---|---|
| `kind_raw` | which mechanism fired (timerfd / hrtimer / epoll) — decoded class |
| `fd` | the epoll or timer fd involved |
| `nready` | number of ready events `epoll_wait` returned (0 = woke with nothing) |
| `ev_mask` | epoll event mask (EPOLLIN/OUT/ERR/HUP bits) |
| `op` | the operation (wait / arm / expire) |
| `expires_ns` | programmed timer expiry |
| `timer_ptr` | kernel timer object identity (correlate arm→expire) |
| `proc` | the task running the loop |

### Patterns
- **Loop stalled (no progress):** `epoll_wait` returning with `nready=0` in a tight
  cycle = the loop is spinning on spurious wakeups, or its timers keep firing with no
  I/O ready. Look at `ev_mask` — an `EPOLLHUP`/`EPOLLERR` bit means a watched fd died
  and the loop keeps re-arming a dead descriptor.
- **Timer never re-armed (heartbeat died):** you see the `arm` for a `timer_ptr`, an
  `expire`, then no subsequent `arm` — the periodic task stopped rescheduling itself.
  (For an affirmative "the write stopped" verdict, use `absence_assert` —
  reliability-asserts.md.)
- **Wrong timeout:** `expires_ns` far in the future while the app "feels slow" =
  a mis-programmed poll timeout, not kernel latency.

## 2. Recursion / call-never-returned — `call_depth` + `phase`

Every `attach`/`attach_uprobe` row carries `phase` (`enter`|`ret`) and, for the
uprobe pairing engine, `call_depth` — the in-flight nesting depth of the same
call chain on the same thread. MEP auto-pairs enter/return.

| field | meaning |
|---|---|
| `phase` | `enter` or `ret` (raw in `phase_raw`) |
| `call_depth` | current in-flight depth for this tid's chain |

### Patterns
- **Runaway recursion:** `call_depth` climbing monotonically with only `enter`
  phases and no matching `ret` = the function is recursing (or re-entering) without
  unwinding — the classic pre-stack-overflow signature.
- **Call that never returned (hang):** an `enter` with no paired `ret` within the
  window, `call_depth` stuck at N = the call is blocked *inside* that function.
  Cross-reference with `lock_trace` (blocked on a mutex) or `sock_snapshot`
  (blocked on a wedged socket).

## 3. Stack-depth watermark — `stack_used` + `stack_alarm`

Arms a one-shot alarm when a call chain's stack usage first crosses a threshold —
catch a near-overflow *before* it faults.

| field | meaning |
|---|---|
| `stack_used` | bytes of stack consumed by this call chain |
| `stack_alarm` | 1 on the one-shot row where `stack_used` first crossed the armed watermark (fires at most once per tid chain); 0 otherwise |

Arm it by setting the stack watermark param (e.g. `6291456` for 6 MiB). When
`stack_alarm=1` fires, `stack_used` tells you how deep you got and the inline
4-tuple/`func` tells you on which request path — actionable before a crash.

## 4. `uprobe_argdecode` — symbolized string arg at a uprobe (field `arg_str`)

When a uprobe target's argument is a `char *` (a path, a URL, a query, a hostname),
`arg_str` is the decoded string, not just a raw pointer in `arg0`. That turns
"`SSL_write` was called" into "`SSL_write("GET /healthz ...")` was called" — you see
the actual payload key without a userspace debugger.

- attach with `attach_uprobe --target=<lib-or-binary>:<symbol>`; read `arg_str`
  alongside `arg0..arg4` on the `mep` datasource.
- Combine with `call_depth`/`phase` to see *which* recursion level passed *which*
  string.

## Worked pattern — "the proxy's event loop wedged"
1. `epoll_timer --pid=<proxy>` → is `epoll_wait` returning `nready=0` in a spin, or
   blocked with no wakeups? Check `ev_mask` for HUP/ERR on a dead fd.
2. If a handler entered and never returned: `attach_uprobe --target=<proxy-bin>:<handler>`
   and watch `call_depth`/`phase` for an unpaired `enter`.
3. If it's recursing toward overflow: arm the stack watermark and catch `stack_alarm=1`.
