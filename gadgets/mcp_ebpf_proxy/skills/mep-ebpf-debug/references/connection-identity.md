# Connection identity — the inline 4-tuple, socket-pair correlation, peer identity

MEP stamps **socket identity inline on every socket-bearing event**, so you rarely
need a second capability just to answer "which connection was that?". This is the
single biggest workflow change: on a kprobe/syscall/net/fs row you already have the
connection.

## 1. The inline 4-tuple (always-on)

Any event that ran while a `struct sock *` was in scope carries:

| field | meaning |
|---|---|
| `saddr` / `daddr` | local / remote IPv4 (columns render network order; hex flag set) |
| `sport` / `dport` | local / remote port (host order) |
| `sk_family` | address family (2 = AF_INET, 10 = AF_INET6) |
| `sk_state` | TCP state at event time (1=ESTABLISHED … 10=LISTEN; see socket-lifecycle.md) |

On a row where no socket was in scope, `sk_family=0` and the address fields are
zero — that gate is how you tell "this event had no connection" from "this event's
connection is 0.0.0.0". Present on the `mep` (attach/uprobe), `mep_sys`
(trace_syscall), `mep_net` (net_trace), and `mep_fs` (fs_trace) datasources.

**Why it matters:** to answer "was this failing `openat` on a socket-handling
thread, and to whom was it talking?", you no longer correlate two traces by PID +
timestamp — the `fs_trace` row already names the peer.

## 2. `sockpair_correlate` — downstream ↔ upstream socket link (datasource `mep_sockpair`)

A proxy accepts a downstream connection and opens an upstream one. To prove *which
upstream serves which downstream* (the core proxy question), `sockpair_correlate`
links the `accept()`-side socket to the `connect()`-side socket in the same task:

| field | meaning |
|---|---|
| `down_saddr/daddr/sport/dport` | the accepted (downstream/client-facing) 4-tuple |
| `up_saddr/daddr/sport/dport` | the initiated (upstream/backend-facing) 4-tuple |
| `down_state` / `up_state` | TCP state of each side |
| `up_retval` | return of the upstream `connect()` (0 ok, `-errno` = upstream refused) |
| `accept_to_connect_ns` | latency from accept to the matching upstream connect |
| `proc` | the proxy task that owns both sockets |

**Read it as:** one row = one proxied flow. A large `accept_to_connect_ns` isolates
proxy-internal routing/policy latency from network latency. A negative `up_retval`
with a healthy downstream says "the client is fine; the backend refused us."

## 3. Peer identity — `dst_endpoint` and k8s pod meta (datasource `mep_net`)

`net_trace` emits `dst_endpoint`, the remote peer published as IG's standard
`gadget_l4endpoint_t`. In a Kubernetes cluster IG's enrichment resolves that
endpoint to pod/namespace/service metadata, so "who is on the far end" is answered
without a second lookup. Pair it with the inline 4-tuple on other capabilities to
carry peer identity across families.

Other `mep_net` fields: `connect_latency_ns` (SYN→established), `retrans_out`
(retransmit count — the retransmit/slow-connect signal), `tcp_state`, `bytes`,
`retval`.

## 4. `kern_user_correlate` — bind a userspace fd to its kernel socket

When you attach a **uprobe** to a userspace function whose argument is a file
descriptor (e.g. a proxy's `on_read(fd)`), MEP resolves that fd through the calling
task's fd-table (CO-RE walk of `bpf_get_current_task`) to the underlying
`struct sock *` and stamps the **same inline 4-tuple** on the uprobe row. That is
the userspace-symbol → kernel-socket bridge:

- attach with `attach_uprobe --target=<lib-or-binary>:<symbol>` where the symbol
  takes an fd arg; read `daddr/dport/saddr/sport/sk_state` on the resulting `mep`
  rows.
- Now a purely userspace event ("my handler ran for fd 27") is tied to a concrete
  peer ("fd 27 = 10.0.0.7:8080, ESTABLISHED") with no guesswork.

## Worked pattern — "which backend is this proxy hitting for client X?"
1. `sockpair_correlate --pid=<proxy>` → find the row whose `down_*` 4-tuple is
   client X; read its `up_*` 4-tuple = the backend.
2. If the backend is refusing: `sock_state --pid=<proxy>` and look for
   `newstate` SYN_SENT→CLOSE on that `up_*` tuple (see socket-lifecycle.md).
3. To name the backend pod: `net_trace --pid=<proxy>` and read `dst_endpoint`.
