# Socket lifecycle — sock_state transitions, RST direction, point-in-time snapshot

Three capabilities answer "what is happening to this TCP connection": `sock_state`
(the transition tracer — the *history*), the RST-direction signals (who reset whom),
and `sock_snapshot` (the *right-now* view). Together they distinguish the classic
ambiguous failures: **refused vs reset vs peer-closed vs stale-endpoint**.

## 1. `sock_state` — TCP state-machine tracer (datasource `ebpf_proxy_sockstate`)

Fires on `inet_sock_set_state` (every TCP state transition) plus the two RST paths.
Key fields:

| field | meaning |
|---|---|
| `ss_op` | decoded op: `transition` / `reset_rx` (inbound RST) / `reset_tx` (we sent RST) — prefer over `ss_op_raw` |
| `oldstate` / `newstate` | TCP states (1=ESTABLISHED, 2=SYN_SENT, 3=SYN_RECV, 4=FIN_WAIT1, 5=FIN_WAIT2, 6=TIME_WAIT, 7=CLOSE, 8=CLOSE_WAIT, 9=LAST_ACK, 10=LISTEN, 11=CLOSING, 12=NEW_SYN_RECV) |
| `saddr/daddr/sport/dport` | the 4-tuple (network order addrs, host-order ports) |
| `family` | 2=AF_INET, 10=AF_INET6 |
| `reset_dir` | 0=n/a (transition row), 1=inbound RST RECEIVED (`tcp_reset`), 2=outbound RST SENT (`tcp_v4_send_reset`) |
| `sk_null` | 1 iff the send-reset had `sk==NULL` — kernel sent a RST with NO matching socket (stale/torn-down endpoint). The stale-endpoint smoking gun; the 4-tuple is parsed from the offending packet so the target is still named |
| `proc` | process context — often softirq/timer; **key on the 4-tuple, not proc** |

### Decisive transition patterns (memorize these)
- **Connection refused / never established:** `SYN_SENT(2) → CLOSE(7)` with **no
  ESTABLISHED(1)** in between. The peer answered the SYN with a RST (or nothing +
  timeout). Distinguishes "refused" from "reset after working".
- **Peer half-closed first (peer sent FIN):** `ESTABLISHED(1) → CLOSE_WAIT(8)`. Your
  side still owes a `close()`; if you never send it → fd/half-open leak.
- **We closed first:** `ESTABLISHED(1) → FIN_WAIT1(4) → FIN_WAIT2(5) → TIME_WAIT(6)`.
- **Inbound RST on a live socket** (peer reset an established conn): a row with
  `ss_op=reset_rx`, `reset_dir=1` on an `ESTABLISHED` tuple.
- **Stale-endpoint RST:** `ss_op=reset_tx`, `sk_null=1` — kernel RST with no socket;
  something is talking to an endpoint that has already gone away (common after a
  crashed/restarted backend; the 4-tuple names who is still knocking).

## 2. `sock_snapshot` — point-in-time per-socket TCP iterator (datasource `ebpf_proxy_socksnap`)

A one-pass walk of live TCP sockets (`iter/tcp`) — the "what does this connection
look like RIGHT NOW" view, independent of whether any event is firing. Fields:

| field | meaning |
|---|---|
| `saddr/daddr/sport/dport` / `family` | the 4-tuple |
| `state` | current TCP state (same enum as above) |
| `netns_id` | network namespace (which pod/container the socket lives in) |
| `sock_kind` | listening vs established vs time-wait class |
| `srtt_us` | smoothed RTT (µs) — the live latency of the path |
| `rto` | retransmission timeout |
| `retransmits` | current retransmit counter on this socket |
| `snd_cwnd` | congestion window |
| `sndq_bytes` / `unacked_bytes` / `rcvq_bytes` | send-queue / in-flight-unacked / receive-queue backlog |
| `last_snd_ts` | time of last send |

### Reading a snapshot
- **"The connection is stuck":** high `sndq_bytes` + high `unacked_bytes` +
  non-zero `retransmits` + growing `rto` = we're sending but the peer isn't ACKing
  (network/peer stall, not our app).
- **"Receiver not draining":** high `rcvq_bytes` with our app as owner = the
  application isn't `read()`-ing fast enough (app-side backpressure).
- **`srtt_us`** gives you the real path latency without a ping, per-socket.
- **`state=CLOSE_WAIT`** lingering in a snapshot = the half-close leak from §1 made
  visible as standing state.

## Choosing between them
- Something is *changing* and you want the causal sequence → `sock_state` (history).
- Something is *stuck* and you want the current condition → `sock_snapshot` (state).
- Use both: snapshot finds the wedged socket; sock_state (re-run) shows how it got
  there on the next transition.
