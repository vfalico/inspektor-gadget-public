# chaos_dns

DNS chaos on the TC (clsact) datapath. Selectable and runtime-reconfigurable
modes for exercising resolver-failure behaviour of workloads.

## Modes

- **MODE_DROP (1)** — drop the outbound query; client sees a resolver timeout.
- **MODE_RCODE (2)** — reflect the client's own query back as a response with
  `QR=1, RA=1, TC=0` and `RCODE=NXDOMAIN|SERVFAIL`. The reflected reply is built
  in place with `bpf_skb_store_bytes` + `bpf_l4_csum_replace` and bounced on
  ingress via `bpf_clone_redirect` — no `bpf_probe_write_user`, so it works
  under Secure Boot / kernel lockdown. `TC=0` is set explicitly to avoid the
  truncated-bit -> client TCP-retry -> timeout artifact.
- **MODE_MARK (3)** — mark matched packets (`skb->mark`) so a userspace
  `tc-netem` qdisc can add latency (delay handoff).

## Scoping

- UDP dst port 53 (egress query)
- optional client source IP (`client-ip`)
- optional qname match by FNV-1a hash (`qhash`) of the lowercased wire-format qname

## Engineering note (verifier)

Every packet field consumed by MODE_RCODE is read into a local via
`bpf_skb_load_bytes` **before** the first `bpf_skb_store_bytes`, because store
helpers may reallocate the skb and invalidate cached packet pointers.

## Parameters

| key | default | meaning |
|-----|---------|---------|
| `mode` | 1 | 1 drop, 2 synth-rcode, 3 mark-for-delay |
| `rcode` | 3 | RCODE for mode 2 (3 NXDOMAIN, 2 SERVFAIL) |
| `client-ip` | 0 | client source IP to scope (network order; 0 = any) |
| `qhash` | 0 | FNV-1a of qname to match (0 = all) |
| `enable` | true | arm the chaos |

## References

- IG DNS tracing: https://www.inspektor-gadget.io/docs/latest/gadgets/trace_dns
- TC BPF: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/
