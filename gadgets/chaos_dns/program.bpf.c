// SPDX-License-Identifier: Apache-2.0
/* chaos_dns — TC-eBPF DNS chaos: DROP / DELAY-mark / synthesize NXDOMAIN|SERVFAIL.
 *
 * Attaches to TC egress (client -> resolver). Modes, selectable +
 * reconfigurable AT RUNTIME via the cfg map (no reload):
 *   MODE_DROP  : silently drop the DNS query        -> client sees timeout
 *   MODE_RCODE : REFLECT the client's own query back as a response with
 *                QR=1, RA=1, RCODE=NXDOMAIN|SERVFAIL, and CRUCIALLY TC=0.
 *                We do NOT use bpf_probe_write_user (unavailable under Secure
 *                Boot / kernel lockdown). Instead we mutate the skb in place
 *                with bpf_skb_store_bytes + bpf_l4_csum_replace and bounce it
 *                back on INGRESS via bpf_clone_redirect. Minimal-mutation
 *                reflect keeps the question section byte-identical and sets
 *                flags precisely, so the client never sees the TC (truncated)
 *                bit -> no spurious TCP retry.
 *   MODE_MARK  : mark matched packets for a userspace tc-netem delay handoff.
 *
 * Scope: UDP dst port 53, by client saddr (target pod/PID IP filled by loader),
 * by target qname hash (FNV-1a). PID/mntns scoping for DNS is done by the LSM
 * socket companion; on TC we scope by saddr + qname.
 *
 * ENGINEERING NOTE (verifier): every packet field needed by MODE_RCODE is read
 * into a local via bpf_skb_load_bytes BEFORE the first bpf_skb_store_bytes,
 * because store helpers may reallocate the skb and INVALIDATE all packet
 * pointers (data/eth/ip/udp). Dereferencing a cached packet pointer after a
 * store is rejected as "invalid mem access 'scalar'".
 *
 * Copyright 2026 The Inspektor Gadget authors
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP    0x0800
#define IPPROTO_UDP 17
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#ifndef BPF_F_INGRESS
#define BPF_F_INGRESS (1ULL << 0)
#endif

#define MODE_OFF   0
#define MODE_DROP  1
#define MODE_RCODE 2
#define MODE_MARK  3

#define RCODE_NXDOMAIN 3
#define RCODE_SERVFAIL 2

struct cfg_t {
	__u32 mode;
	__u32 rcode;        /* used in MODE_RCODE */
	__u32 target_saddr; /* network order; 0 = any client */
	__u32 match_qhash;  /* fnv1a of lowercased qname; 0 = all names */
	__u32 enabled;
	__u64 hits;
};
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct cfg_t); } cfg SEC(".maps");

struct dns_event { __u64 ts; __u32 saddr,daddr; __u16 sport,dport; __u32 mode; __u32 qhash; };
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,1<<16); } events SEC(".maps");

struct dnshdr { __u16 id; __u16 flags; __u16 qd, an, ns, ar; };

static __always_inline struct cfg_t *getcfg(void){ __u32 k=0; return bpf_map_lookup_elem(&cfg,&k); }

/* FNV-1a over wire-format qname (labels), lowercased. Bounded loop. */
static __always_inline __u32 qname_hash(struct __sk_buff *skb, __u32 off)
{
	__u32 h = 2166136261u;
	#pragma unroll
	for (int i=0;i<64;i++){
		__u8 b;
		if (bpf_skb_load_bytes(skb, off+i, &b, 1) < 0) break;
		if (b==0) break;
		if (b>='A'&&b<='Z') b += 32;
		h = (h ^ b) * 16777619u;
	}
	return h;
}

SEC("tc")
int chaos_dns(struct __sk_buff *skb)
{
	struct cfg_t *c = getcfg();
	if (!c || !c->enabled || c->mode==MODE_OFF) return TC_ACT_OK;

	void *data = (void*)(long)skb->data;
	void *end  = (void*)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void*)(eth+1) > end) return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
	struct iphdr *ip = (void*)(eth+1);
	if ((void*)(ip+1) > end) return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
	__u32 ihl = ip->ihl*4;
	struct udphdr *udp = (void*)ip + ihl;
	if ((void*)(udp+1) > end) return TC_ACT_OK;
	if (udp->dest != bpf_htons(53)) return TC_ACT_OK;   /* egress query only */

	if (c->target_saddr && ip->saddr != c->target_saddr) return TC_ACT_OK;

	__u32 ip_off  = (void*)ip  - data;
	__u32 udp_off = (void*)udp - data;
	__u32 dns_off = udp_off + sizeof(struct udphdr);

	if (c->match_qhash){
		__u32 qh = qname_hash(skb, dns_off + sizeof(struct dnshdr));
		if (qh != c->match_qhash) return TC_ACT_OK;
	}

	/* Observability event. */
	struct dns_event *e = bpf_ringbuf_reserve(&events,sizeof(*e),0);
	if (e){ e->ts=bpf_ktime_get_ns(); e->saddr=ip->saddr; e->daddr=ip->daddr;
		e->sport=udp->source; e->dport=udp->dest; e->mode=c->mode;
		e->qhash=c->match_qhash; bpf_ringbuf_submit(e,0); }
	__sync_fetch_and_add(&c->hits,1);

	if (c->mode==MODE_DROP)  return TC_ACT_SHOT;
	if (c->mode==MODE_MARK){ skb->mark = 0xDEAD; return TC_ACT_OK; }

	if (c->mode==MODE_RCODE){
		/* Cache EVERY field we need BEFORE the first store (stores invalidate
		 * packet pointers). Read via load_bytes so nothing depends on stale
		 * data/eth/ip/udp pointers afterwards. */
		__u32 flags_off = dns_off + offsetof(struct dnshdr, flags);
		__u16 sp, dp, oldflags; __u32 sa, da; __u8 smac[6], dmac[6];

		if (bpf_skb_load_bytes(skb, udp_off+offsetof(struct udphdr,source), &sp, 2) < 0) return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, udp_off+offsetof(struct udphdr,dest),   &dp, 2) < 0) return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, ip_off +offsetof(struct iphdr,saddr),   &sa, 4) < 0) return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, ip_off +offsetof(struct iphdr,daddr),   &da, 4) < 0) return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, flags_off, &oldflags, 2) < 0) return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr,h_source), smac, 6) < 0) return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr,h_dest),   dmac, 6) < 0) return TC_ACT_OK;

		/* QR=1 AA=0 TC=0 RD=1 RA=1 | RCODE. Base 0x8180 guarantees TC=0. */
		__u16 newflags = bpf_htons(0x8180 | (c->rcode & 0x0F));

		/* (a) DNS flags: only real payload change -> fix UDP csum for THIS delta. */
		bpf_skb_store_bytes(skb, flags_off, &newflags, 2, 0);
		bpf_l4_csum_replace(skb, udp_off+offsetof(struct udphdr,check), oldflags, newflags, 2);

		/* (b) swap UDP ports (checksum-neutral: sp+dp == dp+sp). */
		bpf_skb_store_bytes(skb, udp_off+offsetof(struct udphdr,source), &dp, 2, 0);
		bpf_skb_store_bytes(skb, udp_off+offsetof(struct udphdr,dest),   &sp, 2, 0);

		/* (c) swap IP src/dst. IP header csum AND UDP pseudo-header csum are
		 *     one's-complement neutral under a saddr<->daddr swap -> no csum
		 *     fixup needed for the address swap. */
		bpf_skb_store_bytes(skb, ip_off+offsetof(struct iphdr,saddr), &da, 4, 0);
		bpf_skb_store_bytes(skb, ip_off+offsetof(struct iphdr,daddr), &sa, 4, 0);

		/* (d) swap MACs so the reflected frame heads back toward the client. */
		bpf_skb_store_bytes(skb, offsetof(struct ethhdr,h_dest),   smac, 6, 0);
		bpf_skb_store_bytes(skb, offsetof(struct ethhdr,h_source), dmac, 6, 0);

		/* Bounce the mutated frame in on INGRESS so the local resolver/client
		 * receives it as the reply; drop the original outbound query. */
		bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}
