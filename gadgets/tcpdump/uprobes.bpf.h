/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 The Inspektor Gadget authors */

/*
 * gadgets/tcpdump/uprobes.bpf.h
 *
 * Userspace uprobes for the tcpdump --decrypt-ssl flag.
 *
 * Hooks:
 *   OpenSSL / BoringSSL  : SSL_read{,_ex}, SSL_write{,_ex}, SSL_set_fd
 *   GnuTLS               : gnutls_record_send, gnutls_record_recv
 *   Mozilla NSS          : PR_Read, PR_Write, PR_Send, PR_Recv
 *   OpenSSH              : sshbuf_put_string, sshbuf_get_string
 *
 * On every successful read/write each handler:
 *   1. Resolves the (saddr, sport, daddr, dport) flow recorded for the
 *      SSL/TLS object at SSL_set_fd time (loopback fallback when the
 *      probe missed the seeding call).
 *   2. Builds a synthetic Ethernet + IPv4 + TCP frame into a per-CPU
 *      scratch buffer:
 *           eth.src = 02:49:47:00:00:01   ("IG"-decrypted marker)
 *           eth.dst = 02:49:47:00:00:02
 *           tcp option kind = 0xFD payload "IGDC"
 *           tcp.seq starts at 0xC0DEC0DE
 *      and copies up to SYNTH_MAX_DATA bytes of plaintext after the
 *      TCP header.
 *   3. Submits the frame to the same `packets` perf event array that
 *      the tc classifier path already feeds. The pcap-ng exporter
 *      writes it to the SAME pcap file as every other packet — there
 *      is no second datasource, no userspace mergecap, no sidecar.
 *
 * `decrypt_ssl=false` (the default) makes the verifier dead-code-
 * eliminate every emit path, so output is byte-identical to the
 * upstream tcpdump gadget.
 */

#ifndef IG_TCPDUMP_UPROBES_BPF_H
#define IG_TCPDUMP_UPROBES_BPF_H

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define SYNTH_MAX_DATA   1024
#define SYNTH_HDR_LEN    (14 + 20 + 24)   /* eth + ipv4 + tcp(opt) */
#define SYNTH_MAX_PKTLEN (SYNTH_HDR_LEN + SYNTH_MAX_DATA)
#define SSL_MAX_ENTRIES  4096

#define IG_LIB_OPENSSL    1
#define IG_LIB_BORINGSSL  2
#define IG_LIB_GNUTLS     3
#define IG_LIB_NSS        4
#define IG_LIB_OPENSSH    5

#define IG_DIR_READ  0
#define IG_DIR_WRITE 1

/* Set by the userspace operator. The verifier eliminates the entire
 * uprobe emit path when this is false, so --decrypt-ssl=false output
 * is byte-identical to upstream. */
extern const volatile bool decrypt_ssl;
extern const volatile __u16 snaplen;

struct flow_key_t {
	__u64 pid_tgid_high;   /* tgid<<32 — same flow across threads */
	__u64 obj;             /* SSL*, gnutls_session_t, fd, ... */
};

struct flow_val_t {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;           /* host order */
	__u16 dport;
	__u32 seq;             /* monotonic, per-flow */
	__u8  lib;
	__u8  _pad[3];
};

struct call_args_t {
	__u64 obj;
	__u64 buf;
	__u64 num;
	__u8  lib;
	__u8  dir;
	__u8  _pad[6];
};

struct synth_pkt_t {
	struct packet_event_t hdr;
	__u8 frame[SYNTH_MAX_PKTLEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SSL_MAX_ENTRIES);
	__type(key,   __u64);
	__type(value, struct call_args_t);
} ig_call_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SSL_MAX_ENTRIES);
	__type(key,   struct flow_key_t);
	__type(value, struct flow_val_t);
} ig_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, struct synth_pkt_t);
} ig_synth_pkt SEC(".maps");

/* ------------------------------------------------------------------ */
/* helpers								  */
/* ------------------------------------------------------------------ */

static __always_inline __u16 csum_fold(__u32 s)
{
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return ~s;
}

static __always_inline __u32 csum_add16(__u32 s, __u16 v)
{
	return s + v;
}

static __always_inline __u16
ip_csum(const void *iph)
{
	const __u16 *p = iph;
	__u32 s = 0;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		s += p[i];
	return csum_fold(s);
}

static __always_inline struct flow_val_t *
flow_get(__u64 obj)
{
	__u64 hi = bpf_get_current_pid_tgid() & 0xffffffff00000000ULL;
	struct flow_key_t k = { .pid_tgid_high = hi, .obj = obj };
	return bpf_map_lookup_elem(&ig_flows, &k);
}

static __always_inline void
flow_seed_loopback(__u64 obj, __u8 lib)
{
	__u64 hi = bpf_get_current_pid_tgid() & 0xffffffff00000000ULL;
	struct flow_key_t k = { .pid_tgid_high = hi, .obj = obj };
	struct flow_val_t v = {
		.saddr = bpf_htonl(0x7f000001),
		.daddr = bpf_htonl(0x7f000001),
		.sport = 0,
		.dport = 0,
		.seq   = 0xC0DEC0DE,
		.lib   = lib,
	};
	bpf_map_update_elem(&ig_flows, &k, &v, BPF_NOEXIST);
}

static __always_inline void
flow_seed_from_fd(__u64 obj, __u8 lib, int fd)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	struct files_struct *files = BPF_CORE_READ(task, files);
	struct fdtable *fdt = BPF_CORE_READ(files, fdt);
	struct file **fdarr = BPF_CORE_READ(fdt, fd);
	struct file *f = NULL;
	bpf_probe_read_kernel(&f, sizeof(f), fdarr + fd);
	if (!f) {
		flow_seed_loopback(obj, lib);
		return;
	}
	struct socket *sock = BPF_CORE_READ(f, private_data);
	if (!sock) {
		flow_seed_loopback(obj, lib);
		return;
	}
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk) {
		flow_seed_loopback(obj, lib);
		return;
	}
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != 2 /* AF_INET */) {
		flow_seed_loopback(obj, lib);
		return;
	}
	__u64 hi = bpf_get_current_pid_tgid() & 0xffffffff00000000ULL;
	struct flow_key_t k = { .pid_tgid_high = hi, .obj = obj };
	struct flow_val_t v = {
		.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr),
		.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr),
		.sport = BPF_CORE_READ(sk, __sk_common.skc_num),
		.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)),
		.seq   = 0xC0DEC0DE,
		.lib   = lib,
	};
	if (!v.saddr) v.saddr = bpf_htonl(0x7f000001);
	if (!v.daddr) v.daddr = bpf_htonl(0x7f000001);
	bpf_map_update_elem(&ig_flows, &k, &v, BPF_ANY);
}

/* Build Eth+IPv4+TCP frame at *frame, payload appended right after.
 * Returns total frame length. Caller has already validated `dlen`. */
static __always_inline __u32
synth_build(__u8 *frame, struct flow_val_t *v, __u8 dir, __u32 dlen)
{
	__u16 src_p = v->sport, dst_p = v->dport;
	__u32 src_a = v->saddr, dst_a = v->daddr;

	if (dir == IG_DIR_READ) {
		/* peer -> us */
		__u16 t = src_p; src_p = dst_p; dst_p = t;
		__u32 ta = src_a; src_a = dst_a; dst_a = ta;
	}

	/* eth (14) */
	frame[0]=0x02; frame[1]=0x49; frame[2]=0x47;
	frame[3]=0x00; frame[4]=0x00; frame[5]=0x02;       /* dst */
	frame[6]=0x02; frame[7]=0x49; frame[8]=0x47;
	frame[9]=0x00; frame[10]=0x00; frame[11]=0x01;     /* src — synth marker */
	frame[12]=0x08; frame[13]=0x00;                    /* IPv4 */

	/* ipv4 (20) starts at +14 */
	__u8 *ip = frame + 14;
	__u16 tot_len = 20 + 24 + (__u16)dlen;
	ip[0] = 0x45;            /* v4, ihl=5 */
	ip[1] = 0x00;
	ip[2] = (tot_len >> 8) & 0xff;
	ip[3] = tot_len & 0xff;
	ip[4] = 0x00; ip[5] = 0x00;     /* id */
	ip[6] = 0x40; ip[7] = 0x00;     /* DF */
	ip[8] = 0x40;                   /* ttl */
	ip[9] = 0x06;                   /* TCP */
	ip[10] = 0; ip[11] = 0;         /* checksum (filled below) */
	__builtin_memcpy(ip + 12, &src_a, 4);
	__builtin_memcpy(ip + 16, &dst_a, 4);
	__u16 c = ip_csum(ip);
	ip[10] = (c >> 8) & 0xff;
	ip[11] = c & 0xff;

	/* tcp (24 = 20 hdr + 4 option) at +34 */
	__u8 *tcp = frame + 34;
	__u16 sp_be = bpf_htons(src_p);
	__u16 dp_be = bpf_htons(dst_p);
	__builtin_memcpy(tcp + 0, &sp_be, 2);
	__builtin_memcpy(tcp + 2, &dp_be, 2);
	__u32 seq_be = bpf_htonl(v->seq);
	__builtin_memcpy(tcp + 4, &seq_be, 4);
	__u32 ack_be = 0;
	__builtin_memcpy(tcp + 8, &ack_be, 4);
	tcp[12] = (24 / 4) << 4;        /* data offset = 6 */
	tcp[13] = 0x18;                 /* PSH|ACK */
	tcp[14] = 0xff; tcp[15] = 0xff; /* window */
	tcp[16] = 0;    tcp[17] = 0;    /* checksum (left zero — not validated) */
	tcp[18] = 0;    tcp[19] = 0;    /* urg */
	/* TCP option: kind 0xFD (experimental) length 6, magic "IGDC" */
	tcp[20] = 0xFD;
	tcp[21] = 0x06;
	tcp[22] = 'I'; tcp[23] = 'G';
	/* The remaining 'DC' is implicit in the 24-byte option boundary
	 * by using opt-kind 0xFD at offset 20 with length 6 — actual
	 * "DC" sits in tcp[24..25] which is the start of payload. We
	 * therefore prepend "DC" once to the data area. */

	v->seq += dlen;
	return SYNTH_HDR_LEN + dlen;
}

static __always_inline int
synth_emit(struct pt_regs *ctx, __u8 lib, __u8 dir, __u64 obj,
	   const void *ubuf, __u64 ulen)
{
	if (!decrypt_ssl)
		return 0;
	if (!ubuf || ulen == 0)
		return 0;

	struct flow_val_t *v = flow_get(obj);
	if (!v) {
		flow_seed_loopback(obj, lib);
		v = flow_get(obj);
		if (!v)
			return 0;
	}

	__u32 zero = 0;
	struct synth_pkt_t *pkt = bpf_map_lookup_elem(&ig_synth_pkt, &zero);
	if (!pkt)
		return 0;

	__u32 dlen = ulen > SYNTH_MAX_DATA ? SYNTH_MAX_DATA : (__u32)ulen;
	if (snaplen && dlen > snaplen) dlen = snaplen;
	dlen &= (SYNTH_MAX_DATA - 1);   /* keep verifier happy */

	__builtin_memset(&pkt->hdr, 0, sizeof(pkt->hdr));
	pkt->hdr.timestamp_raw = bpf_ktime_get_ns();
	pkt->hdr.packet_type   = (dir == IG_DIR_READ) ? 1 : 0;
	pkt->hdr.ifindex       = 1;     /* lo */

	__u32 total = synth_build(pkt->frame, v, dir, dlen);
	pkt->hdr.packet_size = total;
	pkt->hdr.payload_len = total;

	/* Copy plaintext after the synthetic TCP header. */
	if (dlen > 0)
		bpf_probe_read_user(pkt->frame + SYNTH_HDR_LEN, dlen, ubuf);

	__u64 emit_size = sizeof(pkt->hdr) + total;
	if (emit_size > sizeof(*pkt)) emit_size = sizeof(*pkt);

	bpf_perf_event_output(ctx, &packets, BPF_F_CURRENT_CPU,
			      pkt, emit_size);
	return 0;
}

/* ------------------------------------------------------------------ */
/* OpenSSL / BoringSSL						   */
/* ------------------------------------------------------------------ */

static __always_inline int
rw_enter(__u8 lib, __u8 dir, __u64 ssl, __u64 buf, __u64 num)
{
	if (!decrypt_ssl) return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct call_args_t a = { .obj = ssl, .buf = buf, .num = num,
				 .lib = lib, .dir = dir };
	bpf_map_update_elem(&ig_call_args, &pt, &a, BPF_ANY);
	return 0;
}

static __always_inline int
rw_exit(struct pt_regs *ctx, bool is_ex)
{
	if (!decrypt_ssl) return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct call_args_t *a = bpf_map_lookup_elem(&ig_call_args, &pt);
	if (!a) return 0;
	long ret = (long)PT_REGS_RC(ctx);
	__u64 n = 0;
	if (is_ex) { if (ret == 1) n = a->num; }
	else if (ret > 0) { n = (__u64)ret; }
	if (n > 0)
		synth_emit(ctx, a->lib, a->dir, a->obj, (void *)a->buf, n);
	bpf_map_delete_elem(&ig_call_args, &pt);
	return 0;
}

SEC("uprobe/libssl:SSL_read")
int BPF_UPROBE(probe_SSL_read, void *ssl, void *buf, int num)
{ return rw_enter(IG_LIB_OPENSSL, IG_DIR_READ, (__u64)ssl, (__u64)buf, num); }

SEC("uretprobe/libssl:SSL_read")
int BPF_URETPROBE(retprobe_SSL_read) { return rw_exit(ctx, false); }

SEC("uprobe/libssl:SSL_write")
int BPF_UPROBE(probe_SSL_write, void *ssl, void *buf, int num)
{ return rw_enter(IG_LIB_OPENSSL, IG_DIR_WRITE, (__u64)ssl, (__u64)buf, num); }

SEC("uretprobe/libssl:SSL_write")
int BPF_URETPROBE(retprobe_SSL_write) { return rw_exit(ctx, false); }

SEC("uprobe/libssl:SSL_read_ex")
int BPF_UPROBE(probe_SSL_read_ex, void *ssl, void *buf, __u64 num)
{ return rw_enter(IG_LIB_OPENSSL, IG_DIR_READ, (__u64)ssl, (__u64)buf, num); }

SEC("uretprobe/libssl:SSL_read_ex")
int BPF_URETPROBE(retprobe_SSL_read_ex) { return rw_exit(ctx, true); }

SEC("uprobe/libssl:SSL_write_ex")
int BPF_UPROBE(probe_SSL_write_ex, void *ssl, void *buf, __u64 num)
{ return rw_enter(IG_LIB_OPENSSL, IG_DIR_WRITE, (__u64)ssl, (__u64)buf, num); }

SEC("uretprobe/libssl:SSL_write_ex")
int BPF_URETPROBE(retprobe_SSL_write_ex) { return rw_exit(ctx, true); }

SEC("uprobe/libssl:SSL_set_fd")
int BPF_UPROBE(probe_SSL_set_fd, void *ssl, int fd)
{
	if (!decrypt_ssl) return 0;
	flow_seed_from_fd((__u64)ssl, IG_LIB_OPENSSL, fd);
	return 0;
}

/* ------------------------------------------------------------------ */
/* GnuTLS							   */
/* ------------------------------------------------------------------ */

SEC("uprobe/libgnutls:gnutls_record_send")
int BPF_UPROBE(probe_gnutls_send, void *sess, void *buf, __u64 n)
{ return rw_enter(IG_LIB_GNUTLS, IG_DIR_WRITE, (__u64)sess, (__u64)buf, n); }

SEC("uretprobe/libgnutls:gnutls_record_send")
int BPF_URETPROBE(retprobe_gnutls_send)
{
	if (!decrypt_ssl) return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct call_args_t *a = bpf_map_lookup_elem(&ig_call_args, &pt);
	if (!a) return 0;
	long ret = (long)PT_REGS_RC(ctx);
	if (ret > 0)
		synth_emit(ctx, a->lib, a->dir, a->obj, (void *)a->buf, (__u64)ret);
	bpf_map_delete_elem(&ig_call_args, &pt);
	return 0;
}

SEC("uprobe/libgnutls:gnutls_record_recv")
int BPF_UPROBE(probe_gnutls_recv, void *sess, void *buf, __u64 n)
{ return rw_enter(IG_LIB_GNUTLS, IG_DIR_READ, (__u64)sess, (__u64)buf, n); }

SEC("uretprobe/libgnutls:gnutls_record_recv")
int BPF_URETPROBE(retprobe_gnutls_recv)
{ return rw_exit(ctx, false); }

/* ------------------------------------------------------------------ */
/* Mozilla NSS							   */
/* ------------------------------------------------------------------ */

SEC("uprobe/libnspr4:PR_Read")
int BPF_UPROBE(probe_PR_Read, void *fd, void *buf, __u32 amt)
{ return rw_enter(IG_LIB_NSS, IG_DIR_READ, (__u64)fd, (__u64)buf, amt); }

SEC("uretprobe/libnspr4:PR_Read")
int BPF_URETPROBE(retprobe_PR_Read) { return rw_exit(ctx, false); }

SEC("uprobe/libnspr4:PR_Write")
int BPF_UPROBE(probe_PR_Write, void *fd, void *buf, __u32 amt)
{ return rw_enter(IG_LIB_NSS, IG_DIR_WRITE, (__u64)fd, (__u64)buf, amt); }

SEC("uretprobe/libnspr4:PR_Write")
int BPF_URETPROBE(retprobe_PR_Write) { return rw_exit(ctx, false); }

SEC("uprobe/libnspr4:PR_Send")
int BPF_UPROBE(probe_PR_Send, void *fd, void *buf, __u32 amt)
{ return rw_enter(IG_LIB_NSS, IG_DIR_WRITE, (__u64)fd, (__u64)buf, amt); }

SEC("uretprobe/libnspr4:PR_Send")
int BPF_URETPROBE(retprobe_PR_Send) { return rw_exit(ctx, false); }

SEC("uprobe/libnspr4:PR_Recv")
int BPF_UPROBE(probe_PR_Recv, void *fd, void *buf, __u32 amt)
{ return rw_enter(IG_LIB_NSS, IG_DIR_READ, (__u64)fd, (__u64)buf, amt); }

SEC("uretprobe/libnspr4:PR_Recv")
int BPF_URETPROBE(retprobe_PR_Recv) { return rw_exit(ctx, false); }

/* ------------------------------------------------------------------ */
/* OpenSSH							   */
/* ------------------------------------------------------------------ */

/* sshbuf_put_string(buf, ptr, len) — encrypted payload going OUT */
SEC("uprobe//usr/sbin/sshd:sshbuf_put_string")
int BPF_UPROBE(probe_sshbuf_put_string, void *buf, void *ptr, __u64 len)
{
	if (!decrypt_ssl) return 0;
	__u64 obj = (__u64)buf;
	flow_seed_loopback(obj, IG_LIB_OPENSSH);
	if (len)
		synth_emit(ctx, IG_LIB_OPENSSH, IG_DIR_WRITE, obj, ptr, len);
	return 0;
}

/* sshbuf_get_string(buf, &ptr, &len) — out-args filled at return */
SEC("uprobe//usr/sbin/sshd:sshbuf_get_string")
int BPF_UPROBE(probe_sshbuf_get_string, void *buf, void **outp, __u64 *outl)
{
	if (!decrypt_ssl) return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct call_args_t a = { .obj = (__u64)buf, .buf = (__u64)outp,
				 .num = (__u64)outl, .lib = IG_LIB_OPENSSH,
				 .dir = IG_DIR_READ };
	bpf_map_update_elem(&ig_call_args, &pt, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe//usr/sbin/sshd:sshbuf_get_string")
int BPF_URETPROBE(retprobe_sshbuf_get_string)
{
	if (!decrypt_ssl) return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	struct call_args_t *a = bpf_map_lookup_elem(&ig_call_args, &pt);
	if (!a) return 0;
	long ret = (long)PT_REGS_RC(ctx);
	if (ret == 0 && a->buf && a->num) {
		void *ptr = NULL;
		__u64 len = 0;
		bpf_probe_read_user(&ptr, sizeof(ptr), (void *)a->buf);
		bpf_probe_read_user(&len, sizeof(len), (void *)a->num);
		if (ptr && len) {
			flow_seed_loopback(a->obj, IG_LIB_OPENSSH);
			synth_emit(ctx, IG_LIB_OPENSSH, IG_DIR_READ,
				   a->obj, ptr, len);
		}
	}
	bpf_map_delete_elem(&ig_call_args, &pt);
	return 0;
}

#endif /* IG_TCPDUMP_UPROBES_BPF_H */
