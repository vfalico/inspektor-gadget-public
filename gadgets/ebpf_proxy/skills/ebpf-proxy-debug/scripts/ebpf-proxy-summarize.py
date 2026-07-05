#!/usr/bin/env python3
"""Summarize eBPF Proxy `-o json` (stdin): separate ebpf_proxy_coverage from events, resolve
proc.*, report top files/ports/return-codes so an agent reads signal not 10^5 rows."""
import sys, json, collections
cov=None; ev=[]
for line in sys.stdin:
    line=line.strip()
    if not line.startswith('{'): continue
    try: d=json.loads(line)
    except Exception: continue
    if d.get('capability') and d.get('attached_targets') is not None: cov=d
    else: ev.append(d)
def g(d,*ks):
    for k in ks:
        v=d
        for part in k.split('.'):
            v=v.get(part) if isinstance(v,dict) else None
            if v is None: break
        if v is not None: return v
    return None
print("=== ebpf_proxy_coverage ===")
if cov:
    print(json.dumps({k:cov.get(k) for k in ('capability','attached_count','pid_filter','attached_targets')}))
    if not ev: print("!! attached-but-idle: probes ON, no events. WIDEN --timeout/--pid; do NOT switch capability.")
else:
    print("(no coverage row — check stderr / image build)")
print(f"=== events: {len(ev)} ===")
for field,label in (('fname','files'),('dport','dst ports'),('syscall','syscalls'),
                    ('func','functions'),('net_op','net ops'),('fs_op','fs ops'),('retval','return codes')):
    vals=[g(d,field) for d in ev if g(d,field) is not None]
    if not vals: continue
    c=collections.Counter(map(str,vals)).most_common(5)
    print(f"top {label}: "+", ".join(f"{v} x{n}" for v,n in c))
print("--- sample events ---")
for d in ev[:3]:
    print(json.dumps({'comm':g(d,'proc.comm','comm'),'pid':g(d,'proc.pid','pid'),
        'fname':g(d,'fname'),'retval':g(d,'retval'),'op':g(d,'fs_op','net_op','syscall','func')}))
