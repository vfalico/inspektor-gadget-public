#!/usr/bin/env python3
"""gpu_mem_max integration test — attach gadget, run torch alloc, assert ALLOC event."""
import json, os, subprocess, time

OUT = '/tmp/gpu_mem_max_it.jsonl'
open(OUT, 'w').close()
p = subprocess.Popen(['sudo', 'ig', 'run', 'gpu_mem_max:v0',
                      '--verify-image=false', '-o', 'json', '--host'],
                     stdout=open(OUT, 'wb'), stderr=subprocess.DEVNULL,
                     preexec_fn=os.setsid)
time.sleep(3)
subprocess.check_call(['python3', '-c',
    'import torch; x=torch.zeros(1024,1024,device="cuda"); import time; time.sleep(1)'])
time.sleep(2)
os.killpg(os.getpgid(p.pid), 2); p.wait(timeout=5)
evs = [json.loads(l) for l in open(OUT) if l.strip()]
allocs = [e for e in evs if e.get('type') == 1]
assert any(e.get('size_bytes', 0) >= 1024*1024 for e in allocs), f'no >=1MB ALLOC ({len(allocs)} total)'
print(f'PASS — {len(allocs)} ALLOC events seen')
