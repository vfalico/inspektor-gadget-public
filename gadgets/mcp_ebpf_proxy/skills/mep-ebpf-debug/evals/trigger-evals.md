# Trigger evals for mep-ebpf-debug (tune the description)
# 24 prompts: 16 SHOULD trigger, 8 should NOT. Run by checking whether the
# description's trigger phrases match the prompt intent.

## SHOULD trigger (load the skill)
1. "my service logs 'config not found' and keeps restarting — find what file it can't open"
2. "this daemon leaks file descriptors, prove which fds aren't closed"
3. "the process RSS climbs forever, is it a malloc leak?"
4. "the app hangs — I think two threads deadlock on a mutex"
5. "we see TCP connection resets to the DB, trace them"
6. "connect() to the upstream is slow, measure the latency in-kernel"
7. "openat is taking milliseconds for PID 4213, why?"
8. "the pod is CPU-starved even though usage is low — run-queue latency?"
9. "heavy page-fault / direct reclaim, show memory pressure"
10. "disk writes are slow, measure block I/O latency"
11. "softirqs are eating a core, which vector?"
12. "attach a kprobe to do_sys_openat2 and show the return codes"
13. "put a uprobe on libssl SSL_read for this PID"
14. "what kernel symbols starting with tcp_ can I attach to?"
15. "trace the execve syscalls this shell spawns"
16. "what is PID 9931 actually doing in the kernel right now?"

## should NOT trigger
17. "rename this variable across the repo" (code edit)
18. "explain what a mutex is" (concept, no live process)
19. "write unit tests for my parser" (authoring)
20. "why won't my Dockerfile build?" (build-time, no runtime trace)
21. "review this PR for style" (static review)
22. "what's the git blame on this line?" (VCS)
23. "design a REST API for users" (design)
24. "profile my GPU kernel VRAM residency" (-> mep-gpu-debug skill, not this one)

# PASS = each SHOULD maps to a capability in the decision map; each should-NOT is declined
# or routed elsewhere. #24 is the deliberate boundary with mep-gpu-debug.
