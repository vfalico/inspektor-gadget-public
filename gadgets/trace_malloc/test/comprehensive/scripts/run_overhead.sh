#!/bin/bash
set -euo pipefail

RESDIR=/root/trace-malloc-tests/results/overhead
RUNS=3

mkdir -p "$RESDIR"

cat > "$RESDIR/bench_alloc.c" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define ITERATIONS 500000
int main(void) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        void *p = malloc(256);
        if (!p) return 1;
        *(volatile char*)p = 'x';
        free(p);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("%.6f\n", elapsed);
    return 0;
}
CEOF

gcc -O2 -o "$RESDIR/bench_alloc" "$RESDIR/bench_alloc.c"

echo "=== Overhead Benchmark ==="
echo "Iterations: 500,000 malloc/free pairs"
echo "Runs per mode: $RUNS"
echo ""

# 1. Baseline
echo "--- Baseline ---"
> "$RESDIR/baseline.txt"
for i in $(seq 1 $RUNS); do
    "$RESDIR/bench_alloc" >> "$RESDIR/baseline.txt"
done
BASE_AVG=$(awk '{sum+=$1; n++} END {printf "%.6f", sum/n}' "$RESDIR/baseline.txt")
echo "  Average: ${BASE_AVG}s"

# 2. Under trace_malloc with stacks
echo "--- trace_malloc (with stacks) ---"
> "$RESDIR/gadget.txt"
for i in $(seq 1 $RUNS); do
    ig run trace_malloc:latest --host --verify-image=false --timeout 120 -o json > /dev/null 2>&1 &
    IG_PID=$!
    sleep 2
    "$RESDIR/bench_alloc" >> "$RESDIR/gadget.txt"
    sleep 1
    kill $IG_PID 2>/dev/null || true
    wait $IG_PID 2>/dev/null || true
    sleep 1
done
IG_AVG=$(awk '{sum+=$1; n++} END {printf "%.6f", sum/n}' "$RESDIR/gadget.txt")
echo "  Average: ${IG_AVG}s"

# 3. Under trace_malloc without stacks
echo "--- trace_malloc (no stacks) ---"
> "$RESDIR/nostacks.txt"
for i in $(seq 1 $RUNS); do
    ig run trace_malloc:latest --host --verify-image=false --timeout 120 --ebpf.capture-stacks=false -o json > /dev/null 2>&1 &
    IG_PID=$!
    sleep 2
    "$RESDIR/bench_alloc" >> "$RESDIR/nostacks.txt"
    sleep 1
    kill $IG_PID 2>/dev/null || true
    wait $IG_PID 2>/dev/null || true
    sleep 1
done
NS_AVG=$(awk '{sum+=$1; n++} END {printf "%.6f", sum/n}' "$RESDIR/nostacks.txt")
echo "  Average: ${NS_AVG}s"

# 4. Under heaptrack
echo "--- heaptrack ---"
> "$RESDIR/heaptrack_times.txt"
for i in $(seq 1 $RUNS); do
    heaptrack -o "$RESDIR/ht_tmp_$i" "$RESDIR/bench_alloc" 2>/dev/null >> "$RESDIR/heaptrack_times.txt"
done
HT_AVG=$(awk '{sum+=$1; n++} END {printf "%.6f", sum/n}' "$RESDIR/heaptrack_times.txt")
echo "  Average: ${HT_AVG}s"

# Summary
OH_GADGET=$(python3 -c "print(f'{(($IG_AVG - $BASE_AVG) / $BASE_AVG) * 100:.1f}%')")
OH_NOSTACKS=$(python3 -c "print(f'{(($NS_AVG - $BASE_AVG) / $BASE_AVG) * 100:.1f}%')")
OH_HT=$(python3 -c "print(f'{(($HT_AVG - $BASE_AVG) / $BASE_AVG) * 100:.1f}%')")

echo ""
echo "=== Results ==="
echo "Baseline:               ${BASE_AVG}s"
echo "trace_malloc (stacks):  ${IG_AVG}s  (overhead: $OH_GADGET)"
echo "trace_malloc (no stk):  ${NS_AVG}s  (overhead: $OH_NOSTACKS)"
echo "heaptrack:              ${HT_AVG}s  (overhead: $OH_HT)"

cat > "$RESDIR/overhead_report.txt" << REOF
=== trace_malloc vs heaptrack Overhead Benchmark ===
Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Workload: 500,000 malloc(256)/free() pairs
Runs per mode: $RUNS

Baseline:               ${BASE_AVG}s
trace_malloc (stacks):  ${IG_AVG}s  (overhead: $OH_GADGET)
trace_malloc (no stk):  ${NS_AVG}s  (overhead: $OH_NOSTACKS)
heaptrack:              ${HT_AVG}s  (overhead: $OH_HT)

Raw data:
  baseline:  $(cat $RESDIR/baseline.txt | tr '\n' ' ')
  gadget:    $(cat $RESDIR/gadget.txt | tr '\n' ' ')
  nostacks:  $(cat $RESDIR/nostacks.txt | tr '\n' ' ')
  heaptrack: $(cat $RESDIR/heaptrack_times.txt | tr '\n' ' ')

Notes:
- trace_malloc is eBPF uprobe-based: attaches to all processes system-wide
- heaptrack uses LD_PRELOAD: wraps only the target process
- trace_malloc captures system-wide events including other processes
- heaptrack provides per-process profiling with richer stack info
- trace_malloc overhead scales with system-wide allocation rate
REOF

echo ""
echo "Report saved to: $RESDIR/overhead_report.txt"
