#!/bin/bash
# trace_malloc overhead benchmark
# Compares baseline vs gadget-attached execution time
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${1:-$SCRIPT_DIR/results}"
RUNS="${2:-10}"

mkdir -p "$RESULTS_DIR"

echo "========================================="
echo "  trace_malloc overhead benchmark"
echo "  Runs: $RUNS"
echo "========================================="

# Compile benchmark binaries
C_BIN="$RESULTS_DIR/bench_alloc"
CPP_BIN="$RESULTS_DIR/bench_cpp"

gcc -O2 -o "$C_BIN" "$SCRIPT_DIR/bench_alloc.c"
g++ -O2 -o "$CPP_BIN" "$SCRIPT_DIR/bench_cpp.cpp"

calc_avg() {
    awk '{ sum += $1; n++ } END { if (n>0) printf "%.4f", sum/n; else printf "N/A" }' "$1"
}

calc_overhead() {
    awk "BEGIN { if ($1 > 0) printf \"%.1f%%\", (($2 - $1) / $1) * 100; else print \"N/A\" }"
}

for lang in c cpp; do
    if [ "$lang" = "c" ]; then BIN="$C_BIN"; else BIN="$CPP_BIN"; fi
    echo ""
    echo "=== $lang benchmark ==="

    # 1. Baseline
    echo "--- Baseline ($RUNS runs) ---"
    > "$RESULTS_DIR/${lang}_baseline.txt"
    for i in $(seq 1 "$RUNS"); do
        /usr/bin/time -f "%e" "$BIN" > /dev/null 2>> "$RESULTS_DIR/${lang}_baseline.txt"
    done
    BASE_AVG=$(calc_avg "$RESULTS_DIR/${lang}_baseline.txt")
    echo "  Average: ${BASE_AVG}s"

    # 2. Under trace_malloc gadget
    echo "--- Under trace_malloc ($RUNS runs) ---"
    > "$RESULTS_DIR/${lang}_gadget.txt"
    for i in $(seq 1 "$RUNS"); do
        sudo ig run trace_malloc:latest --host --verify-image=false \
            --timeout 30 -o json > /dev/null 2>&1 &
        IG_PID=$!
        sleep 0.5
        /usr/bin/time -f "%e" "$BIN" > /dev/null 2>> "$RESULTS_DIR/${lang}_gadget.txt"
        sudo kill $IG_PID 2>/dev/null || true
        wait $IG_PID 2>/dev/null || true
    done
    IG_AVG=$(calc_avg "$RESULTS_DIR/${lang}_gadget.txt")
    echo "  Average: ${IG_AVG}s"

    # 3. Under trace_malloc with stacks disabled
    echo "--- No stacks ($RUNS runs) ---"
    > "$RESULTS_DIR/${lang}_nostacks.txt"
    for i in $(seq 1 "$RUNS"); do
        sudo ig run trace_malloc:latest --host --verify-image=false \
            --timeout 30 --ebpf.capture-stacks=false -o json > /dev/null 2>&1 &
        IG_PID=$!
        sleep 0.5
        /usr/bin/time -f "%e" "$BIN" > /dev/null 2>> "$RESULTS_DIR/${lang}_nostacks.txt"
        sudo kill $IG_PID 2>/dev/null || true
        wait $IG_PID 2>/dev/null || true
    done
    NS_AVG=$(calc_avg "$RESULTS_DIR/${lang}_nostacks.txt")
    echo "  Average: ${NS_AVG}s"

    # Summary
    OH_GADGET=$(calc_overhead "$BASE_AVG" "$IG_AVG")
    OH_NOSTACKS=$(calc_overhead "$BASE_AVG" "$NS_AVG")

    {
        echo "=== $lang overhead benchmark ==="
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Runs: $RUNS"
        echo ""
        echo "Baseline avg:     ${BASE_AVG}s"
        echo "Gadget avg:       ${IG_AVG}s  (overhead: $OH_GADGET)"
        echo "No-stacks avg:    ${NS_AVG}s  (overhead: $OH_NOSTACKS)"
    } > "$RESULTS_DIR/${lang}_overhead_report.txt"

    echo "  Overhead (gadget):    $OH_GADGET"
    echo "  Overhead (no-stacks): $OH_NOSTACKS"
done

echo ""
echo "========================================="
echo "  Results in: $RESULTS_DIR/"
echo "========================================="
