#!/bin/bash
set -euo pipefail

# trace-malloc comprehensive test runner v2
# Languages: C, C++, Rust, .NET (C#)

BINDIR=/root/trace-malloc-v2/bin
RESDIR=/root/trace-malloc-v2/results
TIMEOUT=30
CONVERTER=/root/inspektor-gadget-public/gadgets/trace_malloc/test/comprehensive/scripts/convert_trace_malloc_to_heaptrack.py

run_trace_malloc() {
    local lang=$1
    local bin=$2
    local outdir=$3
    local procname=$4

    echo ""
    echo "================================================================"
    echo "=== Running trace-malloc on $lang (proc=$procname) ==="
    echo "================================================================"
    mkdir -p "$outdir"

    # Start ig in background
    ig run trace_malloc:latest --host --verify-image=false \
        --timeout "$TIMEOUT" -o json > "$outdir/trace_malloc_raw.json" 2>/dev/null &
    local ig_pid=$!

    # Wait for ig to initialize
    sleep 3

    # Run test binary
    echo "  Running: $bin"
    "$bin" > "$outdir/test_stdout.txt" 2>&1 || true

    # Let remaining events flush
    sleep 2

    # Kill ig
    kill $ig_pid 2>/dev/null || true
    wait $ig_pid 2>/dev/null || true

    # Filter events by process name
    python3 -c "
import json, sys
for line in open('$outdir/trace_malloc_raw.json'):
    line = line.strip()
    if not line: continue
    try:
        ev = json.loads(line)
        comm = ev.get('proc', {}).get('comm', '')
        if comm == '$procname':
            print(line)
    except: pass
" > "$outdir/trace_malloc_output.json"

    local total=$(wc -l < "$outdir/trace_malloc_raw.json" 2>/dev/null || echo 0)
    local filtered=$(wc -l < "$outdir/trace_malloc_output.json" 2>/dev/null || echo 0)
    echo "  Total events: $total, Filtered ($procname): $filtered"

    # Operation counts
    python3 -c "
import json, collections
ops = collections.Counter()
sizes = []
for line in open('$outdir/trace_malloc_output.json'):
    try:
        ev = json.loads(line.strip())
        op = ev.get('operation', '?')
        ops[op] += 1
        s = ev.get('size', 0)
        if s > 0: sizes.append(s)
    except: pass
print('  Operations:')
for op, cnt in sorted(ops.items()):
    print(f'    {op}: {cnt}')
if sizes:
    print(f'  Size range: {min(sizes)} - {max(sizes)} bytes')
    print(f'  Total allocated: {sum(sizes)} bytes')
"

    # Convert to heaptrack format
    echo "  Converting to heaptrack format..."
    python3 "$CONVERTER" -i "$outdir/trace_malloc_output.json" -o "$outdir/converted.heaptrack" 2>&1

    # Validate with heaptrack_print
    echo "  Validating with heaptrack_print..."
    heaptrack_print "$outdir/converted.heaptrack" > "$outdir/heaptrack_print_output.txt" 2>&1 || true
    local hp_exit=$?
    if [ -s "$outdir/heaptrack_print_output.txt" ]; then
        echo "  heaptrack_print output (first 20 lines):"
        head -20 "$outdir/heaptrack_print_output.txt" | sed 's/^/    /'
    fi
}

echo "============================================"
echo "trace-malloc comprehensive tests v2"
echo "Languages: C, C++, Rust, .NET (C#)"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================"

# C test
run_trace_malloc "C" "$BINDIR/test_c_allocs" "$RESDIR/c" "test_c_allocs"

# C++ test (comm truncated to 15 chars: "test_cpp_allocs")
run_trace_malloc "C++" "$BINDIR/test_cpp_allocs" "$RESDIR/cpp" "test_cpp_allocs"

# Rust test (comm truncated to 15 chars: "test_rust_alloc")
run_trace_malloc "Rust" "$BINDIR/test_rust_allocs" "$RESDIR/rust" "test_rust_alloc"

# .NET test (comm is truncated to 15 chars: "TestDotnetAlloc")
run_trace_malloc ".NET" "$BINDIR/TestDotnetAllocs" "$RESDIR/dotnet" "TestDotnetAlloc"

echo ""
echo "============================================"
echo "=== Summary ==="
echo "============================================"
for lang in c cpp rust dotnet; do
    f="$RESDIR/$lang/trace_malloc_output.json"
    count=$(wc -l < "$f" 2>/dev/null || echo 0)
    hf="$RESDIR/$lang/converted.heaptrack"
    hcount=$(wc -l < "$hf" 2>/dev/null || echo 0)
    echo "  $lang: $count events -> $hcount heaptrack lines"
done

echo ""
echo "Tests complete!"
