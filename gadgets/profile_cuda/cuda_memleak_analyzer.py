#!/usr/bin/env python3
"""
CUDA Memory Leak Analyzer for Inspektor Gadget VRAM Detection

Reads JSON output from IG's profile_cuda gadget (with VRAM detection patches)
and produces a human-readable report of memory issues found.

Detection types analyzed:
  - leaked_allocs:        Used allocations that were never freed
  - unused_allocs:        Allocated and freed but never accessed
  - exception_path_allocs: Neither used nor freed (error-path allocations)
  - fragmentation_events:  Failed allocations suggesting VRAM fragmentation

Usage:
  ig run --verify-image=false <image> --host -o json > output.json
  python3 cuda_memleak_analyzer.py output.json
  # or: cat output.json | python3 cuda_memleak_analyzer.py

Exit codes:
  0 = no issues found
  1 = memory issues detected
"""

import json
import sys
import os
from collections import defaultdict


# ─── Classification ──────────────────────────────────────────────────────────

def classify_entry(entry):
    """Classify a single JSON entry into a detection type based on its fields."""
    keys = set(entry.keys()) - {"k8s", "runtime", "proc", "ptr_id"}

    # fragmentation_events: have requested_size + error_code
    if "requested_size" in keys and "error_code" in keys:
        return "fragmentation_events"

    # Profile samples (original gadget data) — skip
    if "count" in keys and "stack_id_key" in keys:
        return None

    # leaked_allocs: have both alloc_ts and first_use_ts (used but not freed)
    if "alloc_ts" in keys and "first_use_ts" in keys and "devptr" in keys:
        return "leaked_allocs"

    # exception_path_allocs: have alloc_ts but NO first_use_ts, have pid
    # (allocated, never used, never freed)
    if "alloc_ts" in keys and "first_use_ts" not in keys and "devptr" in keys and "pid" in keys:
        return "exception_path_allocs"

    # unused_allocs: have devptr + size but no alloc_ts
    # (allocated, never used, then freed)
    if "devptr" in keys and "size" in keys and "alloc_ts" not in keys:
        return "unused_allocs"

    return None


def parse_ig_output(source):
    """Parse IG JSON output from file or stdin. Returns classified detections."""
    detections = defaultdict(list)
    seen_ptrs = defaultdict(set)  # dedup by ptr_id/devptr per type
    line_count = 0
    parse_errors = 0

    for line in source:
        line = line.strip()
        if not line or line == "[]":
            continue
        line_count += 1

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        if not isinstance(data, list):
            data = [data]

        for entry in data:
            if not isinstance(entry, dict):
                continue

            dtype = classify_entry(entry)
            if dtype is None:
                continue

            # Dedup by pointer ID
            ptr = entry.get("ptr_id", entry.get("devptr", id(entry)))
            if ptr in seen_ptrs[dtype]:
                continue
            seen_ptrs[dtype].add(ptr)
            detections[dtype].append(entry)

    return detections, line_count, parse_errors


# ─── Formatting helpers ──────────────────────────────────────────────────────

def fmt_bytes(n):
    """Format byte count as human-readable string."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    else:
        return f"{n / (1024 * 1024 * 1024):.2f} GB"


def fmt_ptr(val):
    """Format a device pointer as hex."""
    if isinstance(val, int):
        return f"0x{val:x}"
    return str(val)


def get_proc_name(entry):
    """Extract process name from entry."""
    proc = entry.get("proc", {})
    return proc.get("comm", "unknown")


def get_pid(entry):
    """Extract PID from entry."""
    if "pid" in entry:
        return entry["pid"]
    proc = entry.get("proc", {})
    return proc.get("pid", 0)


def severity_for(detections):
    """Determine overall severity: CRITICAL / WARNING / INFO / CLEAN."""
    leaked = detections.get("leaked_allocs", [])
    exception = detections.get("exception_path_allocs", [])
    frag = detections.get("fragmentation_events", [])
    unused = detections.get("unused_allocs", [])

    leaked_bytes = sum(e.get("size", 0) for e in leaked)
    exception_bytes = sum(e.get("size", 0) for e in exception)

    # Critical: large leaks (>100MB) or fragmentation events
    if leaked_bytes > 100 * 1024 * 1024 or len(frag) > 0:
        return "CRITICAL"
    # Warning: any leaks or exception-path allocs
    if len(leaked) > 0 or exception_bytes > 10 * 1024 * 1024:
        return "WARNING"
    # Info: only unused allocs
    if len(unused) > 0 or len(exception) > 0:
        return "INFO"
    return "CLEAN"


# ─── Report sections ─────────────────────────────────────────────────────────

def print_header():
    print("=" * 72)
    print("  CUDA VRAM Memory Leak Analysis Report")
    print("  Inspektor Gadget — profile_cuda with VRAM detection")
    print("=" * 72)
    print()


def print_summary(detections):
    leaked = detections.get("leaked_allocs", [])
    unused = detections.get("unused_allocs", [])
    exception = detections.get("exception_path_allocs", [])
    frag = detections.get("fragmentation_events", [])

    leaked_bytes = sum(e.get("size", 0) for e in leaked)
    unused_bytes = sum(e.get("size", 0) for e in unused)
    exception_bytes = sum(e.get("size", 0) for e in exception)

    sev = severity_for(detections)
    total_issues = len(leaked) + len(unused) + len(exception) + len(frag)

    print(f"  SUMMARY")
    print(f"  {'─' * 66}")
    print(f"  Severity:              {sev}")
    print(f"  Total issues:          {total_issues}")
    print()
    print(f"  Leaked allocations:    {len(leaked):>4}  ({fmt_bytes(leaked_bytes)})")
    print(f"  Unused allocations:    {len(unused):>4}  ({fmt_bytes(unused_bytes)})")
    print(f"  Exception-path allocs: {len(exception):>4}  ({fmt_bytes(exception_bytes)})")
    print(f"  Fragmentation events:  {len(frag):>4}")
    print()


def print_leaked_details(entries, max_show=15):
    if not entries:
        return

    print("─" * 72)
    print("  LEAKED ALLOCATIONS (used but never freed)")
    print("─" * 72)

    # Sort by size descending
    sorted_entries = sorted(entries, key=lambda e: e.get("size", 0), reverse=True)

    for i, e in enumerate(sorted_entries[:max_show]):
        size = e.get("size", 0)
        devptr = e.get("devptr", 0)
        proc = get_proc_name(e)
        pid = get_pid(e)
        print(f"  [{i+1:>3}] {fmt_bytes(size):>10}  ptr={fmt_ptr(devptr)}  "
              f"proc={proc} (pid={pid})")

    if len(entries) > max_show:
        remaining = len(entries) - max_show
        remaining_bytes = sum(e.get("size", 0) for e in sorted_entries[max_show:])
        print(f"  ... and {remaining} more ({fmt_bytes(remaining_bytes)} total)")
    print()


def print_unused_details(entries, max_show=10):
    if not entries:
        return

    print("─" * 72)
    print("  UNUSED ALLOCATIONS (allocated, freed, but never accessed)")
    print("─" * 72)

    sorted_entries = sorted(entries, key=lambda e: e.get("size", 0), reverse=True)

    for i, e in enumerate(sorted_entries[:max_show]):
        size = e.get("size", 0)
        devptr = e.get("devptr", 0)
        proc = get_proc_name(e)
        print(f"  [{i+1:>3}] {fmt_bytes(size):>10}  ptr={fmt_ptr(devptr)}  proc={proc}")

    if len(entries) > max_show:
        remaining = len(entries) - max_show
        remaining_bytes = sum(e.get("size", 0) for e in sorted_entries[max_show:])
        print(f"  ... and {remaining} more ({fmt_bytes(remaining_bytes)} total)")
    print()


def print_exception_details(entries, max_show=10):
    if not entries:
        return

    print("─" * 72)
    print("  EXCEPTION-PATH ALLOCATIONS (never used, never freed)")
    print("─" * 72)

    sorted_entries = sorted(entries, key=lambda e: e.get("size", 0), reverse=True)

    for i, e in enumerate(sorted_entries[:max_show]):
        size = e.get("size", 0)
        devptr = e.get("devptr", 0)
        proc = get_proc_name(e)
        pid = get_pid(e)
        print(f"  [{i+1:>3}] {fmt_bytes(size):>10}  ptr={fmt_ptr(devptr)}  "
              f"proc={proc} (pid={pid})")

    if len(entries) > max_show:
        remaining = len(entries) - max_show
        remaining_bytes = sum(e.get("size", 0) for e in sorted_entries[max_show:])
        print(f"  ... and {remaining} more ({fmt_bytes(remaining_bytes)} total)")
    print()


def print_fragmentation_details(entries, max_show=10):
    if not entries:
        return

    print("─" * 72)
    print("  FRAGMENTATION EVENTS (allocation failures)")
    print("─" * 72)

    for i, e in enumerate(entries[:max_show]):
        req = e.get("requested_size", 0)
        err = e.get("error_code", 0)
        net = e.get("net_allocated", 0)
        total_alloc = e.get("total_allocated", 0)
        total_freed = e.get("total_freed", 0)
        proc = get_proc_name(e)
        print(f"  [{i+1:>3}] requested={fmt_bytes(req)}  error={err}  "
              f"net_alloc={fmt_bytes(net)}")
        print(f"        total_alloc={fmt_bytes(total_alloc)}  "
              f"total_freed={fmt_bytes(total_freed)}  proc={proc}")

    if len(entries) > max_show:
        print(f"  ... and {len(entries) - max_show} more events")
    print()


def print_recommendations(detections):
    leaked = detections.get("leaked_allocs", [])
    unused = detections.get("unused_allocs", [])
    exception = detections.get("exception_path_allocs", [])
    frag = detections.get("fragmentation_events", [])

    sev = severity_for(detections)
    if sev == "CLEAN":
        print("  No issues found. VRAM usage looks healthy.")
        return

    print("─" * 72)
    print("  RECOMMENDATIONS")
    print("─" * 72)

    if leaked:
        leaked_bytes = sum(e.get("size", 0) for e in leaked)
        print(f"  • {len(leaked)} leaked allocation(s) totaling {fmt_bytes(leaked_bytes)}")
        print(f"    These allocations were used but never freed. Check that every")
        print(f"    cuMemAlloc is paired with cuMemFree on all code paths.")

        # Group by process
        by_proc = defaultdict(list)
        for e in leaked:
            by_proc[get_proc_name(e)].append(e)
        if len(by_proc) > 1:
            print(f"    Affected processes: {', '.join(sorted(by_proc.keys()))}")
        print()

    if unused:
        unused_bytes = sum(e.get("size", 0) for e in unused)
        print(f"  • {len(unused)} unused allocation(s) totaling {fmt_bytes(unused_bytes)}")
        print(f"    Memory was allocated and freed without ever being accessed.")
        print(f"    This wastes VRAM bandwidth and may indicate over-provisioning")
        print(f"    or defensive pre-allocation that is never needed.")
        print()

    if exception:
        exc_bytes = sum(e.get("size", 0) for e in exception)
        print(f"  • {len(exception)} exception-path allocation(s) totaling {fmt_bytes(exc_bytes)}")
        print(f"    These allocations were neither used nor freed — likely allocated")
        print(f"    in error-handling code paths and leaked on exit. Review error")
        print(f"    paths for missing cuMemFree calls.")
        print()

    if frag:
        print(f"  • {len(frag)} fragmentation event(s) detected")
        print(f"    Allocation failures despite available free VRAM suggest memory")
        print(f"    fragmentation. Consider using memory pools (cuMemPool) or")
        print(f"    allocating larger blocks upfront and sub-allocating.")
        print()


def print_footer(detections, line_count, parse_errors):
    sev = severity_for(detections)
    total = sum(len(v) for v in detections.values())

    print("=" * 72)
    if sev == "CLEAN":
        print("  RESULT: CLEAN — no VRAM issues detected")
    else:
        print(f"  RESULT: {sev} — {total} issue(s) found")
    print(f"  Lines parsed: {line_count}" +
          (f" ({parse_errors} parse errors)" if parse_errors else ""))
    print("=" * 72)


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    # Determine input source
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        filepath = sys.argv[1]
        if not os.path.exists(filepath):
            print(f"Error: file not found: {filepath}", file=sys.stderr)
            sys.exit(2)
        source = open(filepath, "r")
    else:
        if sys.stdin.isatty():
            print("Usage: python3 cuda_memleak_analyzer.py <ig-output.json>",
                  file=sys.stderr)
            print("       cat ig-output.json | python3 cuda_memleak_analyzer.py",
                  file=sys.stderr)
            sys.exit(2)
        source = sys.stdin

    try:
        detections, line_count, parse_errors = parse_ig_output(source)
    finally:
        if source is not sys.stdin:
            source.close()

    if line_count == 0:
        print("Error: no data found in input", file=sys.stderr)
        sys.exit(2)

    # Generate report
    print_header()
    print_summary(detections)
    print_leaked_details(detections.get("leaked_allocs", []))
    print_unused_details(detections.get("unused_allocs", []))
    print_exception_details(detections.get("exception_path_allocs", []))
    print_fragmentation_details(detections.get("fragmentation_events", []))
    print_recommendations(detections)
    print_footer(detections, line_count, parse_errors)

    # Exit code: 0 = clean, 1 = issues found
    total_issues = sum(len(v) for v in detections.values())
    sys.exit(1 if total_issues > 0 else 0)


if __name__ == "__main__":
    main()
