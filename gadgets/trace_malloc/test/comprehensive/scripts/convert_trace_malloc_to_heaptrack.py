#!/usr/bin/env python3
"""
convert_trace_malloc_to_heaptrack.py - Convert trace-malloc JSON output to heaptrack format.

Reads JSON lines (one event per line) from trace-malloc gadget output,
and produces a heaptrack-compatible data file that can be opened by
heaptrack_print or heaptrack_gui.

Usage:
    cat trace_malloc_output.json | python3 convert_trace_malloc_to_heaptrack.py > output.heaptrack
    python3 convert_trace_malloc_to_heaptrack.py -i input.json -o output.heaptrack

Heaptrack data format (interpreted):
    v <heaptrack_version> <file_format_version>
    X <executable_name>
    I <page_size> <total_pages>
    s <len> <string>                    # string table entry (format v3+)
    i <ip> <module_index> [<func> <file> <line>]*  # instruction pointer
    t <ip_index> <parent_trace_index>   # trace node
    a <size> <trace_index>              # allocation info
    + <alloc_info_index>                # allocation event
    - <alloc_info_index>                # deallocation event
    c <timestamp>                       # timestamp (monotonic ns)
    R <rss_bytes>                       # RSS at this point
    # comment
"""

import sys
import json
import argparse
from collections import OrderedDict

HEAPTRACK_VERSION = 0x010500  # pretend 1.5.0
FILE_FORMAT_VERSION = 3       # v3 = sized strings


def parse_args():
    parser = argparse.ArgumentParser(
        description='Convert trace-malloc JSON to heaptrack format')
    parser.add_argument('-i', '--input', default='-',
                        help='Input JSON file (default: stdin)')
    parser.add_argument('-o', '--output', default='-',
                        help='Output heaptrack file (default: stdout)')
    return parser.parse_args()


# Map trace-malloc operation names to categories
ALLOC_OPS = {
    'malloc', 'calloc', 'realloc', 'mmap', 'posix_memalign',
    'aligned_alloc', 'valloc', 'memalign', 'pvalloc',
    'op_new', 'op_new_array', 'reallocarray'
}
FREE_OPS = {'free', 'munmap', 'op_delete', 'op_delete_array', 'realloc_free'}


def main():
    args = parse_args()

    if args.input == '-':
        infile = sys.stdin
    else:
        infile = open(args.input, 'r')

    if args.output == '-':
        outfile = sys.stdout
    else:
        outfile = open(args.output, 'w')

    events = []
    for line in infile:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            events.append(ev)
        except json.JSONDecodeError:
            continue

    if not events:
        sys.stderr.write("No events parsed from input.\n")
        sys.exit(1)

    # Determine executable name from first event
    exe_name = "unknown"
    for ev in events:
        proc = ev.get('proc', {})
        comm = proc.get('comm', '')
        if comm:
            exe_name = comm
            break

    # String table
    strings = OrderedDict()  # string -> 1-based index

    def get_string_index(s):
        if s not in strings:
            strings[s] = len(strings) + 1
        return strings[s]

    # Instruction pointer table: ip_hex -> (ip_index, module_str_index)
    ip_table = OrderedDict()  # ip_key -> 1-based index

    def get_ip_index(ip_hex, module=""):
        key = ip_hex
        if key not in ip_table:
            mod_idx = get_string_index(module) if module else 0
            ip_table[key] = (len(ip_table) + 1, ip_hex, mod_idx)
        return ip_table[key][0]

    # Trace table: (ip_index, parent_trace_index) -> trace_index
    trace_list = []  # list of (ip_index, parent_index)
    trace_map = {}   # tuple(stack_ips) -> trace_index

    def get_trace_index(stack_frames):
        """Build trace chain from stack frames (top-to-bottom).
        Returns 1-based trace index."""
        if not stack_frames:
            # Create a single dummy trace
            dummy_ip = get_ip_index("0", "unknown")
            key = (dummy_ip,)
            if key not in trace_map:
                trace_list.append((dummy_ip, 0))
                trace_map[key] = len(trace_list)
            return trace_map[key]

        # stack_frames: bottom-of-stack first for heaptrack
        # trace is built: leaf -> parent -> grandparent
        # We interpret ustack as leaf-first (top of stack first)
        parent_idx = 0
        chain_key = []
        for frame in reversed(stack_frames):
            ip_hex = frame if isinstance(frame, str) else hex(frame)
            ip_idx = get_ip_index(ip_hex, "")
            chain_key.append(ip_idx)
            ckey = tuple(chain_key)
            if ckey not in trace_map:
                trace_list.append((ip_idx, parent_idx))
                trace_map[ckey] = len(trace_list)
            parent_idx = trace_map[ckey]

        return parent_idx

    # Allocation info table: (size, trace_index) -> alloc_info_index (0-based)
    alloc_info_list = []  # list of (size, trace_index)
    alloc_info_map = {}

    def get_alloc_info_index(size, trace_idx):
        key = (size, trace_idx)
        if key not in alloc_info_map:
            alloc_info_map[key] = len(alloc_info_list)
            alloc_info_list.append(key)
        return alloc_info_map[key]

    # Parse all events and build tables
    parsed_events = []  # (timestamp_ns, is_alloc, alloc_info_index, addr)
    # Track addr -> alloc_info_index for free matching
    addr_to_alloc = {}

    for ev in events:
        op = ev.get('operation', ev.get('operation_raw', ''))
        addr = ev.get('addr', 0)
        size = ev.get('size', 0)
        ts = ev.get('timestamp_raw', ev.get('timestamp', 0))

        # Parse stack if available
        ustack = ev.get('ustack', {})
        stack_frames = []
        if isinstance(ustack, dict):
            addrs = ustack.get('addresses', ustack.get('addrs', []))
            if addrs:
                stack_frames = addrs
        elif isinstance(ustack, list):
            stack_frames = ustack

        trace_idx = get_trace_index(stack_frames)

        if op in ALLOC_OPS:
            ai_idx = get_alloc_info_index(size, trace_idx)
            parsed_events.append((ts, True, ai_idx, addr))
            if addr:
                addr_to_alloc[addr] = ai_idx
        elif op in FREE_OPS:
            ai_idx = addr_to_alloc.get(addr, None)
            if ai_idx is not None:
                parsed_events.append((ts, False, ai_idx, addr))
                del addr_to_alloc[addr]
            else:
                # Free without known alloc — create dummy alloc info
                ai_idx = get_alloc_info_index(0, trace_idx)
                parsed_events.append((ts, False, ai_idx, addr))

    # Sort by timestamp
    parsed_events.sort(key=lambda x: x[0])

    # Write heaptrack format
    out = outfile

    # Version line
    out.write(f"v {HEAPTRACK_VERSION:x} {FILE_FORMAT_VERSION:x}\n")
    # Executable
    out.write(f"X {exe_name}\n")
    # System info: page size and pages
    out.write(f"I 1000 100000\n")

    # String table (v3 format: "s <hex_len> <string>")
    for s, idx in strings.items():
        out.write(f"s {len(s):x} {s}\n")

    # Instruction pointers
    for key, (idx, ip_hex, mod_idx) in ip_table.items():
        # Format: i <ip_hex> <module_index>
        ip_val = ip_hex
        if isinstance(ip_val, str) and ip_val.startswith('0x'):
            ip_val = ip_val[2:]
        out.write(f"i {ip_val} {mod_idx:x}\n")

    # Traces
    for ip_idx, parent_idx in trace_list:
        out.write(f"t {ip_idx:x} {parent_idx:x}\n")

    # Allocation infos
    for size, trace_idx in alloc_info_list:
        out.write(f"a {size:x} {trace_idx:x}\n")

    # Events with timestamps
    base_ts = parsed_events[0][0] if parsed_events else 0
    for ts, is_alloc, ai_idx, addr in parsed_events:
        elapsed = ts - base_ts if ts >= base_ts else 0
        out.write(f"c {elapsed:x}\n")
        if is_alloc:
            out.write(f"+ {ai_idx:x}\n")
        else:
            out.write(f"- {ai_idx:x}\n")

    out.write(f"# generated by trace-malloc to heaptrack converter\n")

    if args.input != '-':
        infile.close()
    if args.output != '-':
        outfile.close()

    sys.stderr.write(f"Conversion complete: {len(parsed_events)} events, "
                     f"{len(strings)} strings, {len(ip_table)} IPs, "
                     f"{len(trace_list)} traces, {len(alloc_info_list)} alloc infos\n")


if __name__ == '__main__':
    main()
