#!/usr/bin/env python3
"""Validate terminal IG output and bounded Copilot workload integrity."""

import argparse
import json
from pathlib import Path


FAILURE_KEYS = {
    "reserve_failures",
    "pending_update_failures",
    "unmatched_returns",
    "marker_reserve_failures",
    "state_insert_failures",
    "exit_reserve_failures",
}


def rows(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if isinstance(payload, list):
                yield from payload
            elif isinstance(payload, dict):
                yield payload
            else:
                raise SystemExit(f"{path}:{line_number}: unexpected JSON value")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ig-output", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--preset", required=True)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--minimum-turns", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    workload = list(rows(args.workload))
    workload_starts = [
        row.get("started_ns")
        for row in workload
        if isinstance(row.get("started_ns"), int)
    ]
    workload_wall_starts = [
        row.get("wall_started_ns")
        for row in workload
        if isinstance(row.get("wall_started_ns"), int)
    ]
    measurement_start_ns = min(workload_starts) if workload_starts else None
    measurement_wall_start_ns = (
        min(workload_wall_starts) if workload_wall_starts else None
    )

    effective_configs = 0
    first_decode_candidates = 0
    decode_candidates = 0
    analyzer_health = 0
    pre_measurement_analyzer_health = 0
    unexpected_cuda_sources = set()
    failures = []
    for row in rows(args.ig_output):
        row_type = row.get("type")
        timestamp_ns = row.get("timestamp_ns")
        timestamp_raw = row.get("timestamp_raw")
        in_measurement = (
            (
                isinstance(timestamp_ns, int)
                and (
                    measurement_start_ns is None
                    or timestamp_ns >= measurement_start_ns
                )
            )
            or (
                isinstance(timestamp_raw, int)
                and (
                    measurement_wall_start_ns is None
                    or timestamp_raw >= measurement_wall_start_ns
                )
            )
            or (
                not isinstance(timestamp_ns, int)
                and not isinstance(timestamp_raw, int)
            )
        )
        if row_type == "effective_config":
            effective_configs += 1
            if row.get("preset") != args.preset:
                failures.append(
                    f"unexpected preset: {row.get('preset')!r}"
                )
        elif row_type == "first_decode_candidate" and in_measurement:
            first_decode_candidates += 1
        elif row_type == "decode_candidate" and in_measurement:
            decode_candidates += 1
        elif row_type == "analyzer_health":
            if in_measurement:
                analyzer_health += 1
            else:
                pre_measurement_analyzer_health += 1
        if row.get("operation") and row.get("proc"):
            container_id = (row.get("runtime") or {}).get("containerId")
            if container_id != args.container_id:
                unexpected_cuda_sources.add(container_id or "host")
        for key in FAILURE_KEYS:
            value = row.get(key)
            if isinstance(value, (int, float)) and value != 0:
                failures.append(f"{key}={value}")

    failed_turns = [
        row
        for row in workload
        if row.get("returncode") != 0 or row.get("tool_activity") is not False
    ]
    if effective_configs != 1:
        failures.append(f"effective_config_count={effective_configs}")
    if first_decode_candidates == 0:
        failures.append("no first-decode candidates")
    if decode_candidates == 0:
        failures.append("no decode candidates")
    if analyzer_health:
        failures.append(f"analyzer_health_events={analyzer_health}")
    if len(workload) < args.minimum_turns:
        failures.append(f"completed_turns={len(workload)}")
    if failed_turns:
        failures.append(f"failed_or_tool_turns={len(failed_turns)}")
    if unexpected_cuda_sources:
        failures.append(
            "unexpected_cuda_sources="
            + ",".join(sorted(unexpected_cuda_sources))
        )

    report = {
        "schema": 2,
        "measurement_start_ns": measurement_start_ns,
        "measurement_wall_start_ns": measurement_wall_start_ns,
        "effective_config_count": effective_configs,
        "first_decode_candidates": first_decode_candidates,
        "decode_candidates": decode_candidates,
        "analyzer_health_events": analyzer_health,
        "pre_measurement_analyzer_health_events": pre_measurement_analyzer_health,
        "unexpected_cuda_sources": sorted(unexpected_cuda_sources),
        "completed_turns": len(workload),
        "failures": sorted(set(failures)),
    }
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True))
    if failures:
        raise SystemExit("run integrity validation failed")


if __name__ == "__main__":
    main()
