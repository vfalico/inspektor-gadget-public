#!/usr/bin/env python3
"""Collect paired native-vLLM and IG CUDA gadget Prometheus snapshots."""

import argparse
import json
import math
import signal
import subprocess
import threading
import time
import urllib.request
from pathlib import Path


STOP = threading.Event()


def request_stop(_signum, _frame) -> None:
    STOP.set()


def scrape(url: str, timeout: float) -> dict:
    started_ns = time.monotonic_ns()
    payload = {"url": url, "started_ns": started_ns}
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload["status"] = response.status
            payload["metrics"] = response.read().decode("utf-8", "replace")
    except Exception as exc:
        payload["error"] = f"{type(exc).__name__}: {exc}"
    payload["ended_ns"] = time.monotonic_ns()
    payload["midpoint_ns"] = (payload["started_ns"] + payload["ended_ns"]) // 2
    return payload


def gpu_processes(allowed_container_id: str) -> tuple[list[dict], str | None]:
    completed = subprocess.run(
        [
            "nvidia-smi",
            "--query-compute-apps=pid,process_name,used_memory",
            "--format=csv,noheader,nounits",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return [], f"nvidia-smi exited {completed.returncode}: {completed.stderr.strip()}"
    processes = []
    unexpected = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        fields = [field.strip() for field in line.split(",", 2)]
        if len(fields) != 3 or not fields[0].isdigit():
            return processes, f"unexpected nvidia-smi row: {line!r}"
        pid = int(fields[0])
        try:
            cgroup = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
        except OSError as exc:
            return processes, f"cannot inspect GPU process {pid}: {exc}"
        belongs_to_vllm = allowed_container_id in cgroup
        process = {
            "pid": pid,
            "process_name": fields[1],
            "used_memory_mib": fields[2],
            "belongs_to_vllm": belongs_to_vllm,
        }
        processes.append(process)
        if not belongs_to_vllm:
            unexpected.append(process)
    if unexpected:
        return processes, f"unexpected GPU processes: {unexpected}"
    return processes, None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vllm-url", default="http://127.0.0.1:18080/metrics")
    parser.add_argument("--gadget-url", default="http://127.0.0.1:2224/metrics")
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--allowed-container-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.duration <= 0 or args.interval <= 0 or args.timeout <= 0:
        raise SystemExit("duration, interval, and timeout must be positive")

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + args.duration
    boundary = started
    ordinal = 0
    with args.output.open("w", encoding="utf-8") as handle:
        while not STOP.is_set() and boundary <= deadline:
            remaining = boundary - time.monotonic()
            if remaining > 0:
                STOP.wait(remaining)
            if STOP.is_set():
                break
            ordinal += 1
            pair_started_ns = time.monotonic_ns()
            vllm = scrape(args.vllm_url, args.timeout)
            gadget = scrape(args.gadget_url, args.timeout)
            observed_gpu_processes, gpu_process_error = gpu_processes(
                args.allowed_container_id
            )
            pair_ended_ns = time.monotonic_ns()
            payload = {
                "schema": 1,
                "ordinal": ordinal,
                "interval_s": args.interval,
                "wall_ns": time.time_ns(),
                "scheduled_ns": int(boundary * 1_000_000_000),
                "pair_started_ns": pair_started_ns,
                "pair_ended_ns": pair_ended_ns,
                "midpoint_skew_ns": abs(
                    int(vllm["midpoint_ns"]) - int(gadget["midpoint_ns"])
                ),
                "vllm": vllm,
                "gadget": gadget,
                "gpu_processes": observed_gpu_processes,
            }
            if gpu_process_error is not None:
                payload["gpu_process_error"] = gpu_process_error
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
            handle.flush()
            elapsed_intervals = math.floor((time.monotonic() - started) / args.interval)
            boundary = started + max(ordinal, elapsed_intervals + 1) * args.interval


if __name__ == "__main__":
    main()
