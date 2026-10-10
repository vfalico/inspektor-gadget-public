#!/usr/bin/env python3
"""Run a bounded, sequential GitHub Copilot CLI workload against local vLLM."""

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path


LARGE_INPUT = (
    "A passive GPU observability pipeline sees CUDA driver calls, kernel launches, "
    "memory copies, synchronization, process identity, and host timestamps. It does "
    "not see prompts, token IDs, scheduler queues, semantic request boundaries, or "
    "whether streamed bytes were useful to a user. A serving runtime separately "
    "reports request timing and token histograms. These clock domains answer "
    "different questions: request time includes queueing and tokenization, while "
    "CUDA activity begins only when GPU work becomes visible. A defensible test pins "
    "versions, model, generation limits, concurrency, host, device, and loss counters."
)

PROMPTS = (
    (
        "short",
        "Answer in plain text without tools. In two sentences, explain why deterministic tests help GPU observability software.",
    ),
    (
        "medium",
        "Answer in plain text without tools. Give three strengths, three limitations, and one safe documentation claim for a passive CUDA observer that estimates first-token and inter-token latency.",
    ),
    (
        "code",
        "Answer in plain text without tools. Return only one Python function, no markdown and no explanation. Compute median absolute error for two equal-length numeric lists in at most 14 lines.",
    ),
    (
        "large_input",
        "Answer in plain text without tools. Read the passage, then return exactly three bullets of at most 12 words each: one strength, one limitation, and one safe claim.\n\n"
        + LARGE_INPUT,
    ),
    (
        "context",
        "Answer in plain text without tools. Based on this continuing session, distinguish CUDA candidate metrics from semantic serving metrics and propose a concise chart caption.",
    ),
    (
        "burst",
        "Answer in plain text without tools. Produce exactly eight numbered recommendations for validating a hook-free GPU inference latency estimator. Keep each under eight words.",
    ),
)

EXCLUDED_TOOLS = (
    "bash",
    "read_bash",
    "stop_bash",
    "list_bash",
    "view",
    "create",
    "edit",
    "fetch_copilot_cli_documentation",
    "skill",
    "sql",
    "session_store_sql",
    "read_agent",
    "list_agents",
    "grep",
    "glob",
    "task",
)


def write_json_line(handle, payload: dict) -> None:
    handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
    handle.flush()


def contains_tool_activity(path: Path) -> bool:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        lowered = line.lower()
        if '"tool_use"' in lowered or '"tool_result"' in lowered:
            return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--session-prefix", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--copilot", default="/usr/bin/copilot")
    parser.add_argument("--segment-turns", type=int, default=4)
    parser.add_argument("--turn-timeout", type=float, default=300)
    parser.add_argument("--minimum-start-window", type=float, default=30)
    parser.add_argument("--max-turns", type=int, default=0)
    args = parser.parse_args()
    if (
        args.duration <= 0
        or args.segment_turns <= 0
        or args.turn_timeout <= 0
        or args.minimum_start_window <= 0
    ):
        raise SystemExit(
            "duration, segment-turns, turn-timeout, and minimum-start-window "
            "must be positive"
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    isolated_home = args.output_dir / "home"
    isolated_home.mkdir()
    deadline = time.monotonic() + args.duration
    ordinal = 0
    with (args.output_dir / "workload.jsonl").open("w", encoding="utf-8") as log:
        while time.monotonic() < deadline:
            if args.max_turns and ordinal >= args.max_turns:
                break
            if deadline - time.monotonic() < args.minimum_start_window:
                break
            segment_index = ordinal // args.segment_turns + 1
            segment_turn = ordinal % args.segment_turns + 1
            kind, base_prompt = PROMPTS[ordinal % len(PROMPTS)]
            ordinal += 1
            marker = f"IGCUDA-{args.session_prefix}-{ordinal:04d}"
            prompt = (
                f"{base_prompt}\n\nContinuity marker: {marker}. "
                "Preserve this exact marker when referring to this chat."
            )
            session_name = f"{args.session_prefix}-s{segment_index:03d}"
            command = [
                args.copilot,
                "--no-custom-instructions",
                "--disable-builtin-mcps",
                "--no-remote",
                "--no-remote-export",
                "--no-auto-update",
                "--no-color",
                "--allow-all-tools",
                "--model",
                "qwen",
                "--stream",
                "on",
                "--output-format",
                "json",
            ]
            command.extend(
                f"--excluded-tools={tool_name}" for tool_name in EXCLUDED_TOOLS
            )
            if segment_turn == 1:
                command.extend(["--name", session_name])
            else:
                command.append(f"--resume={session_name}")
            command.extend(["--prompt", prompt])
            stdout_path = args.output_dir / f"copilot-{ordinal:04d}.jsonl"
            stderr_path = args.output_dir / f"copilot-{ordinal:04d}.err"
            wall_started_ns = time.time_ns()
            started_ns = time.monotonic_ns()
            try:
                with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
                    "w", encoding="utf-8"
                ) as stderr_handle:
                    completed = subprocess.run(
                        command,
                        cwd=args.output_dir,
                        env={
                            "HOME": str(isolated_home),
                            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                            "LANG": os.environ.get("LANG", "C.UTF-8"),
                            "COPILOT_HOME": str(isolated_home / ".copilot"),
                            "COPILOT_PROVIDER_BASE_URL": os.environ[
                                "COPILOT_PROVIDER_BASE_URL"
                            ],
                            "COPILOT_PROVIDER_TYPE": os.environ[
                                "COPILOT_PROVIDER_TYPE"
                            ],
                            "COPILOT_PROVIDER_MODEL_ID": os.environ[
                                "COPILOT_PROVIDER_MODEL_ID"
                            ],
                            "COPILOT_PROVIDER_WIRE_MODEL": os.environ[
                                "COPILOT_PROVIDER_WIRE_MODEL"
                            ],
                            "COPILOT_PROVIDER_MAX_PROMPT_TOKENS": os.environ[
                                "COPILOT_PROVIDER_MAX_PROMPT_TOKENS"
                            ],
                            "COPILOT_PROVIDER_MAX_OUTPUT_TOKENS": os.environ[
                                "COPILOT_PROVIDER_MAX_OUTPUT_TOKENS"
                            ],
                            "COPILOT_MODEL": os.environ["COPILOT_MODEL"],
                            "COPILOT_OFFLINE": os.environ["COPILOT_OFFLINE"],
                        },
                        stdout=stdout_handle,
                        stderr=stderr_handle,
                        timeout=min(args.turn_timeout, max(deadline - time.monotonic(), 1)),
                        check=False,
                    )
                returncode = completed.returncode
                error = None
            except subprocess.TimeoutExpired:
                returncode = 124
                error = "turn_timeout"
            ended_ns = time.monotonic_ns()
            tool_activity = contains_tool_activity(stdout_path)
            record = {
                "schema": 1,
                "ordinal": ordinal,
                "segment_index": segment_index,
                "segment_turn": segment_turn,
                "session_name": session_name,
                "kind": kind,
                "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                "wall_started_ns": wall_started_ns,
                "started_ns": started_ns,
                "ended_ns": ended_ns,
                "returncode": returncode,
                "error": error,
                "tool_activity": tool_activity,
                "stdout": stdout_path.name,
                "stderr": stderr_path.name,
            }
            write_json_line(log, record)
            if returncode != 0:
                raise SystemExit(f"Copilot turn {ordinal} failed: {record}")
            if tool_activity:
                raise SystemExit(f"Copilot turn {ordinal} emitted tool activity")


if __name__ == "__main__":
    main()
