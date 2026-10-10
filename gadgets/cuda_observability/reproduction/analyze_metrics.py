#!/usr/bin/env python3
"""Analyze aligned native-vLLM and IG CUDA gadget histogram deltas."""

import argparse
import csv
import html
import json
import math
import re
import statistics
from pathlib import Path


LINE_RE = re.compile(r"^([^\s{]+)(?:\{([^}]*)\})?\s+([^\s]+)$")
ALIASES = {
    "ttft_vllm": {
        "bases": ("vllm:time_to_first_token_seconds",),
        "required_labels": (),
        "scale_ms": 1_000.0,
    },
    "itl_vllm": {
        "bases": ("vllm:inter_token_latency_seconds",),
        "required_labels": (),
        "scale_ms": 1_000.0,
    },
    "ttft_gadget": {
        "bases": (
            "cuda_inference_ttft_candidate_nanoseconds",
            "cuda_inference_ttft_candidate",
        ),
        "required_labels": ('type="first_decode_candidate"',),
        "scale_ms": 1e-6,
    },
    "itl_gadget": {
        "bases": (
            "cuda_inference_decode_interval_candidate_nanoseconds",
            "cuda_inference_decode_interval_candidate",
        ),
        "required_labels": ('type="decode_candidate"',),
        "scale_ms": 1e-6,
    },
}


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc}") from exc
    return rows


def parse_metrics(text: str, source: str) -> dict[str, tuple[float, float]]:
    selected: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = LINE_RE.match(line)
        if not match:
            continue
        name, labels, raw_value = match.groups()
        labels = labels or ""
        for key, contract in ALIASES.items():
            if not key.endswith(source):
                continue
            matched_base = next(
                (
                    base
                    for base in contract["bases"]
                    if name in {f"{base}_sum", f"{base}_count"}
                ),
                None,
            )
            if matched_base is None:
                continue
            if any(label not in labels for label in contract["required_labels"]):
                continue
            field = "sum" if name.endswith("_sum") else "count"
            value = float(raw_value)
            if not math.isfinite(value):
                raise SystemExit(f"non-finite metric {name}")
            target = selected.setdefault(key, {})
            if field in target:
                raise SystemExit(f"duplicate selected series for {name}")
            target[field] = value
    return {
        key: (values["sum"], values["count"])
        for key, values in selected.items()
        if "sum" in values and "count" in values
    }


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def correlation(left: list[float], right: list[float]) -> float | None:
    if len(left) < 2 or len(left) != len(right):
        return None
    left_mean = statistics.fmean(left)
    right_mean = statistics.fmean(right)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    left_energy = sum((value - left_mean) ** 2 for value in left)
    right_energy = sum((value - right_mean) ** 2 for value in right)
    denominator = math.sqrt(left_energy * right_energy)
    return numerator / denominator if denominator else None


def difference_stats(reference: list[float], candidate: list[float]) -> dict:
    errors = [candidate_value - reference_value for reference_value, candidate_value in zip(reference, candidate)]
    absolute = [abs(value) for value in errors]
    return {
        "window_count": len(errors),
        "reference_median_ms": statistics.median(reference) if reference else None,
        "candidate_median_ms": statistics.median(candidate) if candidate else None,
        "median_bias_ms": statistics.median(errors) if errors else None,
        "mean_absolute_error_ms": statistics.fmean(absolute) if absolute else None,
        "median_absolute_error_ms": statistics.median(absolute) if absolute else None,
        "p90_absolute_error_ms": percentile(absolute, 0.9),
        "correlation": correlation(reference, candidate),
    }


def svg_chart(path: Path, title: str, rows: list[dict]) -> None:
    width, height = 1000, 420
    left, right, top, bottom = 80, 40, 50, 90
    values = [
        value
        for row in rows
        for value in (row["reference_ms"], row["candidate_ms"])
    ]
    maximum = max(values) if values else 1.0

    def points(field: str) -> str:
        if len(rows) == 1:
            return f"{left},{height-bottom}"
        return " ".join(
            f"{left + index * (width-left-right)/(len(rows)-1):.2f},"
            f"{top + (maximum-row[field])*(height-top-bottom)/maximum:.2f}"
            for index, row in enumerate(rows)
        )

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">
<rect width="100%" height="100%" fill="white"/>
<text x="{width/2}" y="28" text-anchor="middle" font-size="18">{html.escape(title)}</text>
<line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="#222"/>
<line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="#222"/>
<polyline fill="none" stroke="#2166ac" stroke-width="2" points="{points('reference_ms')}"/>
<polyline fill="none" stroke="#b2182b" stroke-width="2" points="{points('candidate_ms')}"/>
<text x="{width/2}" y="{height-54}" text-anchor="middle" font-size="14">Aligned five-second windows</text>
<line x1="260" y1="{height-28}" x2="300" y2="{height-28}" stroke="#2166ac" stroke-width="3"/>
<text x="310" y="{height-23}" font-size="13">vLLM native</text>
<line x1="540" y1="{height-28}" x2="580" y2="{height-28}" stroke="#b2182b" stroke-width="3"/>
<text x="590" y="{height-23}" font-size="13">IG CUDA gadget candidate</text>
</svg>
"""
    path.write_text(svg, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("samples", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-skew-ms", type=float, default=250.0)
    parser.add_argument("--max-scrape-duration-ms", type=float, default=2_000.0)
    parser.add_argument("--max-interval-drift-ms", type=float, default=1_000.0)
    parser.add_argument("--minimum-itl-count-ratio", type=float, default=0.80)
    parser.add_argument("--maximum-itl-count-ratio", type=float, default=1.20)
    parser.add_argument("--minimum-ttft-windows", type=int, default=1)
    parser.add_argument("--minimum-itl-windows", type=int, default=1)
    args = parser.parse_args()
    rows = load_jsonl(args.samples)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    previous = None
    windows = {"ttft": [], "itl": []}
    rejection_counts = {
        "gpu_process": 0,
        "scrape_error": 0,
        "skew": 0,
        "scrape_duration": 0,
        "interval_drift": 0,
        "missing_series": 0,
        "counter_reset": 0,
        "ttft_count_mismatch": 0,
        "itl_count_ratio": 0,
        "empty_ttft": 0,
        "empty_itl": 0,
    }
    for row in rows:
        if row.get("gpu_process_error"):
            rejection_counts["gpu_process"] += 1
            previous = None
            continue
        if "error" in row.get("vllm", {}) or "error" in row.get("gadget", {}):
            rejection_counts["scrape_error"] += 1
            previous = None
            continue
        if float(row.get("midpoint_skew_ns", 0)) > args.max_skew_ms * 1_000_000:
            rejection_counts["skew"] += 1
            previous = None
            continue
        scrape_duration_ns = max(
            int(row[source]["ended_ns"]) - int(row[source]["started_ns"])
            for source in ("vllm", "gadget")
        )
        if scrape_duration_ns > args.max_scrape_duration_ms * 1_000_000:
            rejection_counts["scrape_duration"] += 1
            previous = None
            continue
        current = {
            **parse_metrics(row["vllm"].get("metrics", ""), "vllm"),
            **parse_metrics(row["gadget"].get("metrics", ""), "gadget"),
        }
        if set(current) != set(ALIASES):
            rejection_counts["missing_series"] += 1
            previous = None
            continue
        if previous is None:
            previous = (row, current)
            continue
        prior_row, prior = previous
        expected_interval_ns = float(row["interval_s"]) * 1_000_000_000
        source_intervals = [
            int(row[source]["midpoint_ns"]) - int(prior_row[source]["midpoint_ns"])
            for source in ("vllm", "gadget")
        ]
        if any(
            abs(interval_ns - expected_interval_ns)
            > args.max_interval_drift_ms * 1_000_000
            for interval_ns in source_intervals
        ):
            rejection_counts["interval_drift"] += 1
            previous = (row, current)
            continue
        reset = any(
            current[key][0] < prior[key][0] or current[key][1] < prior[key][1]
            for key in ALIASES
        )
        if reset:
            rejection_counts["counter_reset"] += 1
            previous = (row, current)
            continue
        for metric, reference_key, candidate_key in (
            ("ttft", "ttft_vllm", "ttft_gadget"),
            ("itl", "itl_vllm", "itl_gadget"),
        ):
            reference_sum = current[reference_key][0] - prior[reference_key][0]
            reference_count = current[reference_key][1] - prior[reference_key][1]
            candidate_sum = current[candidate_key][0] - prior[candidate_key][0]
            candidate_count = current[candidate_key][1] - prior[candidate_key][1]
            if reference_count <= 0 or candidate_count <= 0:
                rejection_counts[f"empty_{metric}"] += 1
                continue
            if metric == "ttft" and reference_count != candidate_count:
                rejection_counts["ttft_count_mismatch"] += 1
                continue
            count_ratio = candidate_count / reference_count
            if metric == "itl" and not (
                args.minimum_itl_count_ratio
                <= count_ratio
                <= args.maximum_itl_count_ratio
            ):
                rejection_counts["itl_count_ratio"] += 1
                continue
            windows[metric].append(
                {
                    "ordinal": int(row["ordinal"]),
                    "start_wall_ns": int(prior_row["wall_ns"]),
                    "end_wall_ns": int(row["wall_ns"]),
                    "reference_count": reference_count,
                    "candidate_count": candidate_count,
                    "candidate_to_reference_count_ratio": count_ratio,
                    "reference_ms": reference_sum / reference_count * ALIASES[reference_key]["scale_ms"],
                    "candidate_ms": candidate_sum / candidate_count * ALIASES[candidate_key]["scale_ms"],
                }
            )
        previous = (row, current)

    report = {
        "schema": 1,
        "contract": "adjacent paired five-second cumulative histogram deltas",
        "max_skew_ms": args.max_skew_ms,
        "max_scrape_duration_ms": args.max_scrape_duration_ms,
        "max_interval_drift_ms": args.max_interval_drift_ms,
        "itl_count_ratio_bounds": [
            args.minimum_itl_count_ratio,
            args.maximum_itl_count_ratio,
        ],
        "sample_pairs": len(rows),
        "rejections": rejection_counts,
        "ttft": difference_stats(
            [row["reference_ms"] for row in windows["ttft"]],
            [row["candidate_ms"] for row in windows["ttft"]],
        ),
        "itl": difference_stats(
            [row["reference_ms"] for row in windows["itl"]],
            [row["candidate_ms"] for row in windows["itl"]],
        ),
    }
    if rejection_counts["gpu_process"]:
        raise SystemExit(
            "unexpected or unverifiable GPU process observed during collection"
        )
    if report["ttft"]["window_count"] < args.minimum_ttft_windows:
        raise SystemExit(
            f"insufficient aligned TTFT windows: {report['ttft']['window_count']}"
        )
    if report["itl"]["window_count"] < args.minimum_itl_windows:
        raise SystemExit(
            f"insufficient aligned ITL windows: {report['itl']['window_count']}"
        )

    for metric in ("ttft", "itl"):
        with (args.output_dir / f"{metric}-windows.csv").open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=list(windows[metric][0]))
            writer.writeheader()
            writer.writerows(windows[metric])
        svg_chart(
            args.output_dir / f"{metric}-vllm-vs-ig-cuda.svg",
            (
                f"{metric.upper()}: native vLLM vs IG CUDA gadget "
                f"({len(windows[metric])} aligned windows)"
            ),
            windows[metric],
        )
    (args.output_dir / "summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
