#!/usr/bin/env bash
set -euo pipefail

mode=${1:-}
case "$mode" in
    preflight)
        duration=0
        max_turns=0
        minimum_ttft_windows=0
        minimum_itl_windows=0
        ;;
    smoke)
        duration=${REPRO_DURATION:-90}
        max_turns=${REPRO_MAX_TURNS:-2}
        minimum_ttft_windows=1
        minimum_itl_windows=1
        ;;
    canary)
        duration=${REPRO_DURATION:-180}
        max_turns=${REPRO_MAX_TURNS:-0}
        minimum_ttft_windows=3
        minimum_itl_windows=6
        ;;
    five-minute)
        duration=${REPRO_DURATION:-300}
        max_turns=${REPRO_MAX_TURNS:-0}
        minimum_ttft_windows=8
        minimum_itl_windows=20
        ;;
    *)
        echo "usage: $0 preflight|smoke|canary|five-minute" >&2
        exit 2
        ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
run_root=${REPRO_RUN_ROOT:-"$PWD/reproduction-runs"}
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$mode"
run_dir="$run_root/$run_id"
container_name=${REPRO_VLLM_CONTAINER:-ig-cuda-vllm}
vllm_image=${REPRO_VLLM_IMAGE:-vllm/vllm-openai:v0.10.2}
model=${REPRO_MODEL:-Qwen/Qwen2.5-0.5B-Instruct}
model_revision=${REPRO_MODEL_REVISION:-}
model_cache=${REPRO_MODEL_CACHE:-"$HOME/.cache/huggingface"}
gadget_image=${REPRO_GADGET_IMAGE:-ghcr.io/vfalico/cuda_observability:v0.1.0}
ig_bin=${REPRO_IG_BIN:-ig}
copilot_bin=${REPRO_COPILOT_BIN:-$(command -v copilot || true)}
gpu_device=${REPRO_GPU_DEVICE:-0}
preset=${REPRO_PRESET:-vllm-0.10.2-qwen2.5-0.5b-a100-sequential-transition-v4}
ig_scope=${REPRO_IG_SCOPE:-host}
cuda_probe_image=${REPRO_CUDA_PROBE_IMAGE:-nvidia/cuda:12.8.1-base-ubuntu24.04}
expected_ig_version=${REPRO_IG_VERSION:-v0.57.0}
expected_copilot_version=${REPRO_COPILOT_VERSION:-1.0.65}

for command in docker curl python3 "$ig_bin"; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "missing command: $command" >&2
        exit 1
    }
done
command -v nvidia-smi >/dev/null 2>&1 || {
    echo "missing command: nvidia-smi" >&2
    exit 1
}
sudo -n true >/dev/null 2>&1 || {
    echo "passwordless sudo is required to run ig noninteractively" >&2
    exit 1
}
docker info >/dev/null
if docker inspect "$container_name" >/dev/null 2>&1; then
    echo "refusing to replace pre-existing container: $container_name" >&2
    exit 1
fi
if ss -lnt | grep -Eq ':(18080|2224) '; then
    echo "required port 18080 or 2224 is already in use" >&2
    exit 1
fi
docker image inspect "$cuda_probe_image" >/dev/null
docker run --rm --pull=never --gpus "device=$gpu_device" \
    --entrypoint nvidia-smi "$cuda_probe_image" \
    --query-gpu=uuid,name,driver_version --format=csv,noheader
test "$("$ig_bin" version)" = "$expected_ig_version"
nvidia-smi --query-gpu=index,uuid,name,mig.mode.current,memory.total \
    --format=csv,noheader
docker image inspect "$vllm_image" >/dev/null
if [[ "$gadget_image" == *@sha256:* ]]; then
    gadget_repository=${gadget_image%@sha256:*}
    gadget_manifest=sha256:${gadget_image##*@sha256:}
    sudo -n "$ig_bin" image list --no-trunc |
        awk -v repository="$gadget_repository" -v manifest="$gadget_manifest" \
            '$1 == repository && $3 == manifest { found = 1 } END { exit !found }'
else
    gadget_repository=${gadget_image%:*}
    gadget_tag=${gadget_image##*:}
    sudo -n "$ig_bin" image list --no-trunc |
        awk -v repository="$gadget_repository" -v tag="$gadget_tag" \
            '$1 == repository && $2 == tag { found = 1 } END { exit !found }'
fi

if [[ -z "$copilot_bin" ]]; then
    echo "copilot executable not found" >&2
    exit 1
fi
copilot_version=$("$copilot_bin" --version)
copilot_version=${copilot_version%%$'\n'*}
test "$copilot_version" = "GitHub Copilot CLI $expected_copilot_version."
nvidia-smi --query-compute-apps=pid,process_name,used_memory \
    --format=csv,noheader >"/tmp/ig-cuda-preflight-gpu-processes.$$"
if [[ -s "/tmp/ig-cuda-preflight-gpu-processes.$$" ]]; then
    echo "competing GPU process detected" >&2
    cat "/tmp/ig-cuda-preflight-gpu-processes.$$" >&2
    rm -f "/tmp/ig-cuda-preflight-gpu-processes.$$"
    exit 1
fi
rm -f "/tmp/ig-cuda-preflight-gpu-processes.$$"

if [[ "$mode" == preflight ]]; then
    exit 0
fi
case "$ig_scope" in
    container)
        ig_scope_args=(--containername="$container_name")
        ;;
    host)
        ig_scope_args=(--host)
        ;;
    *)
        echo "REPRO_IG_SCOPE must be container or host" >&2
        exit 1
        ;;
esac

mkdir -p "$run_dir/copilot"
vllm_started=0
ig_pid=
collector_pid=
cleanup() {
    rc=$?
    trap - EXIT INT TERM
    for pid in "$collector_pid" "$ig_pid"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if docker inspect "$container_name" >/dev/null 2>&1 &&
        [[ "$(docker inspect "$container_name" --format '{{ index .Config.Labels "ig.cuda.reproduction.run" }}')" == "$run_id" ]]; then
        docker logs "$container_name" >"$run_dir/vllm.log" 2>&1 || true
        docker rm -f "$container_name" >/dev/null 2>&1 || true
    fi
    ss -lnt >"$run_dir/ports-after.txt" 2>&1 || true
    nvidia-smi --query-compute-apps=pid,process_name,used_memory \
        --format=csv,noheader >"$run_dir/gpu-processes-after.txt" 2>&1 || true
    if command -v bpftool >/dev/null 2>&1; then
        sudo -n bpftool -j map show >"$run_dir/bpf-maps-after.json" 2>&1 || true
    fi
    {
        printf 'run_id=%s\n' "$run_id"
        printf 'mode=%s\n' "$mode"
        printf 'source_commit=%s\n' "${REPRO_SOURCE_COMMIT:-unknown}"
        printf 'source_dirty=%s\n' "${REPRO_SOURCE_DIRTY:-unknown}"
        printf 'ig_version=%s\n' "$("$ig_bin" version)"
        printf 'ig_sha256=%s\n' "$(sha256sum "$(command -v "$ig_bin")" | awk '{print $1}')"
        printf 'copilot_version=%s\n' "$copilot_version"
        printf 'copilot_sha256=%s\n' "$(sha256sum "$(command -v "$copilot_bin")" | awk '{print $1}')"
        printf 'vllm_image=%s\n' "$vllm_image"
        printf 'gadget_image=%s\n' "$gadget_image"
        printf 'model=%s\n' "$model"
        printf 'model_revision=%s\n' "${model_revision:-unpinned}"
        printf 'preset=%s\n' "$preset"
        printf 'ig_scope=%s\n' "$ig_scope"
    } >"$run_dir/identities.txt"
    docker image inspect "$vllm_image" >"$run_dir/vllm-image-inspect.json"
    sudo -n "$ig_bin" image list --no-trunc >"$run_dir/ig-images.txt"
    nvidia-smi -q >"$run_dir/nvidia-smi-q.txt"
    (
        cd "$run_dir"
        find . -type f ! -name SHA256SUMS -print0 |
            sort -z |
            xargs -0 sha256sum >SHA256SUMS
    )
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_ig() {
    sudo -n "$ig_bin" run \
        --otel-metrics-listen \
        --otel-metrics-listen-address=127.0.0.1:2224 \
        --otel-metrics-export-internals \
        "$gadget_image" \
        --pull=never \
        --verify-image=false \
        --heuristics=true \
        --preset="$preset" \
        --emit-context-get-device=false \
        --otel-metrics-name=cuda_calls:cuda_calls,inference_activity:inference_activity,inference_summary:inference_summary,analyzer_health:analyzer_health \
        "${ig_scope_args[@]}" \
        -o json >"$run_dir/ig.jsonl" 2>"$run_dir/ig.err" &
    ig_pid=$!
    printf '%s\n' "$ig_pid" >"$run_dir/ig.pid"
    curl --silent --show-error --fail \
        --retry 30 --retry-all-errors --retry-delay 1 \
        --connect-timeout 1 --max-time 3 \
        http://127.0.0.1:2224/metrics >"$run_dir/gadget-metrics-ready.txt"
    grep -m1 'CUDA inference heuristics enabled:' \
        < <(tail --pid="$ig_pid" -n +1 -F "$run_dir/ig.err") >/dev/null
}

nvidia-smi --query-compute-apps=pid,process_name,used_memory \
    --format=csv,noheader >"$run_dir/gpu-processes-before.txt"
if [[ -s "$run_dir/gpu-processes-before.txt" ]]; then
    echo "competing GPU process detected" >&2
    cat "$run_dir/gpu-processes-before.txt" >&2
    exit 1
fi
if command -v bpftool >/dev/null 2>&1; then
    sudo -n bpftool -j map show >"$run_dir/bpf-maps-before.json" 2>&1 || true
fi

if [[ "$ig_scope" == host ]]; then
    start_ig
fi

revision_args=()
if [[ -n "$model_revision" ]]; then
    revision_args+=(--revision "$model_revision")
fi
docker run -d \
    --name "$container_name" \
    --label "ig.cuda.reproduction.run=$run_id" \
    --pull=never \
    --gpus "device=$gpu_device" \
    --network host \
    -v "$model_cache:/root/.cache/huggingface" \
    -v "$script_dir/generation-config:/reproduction-generation-config:ro" \
    "$vllm_image" \
    --model "$model" \
    "${revision_args[@]}" \
    --served-model-name qwen \
    --tensor-parallel-size 1 \
    --pipeline-parallel-size 1 \
    --data-parallel-size 1 \
    --max-num-seqs 1 \
    --max-model-len 32768 \
    --enforce-eager \
    --generation-config /reproduction-generation-config \
    --enable-auto-tool-choice \
    --tool-call-parser hermes \
    --host 127.0.0.1 \
    --port 18080 >"$run_dir/vllm-container.id"
vllm_started=1

curl --silent --show-error --fail \
    --retry 180 --retry-all-errors --retry-delay 1 \
    --connect-timeout 1 --max-time 3 \
    http://127.0.0.1:18080/v1/models >"$run_dir/models.json"
curl --silent --show-error --fail \
    http://127.0.0.1:18080/metrics >"$run_dir/vllm-metrics-ready.txt"
grep -q 'vllm:time_to_first_token_seconds' "$run_dir/vllm-metrics-ready.txt"
grep -q 'vllm:inter_token_latency_seconds' "$run_dir/vllm-metrics-ready.txt"

if [[ "$ig_scope" == container ]]; then
    start_ig
fi

curl --silent --show-error --fail \
    http://127.0.0.1:18080/v1/chat/completions \
    -H 'content-type: application/json' \
    -d '{"model":"qwen","messages":[{"role":"user","content":"Reply with exactly: warm"}],"max_tokens":8}' \
    >"$run_dir/warmup.json"

export COPILOT_PROVIDER_BASE_URL=http://127.0.0.1:18080/v1
export COPILOT_PROVIDER_TYPE=openai
export COPILOT_PROVIDER_MODEL_ID=qwen
export COPILOT_PROVIDER_WIRE_MODEL=qwen
export COPILOT_MODEL=qwen
export COPILOT_PROVIDER_MAX_PROMPT_TOKENS=10000
export COPILOT_PROVIDER_MAX_OUTPUT_TOKENS=512
export COPILOT_OFFLINE=true

collector_duration=$((duration + 10))
python3 "$script_dir/collect_metrics.py" \
    --duration "$collector_duration" \
    --allowed-container-id "$(cat "$run_dir/vllm-container.id")" \
    --output "$run_dir/metrics.jsonl" \
    >"$run_dir/collector.out" 2>"$run_dir/collector.err" &
collector_pid=$!
printf '%s\n' "$collector_pid" >"$run_dir/collector.pid"

python3 "$script_dir/workload.py" \
    --duration "$duration" \
    --max-turns "$max_turns" \
    --session-prefix="ig-cuda-$run_id" \
    --output-dir "$run_dir/copilot" \
    --copilot "$copilot_bin"
wait "$collector_pid"
collector_pid=

curl --silent --show-error --fail \
    http://127.0.0.1:18080/metrics >"$run_dir/vllm-metrics-after.txt"
curl --silent --show-error --fail \
    http://127.0.0.1:2224/metrics >"$run_dir/gadget-metrics-after.txt"
grep -q 'cuda_inference_ttft_candidate' "$run_dir/gadget-metrics-after.txt"
grep -q 'cuda_inference_decode_interval_candidate' "$run_dir/gadget-metrics-after.txt"

kill -TERM "$ig_pid"
set +e
wait "$ig_pid"
ig_rc=$?
set -e
ig_pid=
if [[ "$ig_rc" -ne 0 && "$ig_rc" -ne 143 ]]; then
    echo "ig exited unexpectedly: $ig_rc" >&2
    exit 1
fi

minimum_turns=1
if [[ "$mode" == canary ]]; then
    minimum_turns=4
elif [[ "$mode" == five-minute ]]; then
    minimum_turns=8
fi
python3 "$script_dir/validate_run.py" \
    --ig-output "$run_dir/ig.jsonl" \
    --workload "$run_dir/copilot/workload.jsonl" \
    --preset "$preset" \
    --container-id "$(cat "$run_dir/vllm-container.id")" \
    --minimum-turns "$minimum_turns" \
    --output "$run_dir/integrity.json" \
    >"$run_dir/integrity.out" 2>"$run_dir/integrity.err"

python3 "$script_dir/analyze_metrics.py" \
    "$run_dir/metrics.jsonl" \
    --output-dir "$run_dir/analysis" \
    --minimum-ttft-windows "$minimum_ttft_windows" \
    --minimum-itl-windows "$minimum_itl_windows" \
    >"$run_dir/analysis.out" 2>"$run_dir/analysis.err"
cat "$run_dir/analysis.out"
cat "$run_dir/integrity.out"
printf '%s\n' "$run_dir"
