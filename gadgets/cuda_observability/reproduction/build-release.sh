#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
output_dir=${1:-"$PWD/release-output"}
ig_bin=${RELEASE_IG_BIN:-"$repo_root/ig"}
release_image=ghcr.io/vfalico/cuda_observability:v0.1.0
builder_image=ghcr.io/inspektor-gadget/gadget-builder@sha256:88509fd2b8b48a22644a90c0b032c3c9e150c0b9d7d7337f5c1f94774415ab08
expected_commit=${RELEASE_SOURCE_COMMIT:?set RELEASE_SOURCE_COMMIT to the exact public commit}
actual_commit=$(git -C "$repo_root" rev-parse HEAD)

if [[ "$actual_commit" != "$expected_commit" ]]; then
    echo "HEAD $actual_commit does not match RELEASE_SOURCE_COMMIT $expected_commit" >&2
    exit 1
fi
if [[ -n "$(git -C "$repo_root" status --porcelain)" ]]; then
    echo "release checkout must be clean" >&2
    exit 1
fi
if [[ ! -x "$ig_bin" ]]; then
    echo "missing executable IG binary: $ig_bin" >&2
    exit 1
fi

source_epoch=$(git -C "$repo_root" show -s --format=%ct "$actual_commit")
short_commit=${actual_commit:0:12}
build_one=localhost/cuda_observability:v0.1.0-build1-"$short_commit"
build_two=localhost/cuda_observability:v0.1.0-build2-"$short_commit"
work_dir=$(mktemp -d "$repo_root/.cuda-release-build.XXXXXX")
metadata_dir="$work_dir/cuda_observability"

cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT

git -C "$repo_root" archive "$actual_commit" gadgets/cuda_observability |
    tar -x -C "$work_dir" --strip-components=1
python3 - "$metadata_dir/gadget.yaml" "$actual_commit" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
commit = sys.argv[2]
text = path.read_text()
branch_url = (
    "https://github.com/vfalico/inspektor-gadget-public/tree/"
    "cuda-observability/gadgets/cuda_observability"
)
commit_url = (
    f"https://github.com/vfalico/inspektor-gadget-public/tree/"
    f"{commit}/gadgets/cuda_observability"
)
if text.count(branch_url) != 2:
    raise SystemExit("expected exactly two release metadata branch URLs")
path.write_text(text.replace(branch_url, commit_url))
PY

mkdir -p "$output_dir"
for image in "$build_one" "$build_two"; do
    sudo -E \
        IG_SOURCE_PATH="$repo_root" \
        SOURCE_DATE_EPOCH="$source_epoch" \
        "$ig_bin" image build \
        --builder-image "$builder_image" \
        --builder-image-pull=never \
        -t "$image" \
        "$metadata_dir"
done

image_digest() {
    sudo "$ig_bin" image list --no-trunc |
        awk -v repository="${1%:*}" -v tag="${1##*:}" \
            '$1 == repository && $2 == tag { print $3 }'
}

digest_one=$(image_digest "$build_one")
digest_two=$(image_digest "$build_two")
if [[ -z "$digest_one" || "$digest_one" != "$digest_two" ]]; then
    echo "release builds are not reproducible: $digest_one != $digest_two" >&2
    exit 1
fi

sudo "$ig_bin" image tag "$build_one" "$release_image"
archive="$output_dir/cuda_observability-v0.1.0.tar"
sudo "$ig_bin" image export "$release_image" "$archive"
sudo chown "$(id -u):$(id -g)" "$archive"
archive_sha=$(sha256sum "$archive" | awk '{print $1}')

cat >"$output_dir/release-identities.txt" <<EOF
source_commit=$actual_commit
source_date_epoch=$source_epoch
builder_image=$builder_image
release_image=$release_image
manifest_digest=$digest_one
archive_sha256=$archive_sha
EOF
(
    cd "$output_dir"
    sha256sum cuda_observability-v0.1.0.tar release-identities.txt >SHA256SUMS
)

printf 'Built %s@%s\n' "${release_image%:*}" "$digest_one"
printf 'Archive SHA-256: %s\n' "$archive_sha"
