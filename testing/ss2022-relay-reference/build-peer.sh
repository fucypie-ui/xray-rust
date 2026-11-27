#!/usr/bin/env bash
# Linux runner only; never build from a dirty or substituted Go working tree.
set -euo pipefail
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s GO_REFERENCE_ROOT OUTPUT_BINARY\n' "$0" >&2
    exit 2
fi
if [[ $(uname -s) != Linux || -n ${TERMUX_VERSION:-} || -n ${ANDROID_ROOT:-} || ${PREFIX:-} == /data/data/com.termux/* || ${GOOS:-linux} != linux ]]; then
    printf 'Build the pinned SS2022 relay peer on Linux, not Android.\n' >&2
    exit 1
fi
reference_root=$(cd -- "$1" && pwd)
script_directory=$(cd -- "$(dirname -- "$0")" && pwd)
reference=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
if [[ $(git -C "$reference_root" rev-parse HEAD) != "$reference" ]]; then
    printf 'Go reference must be exactly %s\n' "$reference" >&2
    exit 1
fi
mkdir -p -- "$(dirname -- "$2")"
output_directory=$(cd -- "$(dirname -- "$2")" && pwd)
output_binary="$output_directory/$(basename -- "$2")"
scratch=$(mktemp -d)
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
git -C "$reference_root" archive "$reference" | tar -x -C "$scratch"
mkdir -- "$scratch/rust_ss2022_relay_peer"
cp -- "$script_directory/peer.go" "$scratch/rust_ss2022_relay_peer/main.go"
(cd -- "$scratch" && GOWORK=off GOTOOLCHAIN=local GOOS=linux go build \
    -mod=readonly -trimpath -buildvcs=false -o "$output_binary" ./rust_ss2022_relay_peer)
printf 'Wrote %s (Go reference %s)\n' "$output_binary" "$reference" >&2
