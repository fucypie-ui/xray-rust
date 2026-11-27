#!/usr/bin/env bash
# Execute on remote Linux only; the source checkout is read-only input.
set -euo pipefail
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s GO_REFERENCE_ROOT OUTPUT_BINARY\n' "$0" >&2
    exit 2
fi
if [[ $(uname -s) != Linux || -n ${TERMUX_VERSION:-} || ${PREFIX:-} == /data/data/com.termux/* ]]; then
    printf 'Build the pinned reflection peer on remote Linux, not Android.\n' >&2
    exit 1
fi
reference_root=$(cd -- "$1" && pwd -P)
script_directory=$(cd -- "$(dirname -- "$0")" && pwd -P)
reference=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
if [[ $(git -C "$reference_root" rev-parse HEAD) != "$reference" ]]; then
    printf 'Go reference must be at %s\n' "$reference" >&2
    exit 1
fi
output_binary=$(realpath -m -- "$2")
case "$output_binary" in
    "$reference_root"|"$reference_root"/*)
        printf 'Output must be outside the Go reference checkout.\n' >&2
        exit 1
        ;;
esac
mkdir -p -- "$(dirname -- "$output_binary")"
scratch=$(mktemp -d)
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
git -C "$reference_root" archive "$reference" | tar -x -C "$scratch"
mkdir -- "$scratch/rust_api_reflection_peer"
cp -- "$script_directory/peer.go" "$scratch/rust_api_reflection_peer/main.go"
(cd -- "$scratch" && GOWORK=off GOTOOLCHAIN=local go build -mod=readonly \
    -trimpath -buildvcs=false -o "$output_binary" ./rust_api_reflection_peer)
printf 'Wrote %s (Go reference %s)\n' "$output_binary" "$reference" >&2
