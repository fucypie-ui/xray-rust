#!/usr/bin/env bash
# Build only on Linux CI, from committed reference sources in a disposable tree.
set -euo pipefail
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s GO_REFERENCE_ROOT OUTPUT_BINARY\n' "$0" >&2
    exit 2
fi
if [[ $(uname -s) != Linux || -n ${TERMUX_VERSION:-} || ${PREFIX:-} == /data/data/com.termux/* ]]; then
    printf 'Build the pinned SS2022 peer on a Linux CI host, not Android.\n' >&2
    exit 1
fi
reference_root=$(cd -- "$1" && pwd)
script_directory=$(cd -- "$(dirname -- "$0")" && pwd)
expected_reference=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
if [[ $(git -C "$reference_root" rev-parse HEAD) != "$expected_reference" ]]; then
    printf 'Go reference must be at %s\n' "$expected_reference" >&2
    exit 1
fi
mkdir -p -- "$(dirname -- "$2")"
output_directory=$(cd -- "$(dirname -- "$2")" && pwd)
output_binary="$output_directory/$(basename -- "$2")"
scratch=$(mktemp -d)
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
git -C "$reference_root" archive "$expected_reference" | tar -x -C "$scratch"
mkdir -- "$scratch/rust_ss2022_peer"
cp -- "$script_directory/peer.go" "$scratch/rust_ss2022_peer/main.go"
(cd -- "$scratch" && GOWORK=off go build -mod=readonly -trimpath -buildvcs=false \
    -o "$output_binary" ./rust_ss2022_peer)
printf 'Wrote %s (Go reference %s)\n' "$output_binary" "$expected_reference" >&2
