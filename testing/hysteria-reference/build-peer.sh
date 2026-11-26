#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s GO_REFERENCE_ROOT OUTPUT_BINARY\n' "$0" >&2
    exit 2
fi
reference_root=$(cd -- "$1" && pwd)
script_directory=$(cd -- "$(dirname -- "$0")" && pwd)
expected_reference=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
[[ $(git -C "$reference_root" rev-parse HEAD) == "$expected_reference" ]] || { printf 'Incorrect Go revision\n' >&2; exit 1; }
mkdir -p -- "$(dirname -- "$2")"
output_directory=$(cd -- "$(dirname -- "$2")" && pwd)
output_binary="$output_directory/$(basename -- "$2")"
scratch=$(mktemp -d)
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
git -C "$reference_root" archive "$expected_reference" | tar -x -C "$scratch"
mkdir -- "$scratch/rust_hysteria_peer"
cp -- "$script_directory/peer.go" "$scratch/rust_hysteria_peer/main.go"
(cd -- "$scratch" && go build -o "$output_binary" ./rust_hysteria_peer)
printf 'Wrote %s\n' "$output_binary"
