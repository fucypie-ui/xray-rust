#!/usr/bin/env bash
# Linux-only live helper. Build an exact git archive, never the authority worktree.
set -euo pipefail
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s GO_REFERENCE_ROOT OUTPUT_BINARY\n' "$0" >&2
    exit 2
fi
if [[ $(uname -s) != Linux || -n ${TERMUX_VERSION:-} || ${PREFIX:-} == /data/data/com.termux/* ]]; then
    printf 'Build the pinned classic Shadowsocks peer on Linux CI, not Android.\n' >&2
    exit 1
fi
reference_root=$(cd -- "$1" && pwd -P)
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
expected_reference=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
if [[ $(git -C "$reference_root" rev-parse HEAD) != "$expected_reference" ]]; then
    printf 'Go reference must be at %s\n' "$expected_reference" >&2
    exit 1
fi
output_binary=$(realpath -m -- "$2")
case "$output_binary" in
    "$reference_root"|"$reference_root"/*)
        printf 'Output must be outside the authoritative Go checkout.\n' >&2
        exit 1
        ;;
esac
if [[ -d $output_binary ]]; then
    printf 'Output must name a binary file, not a directory.\n' >&2
    exit 1
fi
mkdir -p -- "$(dirname -- "$output_binary")"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/classic-go-peer.XXXXXXXX")
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
git -C "$reference_root" archive --format=tar "$expected_reference" | tar -xf - -C "$scratch"
# Fail if the pinned tree ever already contains this test-only package name.
mkdir -- "$scratch/rust_classic_peer"
cp -- "$script_directory/peer.go" "$scratch/rust_classic_peer/main.go"
(cd -- "$scratch" && GOWORK=off GOTOOLCHAIN=go1.27.0 go build -mod=readonly \
    -trimpath -buildvcs=false -o "$output_binary" ./rust_classic_peer)
printf 'Wrote %s (Go reference %s; go1.27.0)\n' "$output_binary" "$expected_reference" >&2
