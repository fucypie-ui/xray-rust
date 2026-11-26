#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s GO_REFERENCE_ROOT OUTPUT_DIRECTORY\n' "$0" >&2
    exit 2
fi
reference_root=$(cd -- "$1" && pwd)
script_directory=$(cd -- "$(dirname -- "$0")" && pwd)
expected_reference=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
if [[ $(git -C "$reference_root" rev-parse HEAD) != "$expected_reference" ]]; then
    printf 'Go reference must be at %s\n' "$expected_reference" >&2
    exit 1
fi
mkdir -p -- "$2"
output_directory=$(cd -- "$2" && pwd)
# Only run against a disposable Linux runner checkout. No Go source is edited.
helper_directory=$(mktemp -d "$reference_root/xray-rust-reality-peer.XXXXXX")
helper_name=$(basename -- "$helper_directory")
cleanup() {
    rm -f -- "$helper_directory/main.go"
    rmdir -- "$helper_directory"
}
trap cleanup EXIT
cp -- "$script_directory/peer.go" "$helper_directory/main.go"
(cd -- "$reference_root" && go build -trimpath -o "$output_directory/go-reality-peer" "./$helper_name")
printf '%s\n' "$expected_reference" > "$output_directory/go-reference-commit.txt"
printf 'Built %s/go-reality-peer\n' "$output_directory"
