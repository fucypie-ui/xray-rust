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

# Keep the helper inside the disposable runner checkout's Go module so it
# resolves the authoritative go.mod/go.sum. Do not run this locally.
helper_directory=$(mktemp -d "$reference_root/xray-rust-crypto-reference.XXXXXX")
helper_name=$(basename -- "$helper_directory")
cleanup() {
    rm -f -- "$helper_directory/main.go" "$helper_directory/vectors.json"
    rmdir -- "$helper_directory"
}
trap cleanup EXIT
cp -- "$script_directory/main.go" "$helper_directory/main.go"
(
    cd -- "$reference_root"
    go run "./$helper_name"
) > "$helper_directory/vectors.json"
mv -- "$helper_directory/vectors.json" "$output_directory/vectors.json"
printf 'Wrote %s/vectors.json\n' "$output_directory"
