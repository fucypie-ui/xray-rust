#!/usr/bin/env bash
# Run on the remote Ubuntu builder; the reference checkout stays read-only.
set -euo pipefail
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s GO_REFERENCE_ROOT OUTPUT_DIRECTORY\n' "$0" >&2
    exit 2
fi
reference_root=$(cd -- "$1" && pwd)
mkdir -p -- "$2"
output_directory=$(cd -- "$2" && pwd)
helper_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
reference_commit=$(git -C "$reference_root" rev-parse HEAD)
if [[ "$reference_commit" != 67756b3674d56b72c7a7e675e8dcd3f883e1b2f7 ]]; then
    printf 'Wrong Go reference commit: %s\n' "$reference_commit" >&2
    exit 1
fi
(cd -- "$reference_root" && go run -mod=readonly "$helper_directory/main.go" "$output_directory")
printf '%s\n' "$reference_commit" > "$output_directory/reference-commit.txt"
