#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 GO_REFERENCE_ROOT OUTPUT_DIRECTORY" >&2
    exit 2
fi
helper_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
go_root=$(cd -- "$1" && pwd)
mkdir -p -- "$2"
output_dir=$(cd -- "$2" && pwd)
expected=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
actual=$(git -C "$go_root" rev-parse HEAD)
if [[ $actual != "$expected" ]]; then
    echo "Expected Go reference $expected; found $actual" >&2
    exit 1
fi
work_dir=$(mktemp -d "$output_dir/mux-reference.XXXXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT
# Archive avoids modifying the reference checkout or compiling on Android.
git -C "$go_root" archive "$expected" | tar -x -C "$work_dir"
cp -- "$helper_dir/reference_test.go" "$work_dir/proxy/vless/multiplex/rust_reference_test.go"
(cd -- "$work_dir" && go test ./proxy/vless/multiplex -run '^TestRustMuxReference$' -count=1 -v) >"$output_dir/mux-reference.log" 2>&1 || {
    cat -- "$output_dir/mux-reference.log" >&2
    exit 1
}
sed -n 's/^MUX_REFERENCE_VECTOR //p' "$output_dir/mux-reference.log" >"$output_dir/mux-vectors.jsonl"
if [[ $(wc -l <"$output_dir/mux-vectors.jsonl") -ne 12 ]]; then
    echo "Expected 12 Go mux golden vectors" >&2
    exit 1
fi
cat -- "$output_dir/mux-vectors.jsonl"
