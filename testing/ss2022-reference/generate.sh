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
    echo "Go reference must be at $expected; found $actual" >&2
    exit 1
fi
target="$go_root/proxy/shadowsocks_2022/rust_reference_test.go"
if [[ -e $target ]]; then
    echo "Refusing to overwrite existing $target" >&2
    exit 1
fi
trap 'rm -f -- "$target"' EXIT
cp -- "$helper_dir/reference_test.go" "$target"
(cd -- "$go_root" && go test ./proxy/shadowsocks_2022 -run '^TestRustReferenceVectors$' -count=1 -v) >"$output_dir/ss2022-reference.log" 2>&1 || {
    cat -- "$output_dir/ss2022-reference.log" >&2
    exit 1
}
sed -n 's/^SS2022_VECTOR //p' "$output_dir/ss2022-reference.log" >"$output_dir/ss2022-vectors.jsonl"
if [[ $(wc -l <"$output_dir/ss2022-vectors.jsonl") -ne 2 ]]; then
    echo "Expected exactly two AES reference vectors" >&2
    exit 1
fi
cat -- "$output_dir/ss2022-vectors.jsonl"
