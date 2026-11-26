#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 GO_REFERENCE_ROOT OUTPUT_DIRECTORY [RUST_VECTORS_JSONL]" >&2
    exit 2
fi
helper_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
go_root=$(cd -- "$1" && pwd)
expected=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
actual=$(git -C "$go_root" rev-parse HEAD)
if [[ $actual != "$expected" ]]; then
    echo "Go reference must be at $expected; found $actual" >&2
    exit 1
fi
mkdir -p -- "$2"
output_dir=$(cd -- "$2" && pwd)
rust_vectors=
if [[ $# -eq 3 ]]; then
    rust_vectors=$(cd -- "$(dirname -- "$3")" && pwd)/$(basename -- "$3")
    [[ -f $rust_vectors ]] || { echo "Missing Rust vectors: $rust_vectors" >&2; exit 1; }
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# Stage the exact committed source; never write into the Go authority checkout.
git -C "$go_root" archive --format=tar "$expected" | tar -xf - -C "$work"
target="$work/proxy/shadowsocks/rust_classic_reference_test.go"
if [[ -e $target ]]; then
    echo "Refusing to overwrite $target" >&2
    exit 1
fi
cp -- "$helper_dir/reference_test.go" "$target"
# Pin the toolchain as well as the source commit; execution belongs on Linux.
export GOTOOLCHAIN=go1.27.0
(cd -- "$work" && go test -mod=readonly ./proxy/shadowsocks -run '^TestRustClassicReferenceVectors$' -count=1 -v) >"$output_dir/shadowsocks-go.log" 2>&1 || {
    cat -- "$output_dir/shadowsocks-go.log" >&2
    exit 1
}
sed -n 's/^SS_CLASSIC_VECTOR //p' "$output_dir/shadowsocks-go.log" >"$output_dir/shadowsocks-go.jsonl"
if [[ $(wc -l <"$output_dir/shadowsocks-go.jsonl") -ne 4 ]]; then
    echo "Expected exactly four Go classic method vectors" >&2
    exit 1
fi
if [[ -n $rust_vectors ]]; then
    (cd -- "$work" && SS_CLASSIC_RUST_VECTORS="$rust_vectors" go test -mod=readonly ./proxy/shadowsocks -run '^TestRustClassicReferenceDecode$' -count=1 -v) >"$output_dir/shadowsocks-rust-decode.log" 2>&1 || {
        cat -- "$output_dir/shadowsocks-rust-decode.log" >&2
        exit 1
    }
fi
cat -- "$output_dir/shadowsocks-go.jsonl"
