#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s GO_REFERENCE_ROOT OUTPUT_DIRECTORY\n' "$0" >&2
    exit 2
fi
reference_root=$(cd -- "$1" && pwd)
script_directory=$(cd -- "$(dirname -- "$0")" && pwd)
expected_reference=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
[[ $(git -C "$reference_root" rev-parse HEAD) == "$expected_reference" ]] || {
    printf 'Go reference must be at %s\n' "$expected_reference" >&2
    exit 1
}
mkdir -p -- "$2"
output_directory=$(cd -- "$2" && pwd)
scratch=$(mktemp -d)
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT
git -C "$reference_root" archive "$expected_reference" | tar -x -C "$scratch"
proxy_target="$scratch/proxy/hysteria/rust_reference_test.go"
transport_target="$scratch/transport/internet/hysteria/rust_reference_test.go"
for target in "$proxy_target" "$transport_target"; do
    [[ ! -e $target ]] || { printf 'Refusing to overwrite %s\n' "$target" >&2; exit 1; }
done
cp -- "$script_directory/proxy_reference_test.go" "$proxy_target"
cp -- "$script_directory/transport_reference_test.go" "$transport_target"
(cd -- "$scratch" && go test ./proxy/hysteria ./transport/internet/hysteria -run '^TestRustReferenceVectors$' -count=1 -v) >"$output_directory/hysteria-reference.log" 2>&1 || {
    cat -- "$output_directory/hysteria-reference.log" >&2
    exit 1
}
sed -n 's/^HYSTERIA_VECTOR //p' "$output_directory/hysteria-reference.log" >"$output_directory/hysteria-vectors.jsonl"
[[ $(wc -l <"$output_directory/hysteria-vectors.jsonl") -eq 2 ]] || {
    printf 'Expected protocol and authentication vector records\n' >&2
    exit 1
}
printf 'Wrote %s/hysteria-vectors.jsonl\n' "$output_directory"
