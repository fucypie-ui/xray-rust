#!/usr/bin/env bash
set -euo pipefail

# Run on the Ubuntu reference runner, never on the Android editing host.
if [[ $# != 2 ]]; then
  printf 'usage: %s GO_REFERENCE_ROOT OUTPUT_DIRECTORY\n' "$0" >&2
  exit 2
fi
reference=$(cd "$1" && pwd)
mkdir -p "$2"
output=$(cd "$2" && pwd)
source_dir=$(cd "$(dirname "$0")" && pwd)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
cp "$reference/go.mod" "$reference/go.sum" "$stage/"
cp "$source_dir/main.go" "$source_dir/main_test.go" "$stage/"
(cd "$stage" && GOWORK=off go test -mod=mod ./main.go ./main_test.go)
(cd "$stage" && GOWORK=off go build -mod=mod -o "$output/wireguard-reference" ./main.go)
"$output/wireguard-reference" -mode vectors > "$output/wireguard-key-vectors.json"
printf 'Go reference executable: %s/wireguard-reference\n' "$output"
printf 'Independent key vectors: %s/wireguard-key-vectors.json\n' "$output"
