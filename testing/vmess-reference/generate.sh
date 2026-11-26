#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'usage: generate.sh GO_REFERENCE_ROOT OUTPUT_DIRECTORY' >&2
  exit 2
fi
root=$(cd "$1" && pwd)
mkdir -p "$2"
output=$(cd "$2" && pwd)
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
expected=67756b3674d56b72c7a7e675e8dcd3f883e1b2f7
actual=$(git -C "$root" rev-parse HEAD)
[[ $actual == "$expected" ]] || { echo "wrong Go revision: $actual" >&2; exit 1; }
# The reference tree remains read-only. Run a disposable copy on Linux.
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cp -a "$root/." "$work/"
cp "$here/vectors_test.go" "$work/proxy/vmess/encoding/port_reference_test.go"
(cd "$work" && VMESS_VECTOR_OUTPUT="$output/vmess-vectors.json" go test ./proxy/vmess/encoding -run '^TestPortReferenceVectors$' -count=1)
echo "$output/vmess-vectors.json"
