#!/bin/sh
# Execute only on the parent Ubuntu CI host. Never modifies GO_REFERENCE_ROOT.
set -eu
if [ "$#" -ne 2 ]; then
    printf "usage: %s GO_REFERENCE_ROOT OUTPUT_DIRECTORY\n" "$0" >&2
    exit 2
fi
reference=$(CDPATH= cd -- "$1" && pwd)
mkdir -p -- "$2"
output=$(CDPATH= cd -- "$2" && pwd)
helper=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test -f "$reference/transport/internet/kcp/connection.go"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
# A private copy permits a package-local test to exercise unexported workers.
cp -R "$reference/." "$work/"
cp "$helper/reference_test.go.txt" "$work/transport/internet/kcp/rust_reference_test.go"
cd -- "$work"
KCP_REFERENCE_OUTPUT="$output/kcp-reference.json" go test -mod=readonly ./transport/internet/kcp -run '^TestRustKCPReference$' -count=1
