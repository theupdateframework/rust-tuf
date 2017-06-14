#!/bin/bash
set -ue

'Runs the CLI tool against a repo and prints the state after.'

cd "$(dirname "$(readlink -f "$0")")/.."

declare -r bin="target/debug/tuf"
temp=$(mktemp -d)
declare -r temp
declare -r repo="tests/tuf-test-vectors/tuf/$1/repo"

cargo build --features=cli

set +e
export RUST_LOG='debug'

"$bin" -p "$temp" -f "$repo" init
cp "$repo"/root.json "$temp/metadata/current"
"$bin" -p "$temp" -f "$repo" update
"$bin" -p "$temp" -f "$repo" fetch targets/file.txt
"$bin" -p "$temp" -f "$repo" verify targets/file.txt

tree "$temp"
