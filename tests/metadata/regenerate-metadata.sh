#!/bin/sh

set -eu

cd `dirname $0`

for d in consistent-snapshot-false consistent-snapshot-true; do
	if [[ -e $d ]]; then
		rm -r $d
	fi
done

cargo run generate
# TODO: re-enable when figure out how to make it play nicely with Windows.
#go run ./tools/linkify-metadata.go
