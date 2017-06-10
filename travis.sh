#!/bin/bash
set -ex

cd tests/tuf-test-vectors
make init
cd ../../

trap '{ rc=$?; cat Cargo.lock; exit $rc; }' EXIT
RUST_BACKTRACE=full cargo build --verbose --features=cli

./tests/tuf-test-vectors/server.py --path tuf &
trap '{ rc=$?; kill %1; cat Cargo.lock; exit $rc; }' EXIT
RUST_BACKTRACE=full cargo test --verbose --features=cli
kill %1 || true

trap - EXIT
trap
