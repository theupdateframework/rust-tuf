#!/bin/bash
set -ex

sudo pip install virtualenv
cd tests/tuf-test-vectors
make init
cd ../../

trap '{ rc=$?; cat Cargo.lock; exit $rc; }' EXIT
RUST_BACKTRACE=full cargo build --verbose --features=cli

./tests/tuf-test-vectors/server.py --path tuf &>/dev/null &
RUST_BACKTRACE=full cargo test --verbose --features=cli
