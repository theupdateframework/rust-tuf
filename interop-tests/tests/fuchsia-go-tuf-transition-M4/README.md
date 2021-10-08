# fuchsia-go-tuf-transition-M4

This is metadata generated as part of Fuchsia's [go-tuf fork] transition from
TUF 0.9 to 1.0. It was copied from this [commit] with the following patches
applied that completes the transition to TUF 1.0:

* [322708]: add sha512 to keyid_hash_algorithms
* [287594]: Stop generating TUF 0.9 prefixed metadata and target files
* [271035]: G4: Remove Signature method, TUF-0.9 compatible keyid

[go-tuf fork]: https://fuchsia.googlesource.com/third_party/go-tuf
[commit]: https://fuchsia.googlesource.com/third_party/go-tuf/+/5527feb6040bc316ea6553f3c5fef0070d2e1be0/client/testdata/go-tuf-transition-M4/
[322708]: https://fuchsia-review.googlesource.com/c/third_party/go-tuf/+/322708/6
[287594]: https://fuchsia-review.googlesource.com/c/third_party/go-tuf/+/287594/13
[271035]: https://fuchsia-review.googlesource.com/c/third_party/go-tuf/+/271035/28
