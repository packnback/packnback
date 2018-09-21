#! /usr/bin/env nix-shell
#! nix-shell --pure -i sh -p rust-bindgen rustfmt

set -e

bindgen ./c/tweetnacl.h -o src/bindings.rs
rustfmt src/bindings.rs