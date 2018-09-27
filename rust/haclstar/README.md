# rust-haclstar

HACL stands for High-Assurance Cryptographic Library

This is a rust crate exporting the nacl api from https://github.com/project-everest/hacl-star .
HACL* is written in F* and compiles to C, the F* code has formal proofs providing us with
strong confidence in security.

This library aims to provide as minimal wrapping around the native API as possible, while 
still being safe and relatively convenient to use from rust. 
For now these wrappers will only maintain the minimal subset of the API required by packnback.

# Additions or changes from native API

- Rust naming conventions for types.
- Boxing secret keys to minimize possible copies in memory.
- Wiping secret keys on drop.
- Misuse resistant type wrappers around Secret/Public keys.
- Assertions around api preconditions.