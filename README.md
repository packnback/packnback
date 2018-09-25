# [packnback](https://packnback.github.io)

*packnback* aims to be a reliable, high performance, open source, security conscious backup and storage
tool supporting client side encryption and deduplication.

# Aspirations

Some aspirations for the project, we aren't there yet, but it is the end goal.

## Clear and strong security mechanisms.

Strict security separation of data upload, data storage, and decryption roles.
This means that in the event of a security incident historic backup integrity can be ensured via
both strong cryptography and access controls.

## Paranoid testing

We aim for total testing of all code paths in the data write/upload path, using fault injection and testing of 
conditions such as out of disk space and out of memory.

Sacrificing feature development speed is acceptable if it means a user never loses data due to our code.

# Roadmap

...

- ~~[Choose programming language](https://packnback.github.io/blog/programming_languages/).~~ Rust
- Get small portable nacl implementation. - Wrapping hacl-star.
- Reimplement [asymcrypt](https://packnback.github.io/blog/asymmetric_encryption/) in rust, probably improving the spec.

...

- Define format of [asymmetrically encypted HMAC addressed content stream](https://packnback.github.io/blog/dedup_and_encryption/).
- Chunking and content defined chunking api.
- Tool + api to chunk, encrypt and pipeline data chunks.
- Tool to filter chunks that have been uploaded previously.
- Tool to sink chunk stream into a repository format.

...

- Server side chunk garbage collector.
- Chunk write cache invalidation cooincides with garbage collection.

...

- Working software.

# Donating

[Please consider donating](https://packnback.github.io/donate/)