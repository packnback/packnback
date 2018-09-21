# [packnback](https://packnback.github.io)

packnback aims to bean open source, high performance, security conscious backup tool
supporting client side encryption and deduplication.

# Roadmap

...

- ~~[Choose programming language](https://packnback.github.io/blog/programming_languages/).~~ Rust
- Get small portable nacl implementation. - Making our own tiny auditable tweetnacl wrapper.
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