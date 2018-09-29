# [packnback](https://packnback.github.io)

*packnback* aims to be a reliable, high performance, open source, security conscious backup and storage
tool.

# Aspirations

Some aspirations for the project, what we are striving for.

## Client side encryption

Once data leaves a client, nobody but the backup administrator can read backup contents, not even
the client who sent the data.

## Data deduplication

Duplicated data is stored only once with each backup being a full snapshot.

## Clear and strong security mechanisms.

Strict security separation of data upload, data storage, and decryption roles.
This means that in the event of a security incident historic backup integrity can be ensured via
both strong cryptography and access controls.

## Paranoid testing

We aim for defailed automated testing of all code paths in the data write/upload path.
Nobody should lose backups due to a bug in our code.

# Roadmap

...

- ~~[Choose programming language](https://packnback.github.io/blog/programming_languages/).~~ Rust
- ~~Get small portable nacl implementation. - Wrapping hacl-star.~~
- ~~Reimplement [asymcrypt](https://packnback.github.io/blog/asymmetric_encryption/) in rust, probably improving the spec.~~

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

# Contact

## irc
```#packnback at chat.freenode.net```

# Donating

[Please consider donating](https://packnback.github.io/donate/)