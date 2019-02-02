# Repository data types

Every object in the repository has a known size and type.

Each data type has it's own function for deriving it's content address (lookup key in the repository),
which is used for data deduplication. The design of the address functions are such that there
is no know way to generate a hash collision for two different object types or object content.

## Notes on notation and disk format.

- This document uses pseudo code notation, that is similar to, but not
  valid rust code.
- The type 'Address' in this document refers to 32 bytes of data.
- The type AsymCryptPublicKey is documented here *TODO*.
- All integer types are big endian encoded unless stated otherwise.

# EData

Encrypted data.

## On disk format

```
type: u8 = 0,
from: AsymCryptPublicKey,
to: AsymCryptPublicKey,
encrypted_data: u8[...],
```

##  Address function

```
HMAC_sha2_256(type ++ ASYMCRYPT_DECRYPT(encrypted_data, from, repo_private_key), SENDER_HMAC_SECRET)
```

## Design notes

- The 'to' field allows a repository to have multiple keys, which will allow easier key rotation.
- The address function is an HMAC, meaning the server cannot lookup a dictionary of well known files.

# HTree

An H(ash)Tree is how a stream of EData entries are stored in the repository.

## On disk format

```
type: u8 = 1,
height: u16,
addresses: Address[...], 
```

##  Address function

```
sha2_256(type ++ height ++ Addresses),
```

## Design notes

- It is possible to walk an htree without a decryption key, this is used for:
  - Server side garbage collection.
  - yielding a stream of EData chunks without network roundtrips for client side decryption.
- If height == 0, then all child addresses should have type EData.


# Directory

A directory is an encrypted directory listing, containing a list of directory entries.

## On disk format

```
type: u8 = 2
num_children: uint64,
children: ChildInfo[NumAddresses],
encrypted_metadata: u8[...],
```

Where ChildInfo is:

```
type: u8
Data: Address, 
```

The contents of encrypted_metadata, after decryption are encoded as:

```
name: String,
mode: u32,
size: u64,
mtime: u64,
data_index: u64,
```

## Address function.

The address of a directory entry is calculated as:

```
HMAC_sha2_256(type ++ (for ent in dir.lexigraphical_sorted_iter() { name ++ mode ++ size ++ mtime ++ data ++ children[data+index] }), HMAC_SECRET)
```

## Design notes

- It is possible to walk the directory tree without a decryption key. This shows
  some of the directory 'shape', but not the metadata or file contents. This design trade off:
  - Lets a server push a whole directory tree, without access to a decryption key with no network roundtrips.
  - Allows the garbage collector to work without a decryption key.

