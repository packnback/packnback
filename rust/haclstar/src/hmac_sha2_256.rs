extern crate chaclstar;
use chaclstar::hmac_sha2_256;
use chaclstar::sha2_256;

// This sizes are only present in the bindings as a runtime value
// Here we make it a compile time value and must use assert at runtime.
const HACL_HMAC_SHA2_256_SIZE_HASH: usize = 32;

pub fn hmac_sha2_256(key: &[u8], data: &[u8]) -> [u8; HACL_HMAC_SHA2_256_SIZE_HASH] {
    assert!(unsafe { sha2_256::Hacl_SHA2_256_size_hash as usize } == HACL_HMAC_SHA2_256_SIZE_HASH);
    assert!(key.len() <= std::u32::MAX as usize);
    assert!(data.len() <= std::u32::MAX as usize);

    let mut h = [0; HACL_HMAC_SHA2_256_SIZE_HASH];
    unsafe {
        hmac_sha2_256::Hacl_HMAC_SHA2_256_hmac(
            h.as_mut_ptr(),
            key.as_ptr() as *mut u8,
            key.len() as u32,
            data.as_ptr() as *mut u8,
            data.len() as u32,
        )
    };
    h
}

#[test]
fn test_hmac_sha256() {
    assert_eq!(
        hmac_sha2_256(b"foo", b"bar"),
        // python: list(bytearray.fromhex(hmac.new('foo', 'bar', hashlib.sha256).hexdigest()))
        [
            249, 50, 11, 175, 2, 73, 22, 158, 115, 133, 12, 214, 21, 109, 237, 1, 6, 226, 187, 106,
            216, 202, 176, 27, 123, 187, 235, 230, 209, 6, 83, 23
        ]
    );
}
